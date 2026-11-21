// Copyright 2024 VNXME
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func init() {
	caddy.RegisterModule(&MatchQUIC{})
}

var isTesting bool

// MatchQUIC is able to match QUIC connections. Its structure
// is different from the auto-generated documentation. This
// value should be a map of matcher names to their values.
type MatchQUIC struct {
	MatchersRaw caddy.ModuleMap `json:"-" caddy:"namespace=tls.handshake_match"`

	// MatchWhenHandshakeFails is the match result returned when the fake
	// handshake fails or the ClientHello cannot be decoded. With true, a
	// negated matcher such as `not quic { ... }` becomes false and the flow
	// falls through to a following route. With false, a positive `quic`
	// matcher does not claim such flows. Definitive results, e.g. an ALPN
	// or SNI mismatch, are unaffected. Default: false.
	MatchWhenHandshakeFails bool `json:"match_when_handshake_fails,omitempty"`

	matchers []caddytls.ConnectionMatcher
	quicConf *quic.Config
	tlsConf  *tls.Config
}

// CaddyModule returns the Caddy module information.
func (m *MatchQUIC) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.quic",
		New: func() caddy.Module { return new(MatchQUIC) },
	}
}

// quicPipeWriter checks the length of the passed in buffer before writing
type quicPipeWriter struct {
	io.Writer
}

func (q quicPipeWriter) Write(p []byte) (int, error) {
	if len(p) < QUICPacketBytesMin || len(p) > QUICPacketBytesMax {
		return 0, errors.New("invalid length for quic packet")
	}
	return q.Writer.Write(p)
}

// validQUICInitialLength reports whether n can be the length of a QUIC
// Initial datagram fed to the matcher. The upper bound is inclusive: 1452 is
// a valid Initial size on a 1500-byte MTU path. Rejecting it would make the
// matcher report "not QUIC", and `not quic alpn ...` would then send the
// client to the wrong route.
func validQUICInitialLength(n int) bool {
	return n >= QUICPacketBytesMin-1 && n <= QUICPacketBytesMax
}

// hasMatchingALPN reports whether the client offered at least one of the
// configured ALPNs. It is only called when at least one ALPN is configured.
func hasMatchingALPN(supported []string, expected map[string]struct{}) bool {
	for _, p := range supported {
		if _, ok := expected[p]; ok {
			return true
		}
	}
	return false
}

// acceptErrorResult decides a match when the fake handshake did not complete.
// The configured matchers are evaluated from the ClientHello, so their verdict
// is authoritative and must not depend on the fake handshake's certificate or
// deadline. A definitive mismatch stays false; a definitive pass stays true.
// Only when no ClientHello verdict exists does matchOnFailure apply.
func acceptErrorResult(alpnMismatch, helloMismatch, helloMatched, matchOnFailure bool, qErr error) (bool, error) {
	if alpnMismatch || helloMismatch {
		return false, nil
	}
	if helloMatched {
		return true, nil
	}
	if matchOnFailure {
		return true, nil
	}
	if errors.Is(qErr, context.DeadlineExceeded) {
		return false, nil
	}
	return false, layer4.ErrConsumedAllPrefetchedBytes
}

// matchError applies the configured failure result to a handshake failure
// that happened before the ClientHello could be decoded.
func (m *MatchQUIC) matchError(err error) (bool, error) {
	if m.MatchWhenHandshakeFails {
		return true, nil
	}
	return false, err
}

// evaluateClientHello runs every configured handshake matcher against the
// ClientHello, before the fake QUIC handshake finishes. It returns whether
// the ALPN constraint is satisfied and whether all matchers passed. Both
// results are needed: a route must not be selected on ALPN alone when SNI or
// another matcher is also configured.
//
// The ClientHelloInfo mirrors the one built from ConnectionState after a
// successful handshake: ALPN matchers are handled separately, and the
// negotiated protocol is represented by the offered ALPNs that we accepted.
func (m *MatchQUIC) evaluateClientHello(cx *layer4.Connection, info *tls.ClientHelloInfo, expectedALPNs map[string]struct{}) (bool, bool) {
	alpnMatched := len(expectedALPNs) == 0 || hasMatchingALPN(info.SupportedProtos, expectedALPNs)
	if !alpnMatched {
		return false, false
	}

	var offered []string
	for _, p := range info.SupportedProtos {
		if _, ok := expectedALPNs[p]; ok {
			offered = append(offered, p)
		}
	}
	chi := &tls.ClientHelloInfo{
		CipherSuites:      info.CipherSuites,
		ServerName:        info.ServerName,
		SupportedProtos:   offered,
		SupportedVersions: []uint16{tls.VersionTLS13},
		Conn:              cx,
	}
	for _, matcher := range m.matchers {
		if _, isALPN := matcher.(*l4tls.MatchALPN); isALPN {
			continue
		}
		if !matcher.Match(chi) {
			return true, false
		}
	}
	return true, true
}

// Match returns true if the connection looks like QUIC.
func (m *MatchQUIC) Match(cx *layer4.Connection) (bool, error) {
	// Check if the protocol is UDP
	if _, isUDP := cx.LocalAddr().(*net.UDPAddr); !isUDP {
		return false, nil
	}

	// Read one byte
	n := 1
	buf := make([]byte, n)
	_, err := io.ReadAtLeast(cx, buf, n)
	if err != nil {
		return m.matchError(err)
	}

	// Ensure the second bit of the first byte is set, i.e. continue if
	// github.com/quic-go/quic-go/internal/wire.IsPotentialQUICPacket(buf[0]).
	qFirstByte := buf[0]
	if qFirstByte&QUICMagicBitValue == 0 {
		return false, nil
	}

	// Ensure the first bit of the first byte is set, i.e. continue if
	// github.com/quic-go/quic-go/internal/wire.IsLongHeaderPacket(buf[0]).
	// Note: this behaviour may be changed in the future if there are packets
	// that should be considered valid despite having the first bit unset.
	if qFirstByte&QUICLongHeaderBitValue == 0 {
		return false, nil
	}

	// Read the remaining bytes. One byte beyond the maximum is kept so that
	// a 1452-byte Initial is accepted while a larger one is still rejected.
	buf = make([]byte, QUICPacketBytesMax+2)
	buf[0] = qFirstByte
	n, err = io.ReadAtLeast(cx, buf[1:], 1)
	if err != nil || !validQUICInitialLength(n) {
		return m.matchError(err)
	}
	version := quic.Version(binary.BigEndian.Uint32(buf[1:5]))

	// Use a workaround to match ALPNs. This way quic.EarlyListener.Accept() exits on deadline
	// if it receives a packet having an ALPN other than those present in tls.Config.NextProtos.
	repl := cx.Replacer()
	tlsConf := &tls.Config{Certificates: m.tlsConf.Certificates, MinVersion: tls.VersionTLS13}
	for _, matcher := range m.matchers {
		if alpnMatcher, ok := matcher.(*l4tls.MatchALPN); ok {
			for _, alpnValue := range *alpnMatcher {
				alpnValue = repl.ReplaceAll(alpnValue, "")
				if len(alpnValue) > 0 {
					tlsConf.NextProtos = append(tlsConf.NextProtos, alpnValue)
				}
			}
		}
	}

	// All handshake matchers are evaluated as soon as the ClientHello is
	// available. This is the authoritative match verdict: it depends only on
	// the ClientHello (ALPN, SNI, ...), not on whether the matcher's own fake
	// handshake with a self-signed certificate happens to complete. Match
	// reads the flags after Accept returns, so the handoff from the handshake
	// goroutine is done atomically.
	var (
		alpnMismatch  atomic.Bool
		helloMismatch atomic.Bool
		helloMatched  atomic.Bool
	)
	if len(tlsConf.NextProtos) > 0 || len(m.matchers) > 0 {
		expectedALPNs := make(map[string]struct{}, len(tlsConf.NextProtos))
		for _, p := range tlsConf.NextProtos {
			expectedALPNs[p] = struct{}{}
		}
		tlsConf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			alpnOK, allOK := m.evaluateClientHello(cx, info, expectedALPNs)
			repl.Set(quicTLSServerNameReplKey, info.ServerName)
			repl.Set(quicTLSVersionReplKey, caddytls.ProtocolName(tls.VersionTLS13))
			repl.Set(quicVersionReplKey, version.String())
			if !alpnOK {
				alpnMismatch.Store(true)
				return nil, errors.New("quic matcher: ALPN mismatch")
			}
			if !allOK {
				helloMismatch.Store(true)
				return nil, errors.New("quic matcher: handshake matcher mismatch")
			}
			helloMatched.Store(true)
			return nil, nil
		}
	}

	// Create a new fakePacketConn pipe
	serverFPC, clientFPC := newFakePacketConnPipe(&fakePipeAddr{ID: newRand(), TS: time.Now()}, nil)

	// Create a new quic.Transport
	qTransport := quic.Transport{
		Conn: serverFPC,
	}

	// Launch a new quic.EarlyListener
	var qListener *quic.EarlyListener
	qListener, err = qTransport.ListenEarly(tlsConf, m.quicConf)
	if err != nil {
		_ = serverFPC.Close()
		_ = clientFPC.Close()
		return m.matchError(err)
	}
	// Single combined cleanup so qListener.Close() always runs (closes the
	// upstream-leaked listener on Accept-error paths) and the fakePacketConn
	// pipes close BEFORE the listener — closing the listener triggers the
	// QUIC server's connection-close goroutine to write a CLOSE frame, which
	// would otherwise deadlock on an unread pipe in the Accept-timeout case.
	defer func() {
		_ = serverFPC.Close()
		_ = clientFPC.Close()
		_ = qListener.Close()
	}()

	// Write the buffered bytes into the pipe
	_, err = clientFPC.WriteTo(buf[:n+1], nil)
	if err != nil {
		return m.matchError(nil)
	}

	// Write more buffered bytes into the pipe, the writer here ensures all frames are likely quic frames based on their lengths
	_, err = io.CopyBuffer(quicPipeWriter{clientFPC}, cx, buf)
	if err != nil && !errors.Is(err, layer4.ErrConsumedAllPrefetchedBytes) {
		return m.matchError(err)
	}

	// return if there are more data to be read, usually there will be frames buffered at the start of a connection.
	if cx.HasMore() {
		return false, layer4.ErrConsumedAllPrefetchedBytes
	}

	// Prepare a context with a deadline
	qContext, qCancel := context.WithDeadline(context.Background(), time.Now().Add(QUICAcceptTimeout))

	// spawn a new go routine to monitor new data. It's possible the available data is enough to determine the quic connection and the context is wrongly canceled.
	done := make(chan struct{})
	go func() {
		// close(done) lives in a deferred recovery so a future refactor
		// that breaks the cx.isPacketConn invariant (or any other panic
		// inside WaitForMore) cannot leave Match() blocked forever at
		// the <-done wait below. Logs the panic + remote addr so
		// operators can attribute the symptom.
		defer func() {
			if r := recover(); r != nil {
				cx.Logger.Error("panic in quic matcher WaitForMore goroutine",
					zap.String("network", cx.LocalAddr().Network()),
					zap.String("local", cx.LocalAddr().String()),
					zap.String("remote", cx.RemoteAddr().String()),
					zap.Any("panic", r),
				)
			}
			close(done)
		}()
		// during testing the connection is not a packet conn
		if isTesting {
			return
		}
		_ = cx.WaitForMore(qContext)
		qCancel()
	}()

	// Accept a new quic.EarlyConnection
	var qConn *quic.Conn
	qConn, err = qListener.Accept(qContext)
	qCancel()
	<-done
	if err != nil {
		// Log unexpected error classes at WARN; expected timeout/cancel
		// races at DEBUG. Field order follows vnxme's review: network,
		// local, remote, then the diagnostic value.
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			cx.Logger.Warn("quic matcher: unexpected Accept() error",
				zap.String("network", cx.LocalAddr().Network()),
				zap.String("local", cx.LocalAddr().String()),
				zap.String("remote", cx.RemoteAddr().String()),
				zap.Error(err))
		} else {
			cx.Logger.Debug("quic matcher: Accept() timeout or cancel",
				zap.String("network", cx.LocalAddr().Network()),
				zap.String("local", cx.LocalAddr().String()),
				zap.String("remote", cx.RemoteAddr().String()),
				zap.Error(err))
		}
		// The ClientHello verdict outranks the fake handshake's fate: a
		// configured ALPN/SNI match is a match even if the self-signed cert
		// or the 1s deadline stops the fake handshake. Only flows with no
		// ClientHello verdict fall back to match_when_handshake_fails.
		return acceptErrorResult(alpnMismatch.Load(), helloMismatch.Load(), helloMatched.Load(), m.MatchWhenHandshakeFails, qContext.Err())
	}

	// Obtain a quic.ConnectionState
	qState := qConn.ConnectionState()

	// Add values to the replacer
	repl.Set(quicTLSServerNameReplKey, qState.TLS.ServerName)
	repl.Set(quicTLSVersionReplKey, caddytls.ProtocolName(qState.TLS.Version))
	repl.Set(quicVersionReplKey, qState.Version.String())

	// Fill a tls.ClientHelloInfo structure
	chi := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{qState.TLS.CipherSuite},
		ServerName:        qState.TLS.ServerName,
		SupportedCurves:   nil,
		SupportedPoints:   nil,
		SignatureSchemes:  nil,
		SupportedProtos:   []string{qState.TLS.NegotiatedProtocol}, // Empty if no ALPNs are provided
		SupportedVersions: []uint16{tls.VersionTLS13},              // Presumed to always be TLS 1.3
		Conn:              cx,
	}

	// Check TLS matchers if any
	for _, matcher := range m.matchers {
		// ALPN matching is implicitly done above when the QUIC listener is initialised,
		// as quic.EarlyConnection.ConnectionState().TLS.NegotiatedProtocol is only filled
		// when the client's ALPN matches one of the values set in tls.Config.NextProtos.
		if _, isMatchALPN := matcher.(*l4tls.MatchALPN); isMatchALPN {
			continue
		}

		// TODO: even though we have more data than the standard lib's
		// ClientHelloInfo lets us fill, the matcher modules we use do
		// not accept our own type; but the advantage of this is that
		// we can reuse TLS connection matchers from the tls app - but
		// it would be nice if we found a way to give matchers all
		// the information
		if !matcher.Match(chi) {
			return false, nil
		}
	}

	return true, nil
}

// Provision prepares m's internal structures.
func (m *MatchQUIC) Provision(ctx caddy.Context) error {
	// Load TLS matchers
	mods, err := ctx.LoadModule(m, "MatchersRaw")
	if err != nil {
		return fmt.Errorf("loading TLS matchers: %v", err)
	}
	for _, modAny := range mods.(map[string]any) {
		m.matchers = append(m.matchers, modAny.(caddytls.ConnectionMatcher))
	}

	// Generate a new private key
	var key *ecdsa.PrivateKey
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating a private key: %v", err)
	}

	// Compose a new x509 certificate template
	template := &x509.Certificate{
		SerialNumber: newRand(),
		Subject: pkix.Name{
			CommonName:   QUICCertificateCommonName,
			Organization: []string{QUICCertificateOrganization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(QUICCertificateValidityPeriod),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{QUICCertificateSubjectAltName},
	}

	// Create a new x509 certificate
	var cert []byte
	cert, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("generating a x509 certificate: %v", err)
	}

	// Initialize a new TLS config
	m.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}

	// Initialize a new QUIC config
	m.quicConf = &quic.Config{}

	return nil
}

// UnmarshalCaddyfile sets up the MatchQUIC from Caddyfile tokens. Syntax:
//
//	quic {
//		<matcher> [<args...>]
//		<matcher> [<args...>]
//	}
//	quic <matcher> [<args...>]
//	quic
func (m *MatchQUIC) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	matcherSet, err := l4tls.ParseCaddyfileNestedMatcherSet(d)
	if err != nil {
		return err
	}
	m.MatchersRaw = matcherSet

	return nil
}

// UnmarshalJSON satisfies the json.Unmarshaler interface. The option is
// pulled out before the remaining keys are loaded as handshake matchers.
func (m *MatchQUIC) UnmarshalJSON(b []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	if raw, ok := fields["match_when_handshake_fails"]; ok {
		if err := json.Unmarshal(raw, &m.MatchWhenHandshakeFails); err != nil {
			return fmt.Errorf("unmarshaling match_when_handshake_fails: %w", err)
		}
		delete(fields, "match_when_handshake_fails")
	}
	rest, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return json.Unmarshal(rest, &m.MatchersRaw)
}

// MarshalJSON satisfies the json.Marshaler interface.
func (m *MatchQUIC) MarshalJSON() ([]byte, error) {
	out := make(caddy.ModuleMap, len(m.MatchersRaw)+1)
	for name, raw := range m.MatchersRaw {
		out[name] = raw
	}
	if m.MatchWhenHandshakeFails {
		raw, err := json.Marshal(true)
		if err != nil {
			return nil, err
		}
		out["match_when_handshake_fails"] = raw
	}
	return json.Marshal(out)
}

// fakePipeAddr satisfies net.Addr and uses a random number and a timestamp
// to avoid panic in quic.connMultiplexer.AddConn() due to the same local address.
type fakePipeAddr struct {
	ID *big.Int
	TS time.Time
}

func (fpa fakePipeAddr) Network() string {
	return "pipe"
}

func (fpa fakePipeAddr) String() string {
	return fmt.Sprintf("fake_%v_%v", fpa.ID.String(), fpa.TS.UnixNano())
}

// fakePacketConn wraps around net.Conn and satisfies net.PacketConn.
type fakePacketConn struct {
	net.Conn

	Local  net.Addr
	Remote net.Addr
}

func (fpc *fakePacketConn) LocalAddr() net.Addr {
	if fpc.Local != nil {
		return fpc.Local
	}
	return fpc.Conn.LocalAddr()
}

func (fpc *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := fpc.Read(p)
	return n, fpc.RemoteAddr(), err
}

func (fpc *fakePacketConn) RemoteAddr() net.Addr {
	if fpc.Remote != nil {
		return fpc.Remote
	}
	return fpc.Conn.RemoteAddr()
}

func (fpc *fakePacketConn) SetReadBuffer(_ int) error {
	return nil
}

func (fpc *fakePacketConn) SetWriteBuffer(_ int) error {
	return nil
}

func (fpc *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return fpc.Write(p)
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchQUIC)(nil)
	_ caddyfile.Unmarshaler = (*MatchQUIC)(nil)
	_ layer4.ConnMatcher    = (*MatchQUIC)(nil)

	_ net.Addr = (*fakePipeAddr)(nil)

	_ net.PacketConn                         = (*fakePacketConn)(nil)
	_ interface{ SetReadBuffer(int) error }  = (*fakePacketConn)(nil)
	_ interface{ SetWriteBuffer(int) error } = (*fakePacketConn)(nil)
)

// Replacer prefixes and keys; names of context variables
const (
	quicReplPrefix = layer4.AppReplPrefix + "quic."

	quicTLSServerNameReplKey = quicReplPrefix + "tls.server_name"
	quicTLSVersionReplKey    = quicReplPrefix + "tls.version"
	quicVersionReplKey       = quicReplPrefix + "version"
)

var (
	QUICAcceptTimeout = 1 * time.Second
)

const (
	QUICCertificateCommonName     = "layer4"
	QUICCertificateOrganization   = "caddy"
	QUICCertificateSubjectAltName = "*"
	QUICCertificateValidityPeriod = time.Hour * 24 * 365 * 20

	QUICLongHeaderBitValue uint8 = 0x80 // github.com/quic-go/quic-go/internal/wire.IsLongHeaderPacket()
	QUICMagicBitValue      uint8 = 0x40 // github.com/quic-go/quic-go/internal/wire.IsPotentialQUICPacket()

	QUICPacketBytesMax = 1452 // github.com/quic-go/quic-go/internal/protocol.MaxPacketBufferSize
	QUICPacketBytesMin = 1200 // github.com/quic-go/quic-go/internal/protocol.MinInitialPacketSize
)

func newFakePacketConnPipe(local, remote net.Addr) (*fakePacketConn, *fakePacketConn) {
	server, client := net.Pipe()
	serverFPC, clientFPC := &fakePacketConn{Conn: server}, &fakePacketConn{Conn: client}
	if local != nil || remote != nil {
		if local == nil {
			local = remote
		}
		if remote == nil {
			remote = local
		}
		serverFPC.Local, clientFPC.Remote = local, local
		serverFPC.Remote, clientFPC.Local = remote, remote
	}
	return serverFPC, clientFPC
}

func newRand() *big.Int {
	rnd, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return rnd
}
