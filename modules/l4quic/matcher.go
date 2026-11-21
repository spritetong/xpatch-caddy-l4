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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

func init() {
	caddy.RegisterModule(&MatchQUIC{})
}

// MatchQUIC matches QUIC connections by passively decrypting the client's
// Initial packets and evaluating TLS handshake matchers against the recovered
// ClientHello. Its structure is different from the auto-generated docs: the
// fields are a map of tls.handshake_match modules.
type MatchQUIC struct {
	MatchersRaw caddy.ModuleMap `json:"-" caddy:"namespace=tls.handshake_match"`

	// MatchWhenHandshakeFails is the match result returned when the QUIC
	// Initial cannot be sniffed (no ClientHello can be recovered). With true,
	// a negated matcher such as `not quic { ... }` becomes false and the flow
	// falls through to a following fallback route. With false, a positive
	// `quic` matcher does not claim such flows. Definitive ClientHello results
	// (ALPN, SNI, ...) are unaffected. Default: false.
	MatchWhenHandshakeFails bool `json:"match_when_handshake_fails,omitempty"`

	matchers []caddytls.ConnectionMatcher
}

// CaddyModule returns the Caddy module information.
func (m *MatchQUIC) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.quic",
		New: func() caddy.Module { return new(MatchQUIC) },
	}
}

// sniffClientHello reads every prefetched datagram, decrypts those that are
// QUIC Initials, and reassembles the ClientHello from CRYPTO fragments.
//
// Returns:
//   - hello, nil: a complete ClientHello was recovered.
//   - nil, ErrConsumedAllPrefetchedBytes: datagrams were valid Initials but the
//     CRYPTO stream is incomplete; layer4 should prefetch more and retry.
//   - nil, err: sniffing is not possible (no Initial / bad packet / no data).
//
// It keeps no state on the matcher, which is shared across connections; each
// call re-reads the accumulated buffer from the start.
func (m *MatchQUIC) sniffClientHello(cx *layer4.Connection, logger *zap.Logger) (*sniffedHello, uint32, error) {
	var fragments []cryptoFragment
	var sawInitial, sawData bool
	var quicVer uint32
	buf := make([]byte, layer4.MaxBufLen)

	for {
		n, err := cx.Read(buf)
		if err != nil {
			if errors.Is(err, layer4.ErrConsumedAllPrefetchedBytes) || errors.Is(err, io.EOF) {
				break
			}
			return nil, 0, err
		}
		if n == 0 {
			break
		}
		sawData = true
		got, decErr := decryptInitial(buf[:n])
		if decErr != nil {
			if logger.Core().Enabled(zap.DebugLevel) {
				logger.Debug("quic matcher: datagram is not a decryptable Initial",
					zap.Int("bytes", n), zap.Error(decErr),
					zap.String("head", fmt.Sprintf("%x", buf[:min(n, 12)])))
			}
			continue
		}
		sawInitial = true
		quicVer = got.version
		fragments = append(fragments, got.fragments...)
	}

	if !sawInitial {
		if !sawData {
			// No data prefetched yet; ask layer4 to fetch the first datagram.
			return nil, 0, layer4.ErrConsumedAllPrefetchedBytes
		}
		return nil, 0, errNotQUICInitial
	}

	msg, complete := reassembleCrypto(fragments)
	if !complete {
		return nil, quicVer, layer4.ErrConsumedAllPrefetchedBytes
	}
	hello, err := parseClientHello(msg)
	if err != nil {
		return nil, quicVer, err
	}
	return hello, quicVer, nil
}

// Match returns true if the connection is a QUIC flow whose ClientHello
// satisfies all configured handshake matchers.
func (m *MatchQUIC) Match(cx *layer4.Connection) (bool, error) {
	if _, isUDP := cx.LocalAddr().(*net.UDPAddr); !isUDP && !strings.HasPrefix(cx.LocalAddr().Network(), "udp") {
		return false, nil
	}

	logger := cx.Logger
	hello, quicVer, err := m.sniffClientHello(cx, logger)
	if err == nil {
		chi := clientHelloInfo(cx, hello)
		repl := cx.Replacer()
		tlsVersion := uint16(tls.VersionTLS13)
		if len(hello.supportedVersions) > 0 {
			tlsVersion = hello.supportedVersions[0]
		}
		repl.Set(quicTLSServerNameReplKey, hello.serverName)
		repl.Set(quicTLSVersionReplKey, caddytls.ProtocolName(tlsVersion))
		repl.Set(quicVersionReplKey, quicVersionName(quicVer))

		for _, matcher := range m.matchers {
			if !matcher.Match(chi) {
				if logger.Core().Enabled(zap.DebugLevel) {
					logger.Debug("quic matcher: ClientHello did not satisfy matchers",
						zap.Strings("alpn", hello.supportedProtos),
						zap.String("sni", hello.serverName))
				}
				return false, nil
			}
		}
		if logger.Core().Enabled(zap.DebugLevel) {
			logger.Debug("quic matcher: matched ClientHello",
				zap.Strings("alpn", hello.supportedProtos),
				zap.String("sni", hello.serverName))
		}
		return true, nil
	}

	if errors.Is(err, layer4.ErrConsumedAllPrefetchedBytes) {
		return false, err
	}

	// Sniffing failed. This is a definitive failure for this flow: no amount
	// of additional prefetched data can turn a non-Initial into a ClientHello.
	if logger.Core().Enabled(zap.DebugLevel) {
		logger.Debug("quic matcher: cannot sniff ClientHello",
			zap.Error(err))
	}
	if m.MatchWhenHandshakeFails {
		return true, nil
	}
	return false, nil
}

// Provision prepares the internal matchers.
func (m *MatchQUIC) Provision(ctx caddy.Context) error {
	mods, err := ctx.LoadModule(m, "MatchersRaw")
	if err != nil {
		return fmt.Errorf("loading TLS matchers: %v", err)
	}
	for _, modAny := range mods.(map[string]any) {
		m.matchers = append(m.matchers, modAny.(caddytls.ConnectionMatcher))
	}
	return nil
}

// UnmarshalCaddyfile sets up the MatchQUIC from Caddyfile tokens. Syntax:
//
//	quic {
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

// UnmarshalJSON satisfies json.Unmarshaler. The option is pulled out before
// the remaining keys are loaded as handshake matchers.
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

// MarshalJSON satisfies json.Marshaler.
func (m *MatchQUIC) MarshalJSON() ([]byte, error) {
	out := make(caddy.ModuleMap, len(m.MatchersRaw)+1)
	maps.Copy(out, m.MatchersRaw)
	if m.MatchWhenHandshakeFails {
		raw, err := json.Marshal(true)
		if err != nil {
			return nil, err
		}
		out["match_when_handshake_fails"] = raw
	}
	return json.Marshal(out)
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchQUIC)(nil)
	_ caddyfile.Unmarshaler = (*MatchQUIC)(nil)
	_ layer4.ConnMatcher    = (*MatchQUIC)(nil)
)

// Replacer prefixes and keys; names of context variables.
const (
	quicReplPrefix = layer4.AppReplPrefix + "quic."

	quicTLSServerNameReplKey = quicReplPrefix + "tls.server_name"
	quicTLSVersionReplKey    = quicReplPrefix + "tls.version"
	quicVersionReplKey       = quicReplPrefix + "version"
)

// quicVersionName mirrors the sniffer's version naming for the replacer.
func quicVersionName(v uint32) string {
	switch v {
	case quicVersionDraft29:
		return "draft-29"
	case quicVersion2:
		return "v2"
	case quicVersion1:
		return "v1"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
