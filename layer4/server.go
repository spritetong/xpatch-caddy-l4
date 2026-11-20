// Copyright 2020 Matthew Holt
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

package layer4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/vnxme/hybrid"
	"go.uber.org/zap"
)

const (
	idleTimeoutDefault     = 30 * time.Second
	MatchingTimeoutDefault = 3 * time.Second
)

// Server represents a Caddy layer4 server.
type Server struct {
	// The network address to bind to. Any Caddy network address
	// is an acceptable value:
	// https://caddyserver.com/docs/conventions#network-addresses
	Listen []string `json:"listen,omitempty"`

	// Routes express composable logic for handling byte streams.
	Routes RouteList `json:"routes,omitempty"`

	// Maximum time before packet connection association (by downstream address:port) is removed. Default: 30s.
	// Note: this field is only relevant for packet connections (e.g., UDP).
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`
	// Maximum time connections have to complete the matching phase (the first terminal handler is matched). Default: 3s.
	MatchingTimeout caddy.Duration `json:"matching_timeout,omitempty"`

	logger        *zap.Logger
	listenAddrs   []caddy.NetworkAddress
	compiledRoute Handler
}

// Provision sets up the server.
func (s *Server) Provision(ctx caddy.Context, logger *zap.Logger) error {
	s.logger = logger

	if s.IdleTimeout <= 0 {
		s.IdleTimeout = caddy.Duration(idleTimeoutDefault)
	}

	if s.MatchingTimeout <= 0 {
		s.MatchingTimeout = caddy.Duration(MatchingTimeoutDefault)
	}

	repl := caddy.NewReplacer()
	for i, address := range s.Listen {
		address = repl.ReplaceAll(address, "")
		addr, err := caddy.ParseNetworkAddress(address)
		if err != nil {
			return fmt.Errorf("parsing listener address '%s' in position %d: %v", address, i, err)
		}
		s.listenAddrs = append(s.listenAddrs, addr)
	}

	err := s.Routes.Provision(ctx)
	if err != nil {
		return err
	}
	s.compiledRoute = s.Routes.Compile(s.logger, time.Duration(s.MatchingTimeout), nopHandler{})

	return nil
}

func (s *Server) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			s.logger.Error("timeout accepting connection", zap.Error(err))
			continue
		}
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// socketClosed reports whether the socket owned by Caddy has really been
// closed. hybrid wraps every splitter failure in net.ErrClosed, so the error
// from AcceptSplit alone cannot tell a real shutdown from a recoverable
// failure. Probing the socket can.
func socketClosed(pc net.PacketConn) bool {
	return errors.Is(pc.SetReadDeadline(time.Time{}), net.ErrClosed)
}

func (s *Server) servePacket(pc net.PacketConn) error {
	// The splitter sorts the packets of the socket into flows by downstream
	// address:port, and serves each flow as a split connection until it's
	// closed or idle. It stops once the socket is closed. As it drops the
	// first packet of a new flow if the accept queue is full, the queue is
	// long enough to absorb a burst of new downstreams while this loop waits
	// to be scheduled.
	// The splitter never closes the socket, which Caddy may not expect closed
	// more than once, while closing it makes the splitter stop on its own.
	// Its Close, used on failure, only interrupts the blocked reads so that the
	// old splitter is fully gone before a replacement starts reading.
	rpc := newResilientPacketConn(pc, s.logger)
	interrupt := func() error {
		_ = rpc.SetWriteDeadline(time.Unix(1, 0))
		return rpc.SetReadDeadline(time.Unix(1, 0))
	}
	for {
		ln := hybrid.Split(hybrid.FakeClosePacketConn(rpc, interrupt), &hybrid.SplitConfig{
			AcceptQueueSize: udpAcceptQueueSize,
			IdleTimeout:     time.Duration(s.IdleTimeout),
			ReadBufferSize:  udpBufSize,
			// Caddy closes the socket on every shutdown and reload, and a client
			// gone makes a write fail, so these errors aren't worth an error log
			ErrorFunc: func(err error) {
				s.logger.Debug("packet connection error",
					zap.String("network", pc.LocalAddr().Network()),
					zap.String("address", pc.LocalAddr().String()),
					zap.Error(err),
				)
			},
		})
		for {
			sc, err := ln.AcceptSplit()
			if err != nil {
				s.logger.Debug("packet connection drops",
					zap.String("network", ln.Addr().Network()),
					zap.String("address", ln.Addr().String()),
					zap.Any("drops", ln.Stats()),
				)
				// A real shutdown is the only reason to stop serving. Any other
				// failure of the splitter is recoverable: rebuild it on the same
				// socket so a transient problem never needs a Caddy restart.
				if rpc.isClosed() || socketClosed(pc) {
					return err
				}
				s.logger.Warn("packet connection splitter stopped unexpectedly, restarting",
					zap.String("network", pc.LocalAddr().Network()),
					zap.String("address", pc.LocalAddr().String()),
					zap.Error(err),
				)
				time.Sleep(10 * time.Millisecond)
				break
			}
			go s.handle(newPacketConn(sc, false))
		}
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	buf := bufPool.Get().([]byte)
	buf = buf[:0]
	defer bufPool.Put(buf)

	cx := WrapConnection(conn, buf, s.logger)

	s.logger.Debug("started handling connection",
		zap.String("network", cx.LocalAddr().Network()),
		zap.String("local", cx.LocalAddr().String()),
		zap.String("remote", cx.RemoteAddr().String()),
	)

	start := time.Now()
	err := s.compiledRoute.Handle(cx)
	duration := time.Since(start)
	if err != nil {
		s.logger.Error("handling connection",
			zap.String("network", cx.LocalAddr().Network()),
			zap.String("local", cx.LocalAddr().String()),
			zap.String("remote", cx.RemoteAddr().String()),
			zap.Error(err),
		)
	}

	s.logger.Debug("stopped handling connection; connection stats",
		zap.String("network", cx.LocalAddr().Network()),
		zap.String("local", cx.LocalAddr().String()),
		zap.String("remote", cx.RemoteAddr().String()),
		zap.Uint64("read", cx.bytesRead),
		zap.Uint64("written", cx.bytesWritten),
		zap.Duration("duration", duration),
	)
}

// UnmarshalCaddyfile sets up the Server from Caddyfile tokens. Syntax:
//
//	<address:port> [<address:port>] {
//		idle_timeout <duration>
//		matching_timeout <duration>
//		@a <matcher> [<matcher_args>]
//		@b {
//			<matcher> [<matcher_args>]
//			<matcher> [<matcher_args>]
//		}
//		route @a @b {
//			<handler> [<handler_args>]
//		}
//		@c <matcher> {
//			<matcher_option> [<matcher_option_args>]
//		}
//		route @c {
//			<handler> [<handler_args>]
//			<handler> {
//				<handler_option> [<handler_option_args>]
//			}
//		}
//	}
func (s *Server) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Wrapper name and all same-line options are treated as network addresses
	for ok := true; ok; ok = d.NextArg() {
		s.Listen = append(s.Listen, d.Val())
	}

	if err := ParseCaddyfileNestedRoutes(d, &s.Routes, &s.MatchingTimeout, &s.IdleTimeout); err != nil {
		return err
	}

	return nil
}

type packet struct {
	// The underlying bytes slice that was gotten from udpBufPool.  It's up to
	// packetConn to return it to udpBufPool once it's consumed.
	pooledBuf []byte
	// Number of bytes read from socket
	n int
}

type packetConn struct {
	// The split connection of the flow, which the packets are read from by
	// the goroutine started by newPacketConn, and written to directly.
	net.PacketConn
	addr   net.Addr
	readCh chan *packet
	// If not nil, then the previous Read() call didn't consume all the data
	// from the buffer, and this packet will be reused in the next Read()
	// without waiting for readCh.
	lastPacket  *packet
	lastBuf     *bytes.Reader
	lastBufSize int

	// stores time.Time as Unix nanoseconds, or zero for no deadline, as Read may be
	// called concurrently with SetReadDeadline
	deadline      atomic.Int64
	deadlineMu    sync.Mutex
	deadlineTimer *time.Timer

	// QUIC / TLS state tracking
	initialDCID       []byte
	initialDTLSRandom []byte
	writtenPackets    atomic.Uint64
	released          atomic.Bool
	// hasFallback reports whether the splitter can take over this flow. With a
	// fallback, a stale flow is handed over; without one, it is ended so the
	// next packet re-enters matching immediately.
	hasFallback bool
}

const (
	// quicInitialMinPacketSize is the minimum size of a client Initial datagram
	// (RFC 9000 §14.1). Shorter packets cannot be Initial packets.
	quicInitialMinPacketSize = 1200
	// quicVersion2 is RFC 9369. In v2 the Initial type bits are 0b01 rather
	// than the 0b00 used by v1, so the first byte is 0xd0 instead of 0xc0.
	quicVersion2 = uint32(0x6b3343cf)
)

// parseQUICInitialDCID parses the Destination Connection ID from a QUIC
// Initial packet (RFC 9000 §17.2, RFC 9369). It handles both v1 and v2 long
// headers; other long-header packet types are deliberately not reported.
func parseQUICInitialDCID(b []byte) ([]byte, bool) {
	if len(b) < quicInitialMinPacketSize {
		return nil, false
	}
	// Long Header (0x80) and Fixed Bit (0x40) must both be set.
	if b[0]&0xc0 != 0xc0 {
		return nil, false
	}
	version := binary.BigEndian.Uint32(b[1:5])
	// Version 0 is for Version Negotiation, which is sent by the server.
	if version == 0 {
		return nil, false
	}
	packetType := (b[0] >> 4) & 0x03
	if version == quicVersion2 {
		if packetType != 0x01 { // v2: Retry=0, Initial=1, 0-RTT=2, Handshake=3
			return nil, false
		}
	} else if packetType != 0x00 { // v1: Initial=0, 0-RTT=1, Handshake=2, Retry=3
		return nil, false
	}
	dcidLen := int(b[5])
	if dcidLen > 20 || 6+dcidLen > len(b) {
		return nil, false
	}
	return b[6 : 6+dcidLen], true
}

// parseDTLSClientHelloRandom extracts the 32-byte Client Random from a DTLS
// ClientHello record (RFC 6347 §4.2.4.1 / RFC 5246 §7.4.1.2).
func parseDTLSClientHelloRandom(b []byte) ([]byte, bool) {
	// DTLS record header (13 bytes):
	// b[0] = 22 (handshake)
	// b[1] = 0xfe (DTLS 1.x / DTLS 1.3)
	// Handshake header (12 bytes):
	// b[13] = 1 (ClientHello)
	// b[19..21] = fragment_offset (uint24, must be 0 for the initial fragment)
	// ClientHello body:
	// b[25..26] = client_version (2 bytes)
	// b[27..58] = random (32 bytes)
	//
	// Minimum length for a record containing Client Random is 27 + 32 = 59 bytes.
	if len(b) < 59 || b[0] != 22 || b[1] != 0xfe || b[13] != 1 {
		return nil, false
	}
	if b[19] != 0 || b[20] != 0 || b[21] != 0 {
		return nil, false
	}
	return b[27:59], true
}

// isDTLSClientHello checks if a packet looks like a DTLS ClientHello.
func isDTLSClientHello(b []byte) bool {
	_, ok := parseDTLSClientHelloRandom(b)
	return ok
}

// newPacketConn returns a packetConn serving the flow of sc. Its goroutine
// moves the packets from sc to readCh, and closes readCh once sc is closed,
// by Close or by the splitter, as the flow is idle or the socket is closed.
func newPacketConn(sc hybrid.SplitConn, hasFallback bool) *packetConn {
	pc := &packetConn{
		PacketConn:  sc,
		addr:        sc.RemoteAddr(),
		readCh:      make(chan *packet, 5),
		hasFallback: hasFallback,
	}
	go func() {
		defer close(pc.readCh)
		for {
			buf := udpBufPool.Get().([]byte)
			n, err := sc.Read(buf)
			if err != nil {
				udpBufPool.Put(buf)
				return
			}

			// Check for new QUIC/TLS handshakes arriving on an existing session
			pkt := buf[:n]
			if len(pkt) > 0 {
				if dcid, ok := parseQUICInitialDCID(pkt); ok {
					if len(pc.initialDCID) == 0 {
						pc.initialDCID = append([]byte(nil), dcid...)
					} else {
						isDifferentDCID := !bytes.Equal(pc.initialDCID, dcid)
						// A different DCID alone does not mean a new connection:
						// QUIC Retry and version negotiation make the client resend
						// its Initial with a server-chosen DCID mid-handshake. Only
						// treat it as a new handshake when the upstream has never
						// answered this flow, which is the misrouting case this
						// detection is meant to recover from. Ending a flow whose
						// handshake is progressing strips its later packets into a
						// new flow, where `not quic alpn ...` can route them to a
						// different upstream and break the connection.
						if isDifferentDCID && pc.writtenPackets.Load() == 0 {
							// This flow is stale: the client started a new handshake on
							// the same port. With a fallback, hand the whole flow over
							// so the new Initial reaches the fallback proxy at once.
							// Without one, end the flow so the next packet re-enters
							// matching immediately instead of waiting for idle timeout.
							if pc.hasFallback {
								pc.releaseToFallback(&packet{pooledBuf: buf, n: n})
							} else {
								_ = pc.PacketConn.Close()
								udpBufPool.Put(buf)
							}
							return
						}
					}
				} else if random, ok := parseDTLSClientHelloRandom(pkt); ok {
					if len(pc.initialDTLSRandom) == 0 {
						pc.initialDTLSRandom = append([]byte(nil), random...)
					} else {
						isDifferentRandom := !bytes.Equal(pc.initialDTLSRandom, random)
						// In DTLS (RFC 6347 §4.2.1), both retransmissions and the
						// second ClientHello of a cookie exchange MUST use the same
						// Client Random as the initial ClientHello. Only a different
						// Random on an unanswered flow indicates a newly started
						// handshake that should be reset.
						if isDifferentRandom && pc.writtenPackets.Load() == 0 {
							if pc.hasFallback {
								pc.releaseToFallback(&packet{pooledBuf: buf, n: n})
							} else {
								_ = pc.PacketConn.Close()
								udpBufPool.Put(buf)
							}
							return
						}
					}
				}
			}

			pc.readCh <- &packet{
				pooledBuf: buf,
				n:         n,
			}
		}
	}()
	return pc
}

// SetDeadline sets the read deadline of the connection and the write deadline
// of the split connection, whose read deadline must stay clear, so as not to
// interrupt the goroutine moving its packets to readCh.
func (pc *packetConn) SetDeadline(t time.Time) error {
	_ = pc.SetReadDeadline(t)
	return pc.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline to wait for data from the underlying net.PacketConn.
func (pc *packetConn) SetReadDeadline(t time.Time) error {
	pc.deadlineMu.Lock()
	defer pc.deadlineMu.Unlock()

	var ns int64
	if !t.IsZero() {
		ns = t.UnixNano()
	}
	pc.deadline.Store(ns)

	if pc.deadlineTimer != nil {
		if !pc.deadlineTimer.Stop() {
			select {
			case <-pc.deadlineTimer.C:
			default:
			}
		}
	}

	if !t.IsZero() {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		if pc.deadlineTimer != nil {
			pc.deadlineTimer.Reset(d)
		} else {
			pc.deadlineTimer = time.NewTimer(d)
		}
	}
	return nil
}

// deadlineExceeded reports whether the read deadline has passed.
func (pc *packetConn) deadlineExceeded() bool {
	ns := pc.deadline.Load()
	return ns != 0 && ns < time.Now().UnixNano()
}

// lastFrameSize returns the size of the last packet read from the connection and whether it's depleted.
// should be called for every successful Read().
func (pc *packetConn) lastFrameStat() (int, bool) {
	return pc.lastBufSize, pc.lastPacket == nil
}

func (pc *packetConn) Read(b []byte) (n int, err error) {
	if pc.lastPacket != nil {
		// There is a partial buffer to continue reading from the previous
		// packet. Its io.EOF is ignored, as the packet may be empty, e.g. if
		// it's been kept by WaitForMore.
		n, _ = pc.lastBuf.Read(b)
		if pc.lastBuf.Len() == 0 {
			udpBufPool.Put(pc.lastPacket.pooledBuf)
			pc.lastPacket = nil
			pc.lastBuf = nil
		}
		return
	}
	// check deadline
	if pc.deadlineExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	for {
		var timerCh <-chan time.Time
		pc.deadlineMu.Lock()
		if pc.deadlineTimer != nil && pc.deadline.Load() != 0 {
			timerCh = pc.deadlineTimer.C
		}
		pc.deadlineMu.Unlock()

		select {
		case pkt := <-pc.readCh:
			if pkt == nil {
				// Channel is closed, as the flow has ended, e.g. as it's been
				// idle. Returning EOF here ensures that io.Copy() waiting on
				// the downstream for reads will terminate.
				return 0, io.EOF
			}
			// An empty packet, which UDP allows, reads as 0, nil, rather than
			// with the io.EOF of an empty buffer, as the flow goes on
			buf := bytes.NewReader(pkt.pooledBuf[:pkt.n])
			n, _ = buf.Read(b)
			if buf.Len() == 0 {
				// Buffer fully consumed, release it.
				udpBufPool.Put(pkt.pooledBuf)
			} else {
				// Buffer only partially consumed. Keep track of it for
				// next Read() call.
				pc.lastPacket = pkt
				pc.lastBuf = buf
			}
			pc.lastBufSize = pkt.n
			return
		case <-timerCh:
			// deadline may change during the wait, recheck
			if pc.deadlineExceeded() {
				return 0, os.ErrDeadlineExceeded
			}
			// next loop will run.
		}
	}
}

func (pc *packetConn) Write(b []byte) (n int, err error) {
	pc.writtenPackets.Add(1)
	return pc.WriteTo(b, pc.addr)
}

func (pc *packetConn) Close() error {
	pc.deadlineMu.Lock()
	if pc.deadlineTimer != nil {
		pc.deadlineTimer.Stop()
	}
	pc.deadlineMu.Unlock()

	if pc.lastPacket != nil {
		udpBufPool.Put(pc.lastPacket.pooledBuf)
		pc.lastPacket = nil
	}
	// Closing the split connection ends the flow, so that the next packet
	// from the downstream starts a new one, and makes the goroutine moving
	// its packets close readCh, which aborts any active Read(). It doesn't
	// close the UDP socket.
	_ = pc.PacketConn.Close()
	// Drain pending packets to ensure we release buffers back to the pool
	for pkt := range pc.readCh {
		udpBufPool.Put(pkt.pooledBuf)
	}
	return nil
}

func (pc *packetConn) RemoteAddr() net.Addr { return pc.addr }

// release hands the flow over to the fallback connection of the splitter, so
// that it misses none of the packets read: the packets given first, e.g. those
// prefetched in full while matching, then the packet read in part, if any, and
// the packets moved to readCh, but not read yet. The packets queued on the split
// connection and the later packets of the flow follow. It closes the split
// connection, so Close only releases what's left afterwards.
func (pc *packetConn) release(pkts [][]byte) error {
	if !pc.released.CompareAndSwap(false, true) {
		return nil
	}
	// Make the goroutine moving the packets close readCh without taking another
	// packet from the split connection, as an exceeded deadline prevails over
	// the packets queued on it
	_ = pc.PacketConn.SetReadDeadline(time.Unix(1, 0))

	var bufs [][]byte
	if pc.lastPacket != nil {
		pkts = append(pkts, pc.lastPacket.pooledBuf[:pc.lastPacket.n])
		bufs = append(bufs, pc.lastPacket.pooledBuf)
		pc.lastPacket, pc.lastBuf = nil, nil
	}
	for pkt := range pc.readCh {
		pkts = append(pkts, pkt.pooledBuf[:pkt.n])
		bufs = append(bufs, pkt.pooledBuf)
	}

	// Release copies the packets, so their buffers can be reused right away
	err := pc.PacketConn.(hybrid.SplitConn).Release(pkts...)
	for _, buf := range bufs {
		udpBufPool.Put(buf)
	}
	return err
}

// releaseToFallback is called by the packet-moving goroutine when the flow is
// recognized as stale. It hands the flow, the offending packet and everything
// already queued to the splitter's fallback. That way an unrecognized UDP
// handshake is never silently dropped: it reaches the fallback proxy at once,
// and the later packets of the same flow follow it there. Without a fallback,
// hybrid counts them as dropped, which is no worse than before.
func (pc *packetConn) releaseToFallback(pkt *packet) {
	if !pc.released.CompareAndSwap(false, true) {
		return
	}
	var pkts, bufs [][]byte
	if pkt != nil {
		pkts = append(pkts, pkt.pooledBuf[:pkt.n])
		bufs = append(bufs, pkt.pooledBuf)
	}
	for {
		select {
		case queued := <-pc.readCh:
			if queued != nil {
				pkts = append(pkts, queued.pooledBuf[:queued.n])
				bufs = append(bufs, queued.pooledBuf)
			}
		default:
			goto handOver
		}
	}
handOver:
	_ = pc.PacketConn.SetReadDeadline(time.Unix(1, 0))
	if sc, ok := pc.PacketConn.(hybrid.SplitConn); ok {
		_ = sc.Release(pkts...)
	}
	for _, buf := range bufs {
		udpBufPool.Put(buf)
	}
}

var udpBufPool = sync.Pool{
	New: func() any {
		// Buffers need to be as large as the largest datagram we'll consume, because
		// ReadFrom() can't resume partial reads.  (This is standard for UDP
		// sockets on *nix.)  So our buffer sizes are 9000 bytes to accommodate
		// networks with jumbo frames.  See also https://github.com/golang/go/issues/18056
		return make([]byte, udpBufSize)
	},
}

// udpBufSize is the size of the buffers of udpBufPool, and the largest packet
// read from a UDP socket. The splitter drops a larger one.
const udpBufSize = 9000

// udpAcceptQueueSize is the number of new flows of a UDP socket waiting to be
// handled, beyond which the splitter drops their first packets.
const udpAcceptQueueSize = 1024

// Interface guard
var _ caddyfile.Unmarshaler = (*Server)(nil)
