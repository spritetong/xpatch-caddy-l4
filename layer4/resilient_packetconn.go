package layer4

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// resilientPacketConn shields a UDP socket from errors that are local to one
// datagram. hybrid's splitter stops on the first error of the underlying
// PacketConn, which would take down the whole listener until Caddy is
// restarted. ICMP errors from a previous send (ECONNREFUSED, WSAECONNRESET,
// ENOBUFS, ...) are normal for UDP and must not have that effect.
type resilientPacketConn struct {
	net.PacketConn
	logger *zap.Logger
	closed atomic.Bool
}

func newResilientPacketConn(pc net.PacketConn, logger *zap.Logger) *resilientPacketConn {
	return &resilientPacketConn{PacketConn: pc, logger: logger}
}

func (r *resilientPacketConn) isClosed() bool { return r.closed.Load() }

func (r *resilientPacketConn) Close() error {
	r.closed.Store(true)
	return r.PacketConn.Close()
}

const (
	resilientInitialBackoff = time.Millisecond
	resilientMaxBackoff     = 25 * time.Millisecond
)

// ReadFrom retries datagram-local errors instead of propagating them to the
// splitter. Timeouts are passed through: the splitter owns the read deadline
// and needs to see them. Backoff prevents a permanently failing socket from
// turning the retry loop into a busy spin.
func (r *resilientPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	backoff := resilientInitialBackoff
	for {
		n, addr, err = r.PacketConn.ReadFrom(b)
		if err == nil || r.closed.Load() {
			return n, addr, err
		}
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			r.closed.Store(true)
			return n, addr, err
		}
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return n, addr, err
		}
		if r.logger != nil {
			r.logger.Debug("transient UDP socket read error ignored", zap.Error(err))
		}
		time.Sleep(backoff)
		if backoff < resilientMaxBackoff {
			backoff *= 2
		}
	}
}
