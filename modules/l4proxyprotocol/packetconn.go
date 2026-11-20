package l4proxyprotocol

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&PacketConnWrapper{})
}

// PacketConnWrapper provides PROXY protocol support for packet connections (UDP/QUIC/HTTP3).
type PacketConnWrapper struct {
	Allow []string `json:"allow,omitempty"`
	allow []netip.Prefix

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (PacketConnWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.packetconns.proxy_protocol",
		New: func() caddy.Module { return new(PacketConnWrapper) },
	}
}

// Provision sets up the PacketConnWrapper.
func (pcw *PacketConnWrapper) Provision(ctx caddy.Context) error {
	pcw.logger = ctx.Logger()
	repl := caddy.NewReplacer()
	for _, allowCIDR := range pcw.Allow {
		allowCIDR = repl.ReplaceAll(allowCIDR, "")
		ipnet, err := netip.ParsePrefix(allowCIDR)
		if err != nil {
			return fmt.Errorf("parsing allow CIDR %q: %w", allowCIDR, err)
		}
		pcw.allow = append(pcw.allow, ipnet)
	}
	return nil
}

// UnmarshalCaddyfile sets up the PacketConnWrapper from Caddyfile tokens. Syntax:
//
//	proxy_protocol {
//		allow <ranges...>
//	}
func (pcw *PacketConnWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name
	for d.NextBlock(0) {
		switch d.Val() {
		case "allow":
			pcw.Allow = append(pcw.Allow, d.RemainingArgs()...)
		default:
			return d.ArgErr()
		}
	}
	return nil
}

// WrapPacketConn wraps a net.PacketConn with PROXY protocol v2 header parsing for incoming UDP datagrams.
func (pcw *PacketConnWrapper) WrapPacketConn(pc net.PacketConn) net.PacketConn {
	return newProxyPacketConn(pc, pcw.allow, pcw.logger)
}

type proxyPacketConn struct {
	net.PacketConn

	allow  []netip.Prefix
	logger *zap.Logger

	mu    sync.RWMutex
	flows map[string]flowEntry

	closed    chan struct{}
	closeOnce sync.Once
}

type flowEntry struct {
	proxyAddr net.Addr
	lastSeen  time.Time
}

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

func newProxyPacketConn(inner net.PacketConn, allow []netip.Prefix, logger *zap.Logger) *proxyPacketConn {
	p := &proxyPacketConn{
		PacketConn: inner,
		allow:      allow,
		logger:     logger,
		flows:      make(map[string]flowEntry),
		closed:     make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
}

func (c *proxyPacketConn) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			const flowTimeout = 2 * time.Minute
			for k, entry := range c.flows {
				if now.Sub(entry.lastSeen) > flowTimeout {
					delete(c.flows, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

// Close closes the connection and terminates the background cleanup goroutine.
func (c *proxyPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return c.PacketConn.Close()
}

// ReadFrom reads one datagram, parses its PROXY protocol header, and returns the payload with the client address.
func (c *proxyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, proxyAddr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}

		// If allow list is configured, enforce source IP validation on proxyAddr
		if len(c.allow) > 0 {
			host, _, err := net.SplitHostPort(proxyAddr.String())
			if err != nil {
				if c.logger != nil {
					c.logger.Debug("proxy address invalid hostport", zap.String("addr", proxyAddr.String()), zap.Error(err))
				}
				continue
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				if c.logger != nil {
					c.logger.Debug("proxy address invalid IP", zap.String("host", host), zap.Error(err))
				}
				continue
			}
			allowed := false
			for _, prefix := range c.allow {
				if prefix.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				if c.logger != nil {
					c.logger.Debug("dropping UDP datagram from untrusted proxy", zap.String("addr", proxyAddr.String()))
				}
				continue
			}
		}

		header, payload, err := proxyproto.ParseUDPDatagram(buf[:n])
		if err != nil {
			if c.logger != nil {
				c.logger.Debug("dropping datagram: invalid PROXY header", zap.String("proxy", proxyAddr.String()), zap.Error(err))
			}
			continue
		}

		var clientAddr net.Addr
		if header.Command.IsLocal() || header.SourceAddr == nil {
			clientAddr = proxyAddr
		} else {
			clientAddr = header.SourceAddr
		}

		now := time.Now()
		c.mu.Lock()
		c.flows[clientAddr.String()] = flowEntry{
			proxyAddr: proxyAddr,
			lastSeen:  now,
		}
		c.mu.Unlock()

		nCopied := copy(p, payload)
		return nCopied, clientAddr, nil
	}
}

// WriteTo sends a reply to a client address, routing it to the proxy that relayed for that client.
func (c *proxyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.RLock()
	entry, ok := c.flows[addr.String()]
	c.mu.RUnlock()
	if !ok {
		// Fallback: if not in flow table, write directly to addr
		return c.PacketConn.WriteTo(p, addr)
	}
	return c.PacketConn.WriteTo(p, entry.proxyAddr)
}

// Interface guards
var (
	_ caddy.Provisioner       = (*PacketConnWrapper)(nil)
	_ caddy.Module            = (*PacketConnWrapper)(nil)
	_ caddy.PacketConnWrapper = (*PacketConnWrapper)(nil)
	_ caddyfile.Unmarshaler   = (*PacketConnWrapper)(nil)
)
