package l4quic

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

// TestSniffQuicheGreaseClientHello covers quiche-client's default wire version
// (0xbabababa), which is a reserved GREASE version. Those Initials use v1 key
// schedule and framing, but the sniffer used to reject them as unsupported
// before it could see any ClientHello.
func TestSniffQuicheGreaseClientHello(t *testing.T) {
	packets := loadQuicheGreasePackets(t)
	var fragments []cryptoFragment
	for i, pkt := range packets {
		got, err := decryptInitial(pkt)
		assertNoError(t, err)
		if got.version != quicVersion1 {
			t.Errorf("packet %d: version = %#x, want v1 keys", i, got.version)
		}
		fragments = append(fragments, got.fragments...)
	}
	msg, ok := reassembleCrypto(fragments)
	if !ok {
		t.Fatalf("ClientHello incomplete after %d fragments", len(fragments))
	}
	hello, err := parseClientHello(msg)
	assertNoError(t, err)
	wantALPN := []string{"h3", "hq-interop", "http/0.9"}
	if len(hello.supportedProtos) != len(wantALPN) {
		t.Fatalf("alpn = %q, want %q", hello.supportedProtos, wantALPN)
	}
	for i := range wantALPN {
		if hello.supportedProtos[i] != wantALPN[i] {
			t.Errorf("alpn = %q, want %q", hello.supportedProtos, wantALPN)
		}
	}
	if hello.serverName != "localhost" {
		t.Errorf("sni = %q, want localhost", hello.serverName)
	}
}

// TestMatchQUICGreaseClientHelloDecidesIndependentlyOfFailureResult proves a
// recovered ClientHello produces a definitive verdict. The configured
// failure result must only matter when no ClientHello can be recovered.
func TestMatchQUICGreaseClientHelloDecidesIndependentlyOfFailureResult(t *testing.T) {
	ctx := testContext(t)
	packets := loadQuicheGreasePackets(t)
	for _, tc := range []struct {
		alpn       string
		failResult bool
		want       bool
	}{
		{"h3", false, true},
		{"h3", true, true},
		{"h2c", false, false},
		{"h2c", true, false},
	} {
		m := &MatchQUIC{
			MatchWhenHandshakeFails: tc.failResult,
			MatchersRaw: caddy.ModuleMap{
				"alpn": json.RawMessage(`["` + tc.alpn + `"]`),
			},
		}
		assertNoError(t, m.Provision(ctx))
		cx := layer4.WrapConnection(&datagramConn{packets: packets}, []byte{}, zap.NewNop())
		got, err := m.Match(cx)
		assertNoError(t, err)
		if got != tc.want {
			t.Errorf("alpn=%q failResult=%v: matched = %v, want %v",
				tc.alpn, tc.failResult, got, tc.want)
		}
	}
}

func loadQuicheGreasePackets(t *testing.T) [][]byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/quiche_grease.hex")
	assertNoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	packets := make([][]byte, 0, len(lines))
	for _, line := range lines {
		pkt, err := hex.DecodeString(strings.TrimSpace(line))
		assertNoError(t, err)
		packets = append(packets, pkt)
	}
	return packets
}

// datagramConn returns one captured UDP datagram per Read, then EOF.
type datagramConn struct {
	packets [][]byte
	idx     int
}

func (c *datagramConn) Read(p []byte) (int, error) {
	if c.idx >= len(c.packets) {
		return 0, io.EOF
	}
	n := copy(p, c.packets[c.idx])
	c.idx++
	return n, nil
}
func (c *datagramConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *datagramConn) Close() error                { return nil }
func (c *datagramConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (c *datagramConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (c *datagramConn) SetDeadline(time.Time) error      { return nil }
func (c *datagramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *datagramConn) SetWriteDeadline(time.Time) error { return nil }
