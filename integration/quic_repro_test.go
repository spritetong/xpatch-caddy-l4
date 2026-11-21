package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func testQUICCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startQUICUpstream runs a QUIC server that echoes a stream's first payload,
// prefixed with "echo:".
func startQUICUpstream(t *testing.T, addr string) {
	t.Helper()
	ln, err := quic.ListenAddr(addr, &tls.Config{
		Certificates: []tls.Certificate{testQUICCert(t)},
		NextProtos:   []string{"h2c"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				buf := make([]byte, 64)
				if n, err := stream.Read(buf); err == nil && n > 0 {
					_, _ = stream.Write([]byte("echo:" + string(buf[:n])))
				}
			}(conn)
		}
	}()
}

// startVerifiedQUICUpstream starts a QUIC echo server with a certificate the
// test client can verify, and returns that certificate. This models a real
// client that trusts the upstream, not the matcher's generated certificate.
func startVerifiedQUICUpstream(t *testing.T, addr string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := quic.ListenAddr(addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2c"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				buf := make([]byte, 64)
				if n, err := stream.Read(buf); err == nil && n > 0 {
					_, _ = stream.Write([]byte("echo:" + string(buf[:n])))
				}
			}(conn)
		}
	}()
	return cert
}

// TestQUICMatchWhenHandshakeFailsSkipsNegatedRoute verifies match_when_handshake_fails: when
// the fake handshake cannot decode a ClientHello, the QUIC matcher reports a
// match so the negated h3 route skips the flow and the fallback raw route
// still receives it.
func TestQUICMatchWhenHandshakeFailsSkipsNegatedRoute(t *testing.T) {
	newSink := func() (net.PacketConn, chan int) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		ch := make(chan int, 1)
		go func() {
			buf := make([]byte, 9000)
			n, _, err := pc.ReadFrom(buf)
			if err == nil {
				ch <- n
			}
		}()
		return pc, ch
	}
	h3Sink, h3Ch := newSink()
	rawSink, rawCh := newSink()

	freePort := func() string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		_ = pc.Close()
		return addr
	}
	l4Addr := freePort()
	cfg := fmt.Sprintf(`{
		"apps": {
			"layer4": {
				"servers": {
					"quic-dispatch": {
						"listen": ["udp/%s"],
						"routes": [
							{
								"match": [{"not": [{"quic": {"alpn": ["h2c"], "match_when_handshake_fails": true}}]}],
								"handle": [{"handler": "proxy", "proxy_protocol": "v2", "upstreams": [{"dial": ["udp/%s"]}]}]
							},
							{
								"handle": [{"handler": "proxy", "upstreams": [{"dial": ["udp/%s"]}]}]
							}
						]
					}
				}
			}
		}
	}`, l4Addr, h3Sink.LocalAddr().String(), rawSink.LocalAddr().String())

	loadCaddyWithJSON(t, []byte(cfg))
	defer stopCaddy(t)

	// A QUIC-looking long-header packet that cannot produce a ClientHello.
	malformed := make([]byte, 1300)
	malformed[0] = 0xc0
	binary.BigEndian.PutUint32(malformed[1:5], 1)
	if _, err := rand.Read(malformed[5:]); err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.WriteTo(malformed, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portOf(l4Addr)}); err != nil {
		t.Fatal(err)
	}

	select {
	case n := <-rawCh:
		if n != len(malformed) {
			t.Fatalf("raw upstream got %d bytes, want %d", n, len(malformed))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake failure was not failed open to the raw fallback route")
	}
	select {
	case n := <-h3Ch:
		t.Fatalf("h3 upstream unexpectedly got %d bytes", n)
	case <-time.After(500 * time.Millisecond):
	}
}

// TestQUICRouteDecidesFromClientHello replays a real QUIC Initial without a
// client that completes the handshake. The matcher's own handshake deadline
// must not change the route: ALPN [h3, h2c] is already known from the
// ClientHello and must select the raw route.
func TestQUICRouteDecidesFromClientHello(t *testing.T) {
	capture, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	initialCh := make(chan [][]byte, 1)
	go func() {
		var packets [][]byte
		buf := make([]byte, 9000)
		for len(packets) < 2 {
			n, _, err := capture.ReadFrom(buf)
			if err != nil {
				return
			}
			packets = append(packets, append([]byte(nil), buf[:n]...))
		}
		initialCh <- packets
	}()
	// The dial is expected to time out; only its first datagram is needed.
	go func() {
		_, _ = quic.DialAddr(ctx, capture.LocalAddr().String(), &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3", "h2c"},
		}, &quic.Config{})
	}()
	var initials [][]byte
	select {
	case initials = <-initialCh:
	case <-time.After(2 * time.Second):
		t.Fatal("did not capture two QUIC Initials")
	}

	newSink := func() (net.PacketConn, chan int) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		ch := make(chan int, 1)
		go func() {
			buf := make([]byte, 9000)
			n, _, err := pc.ReadFrom(buf)
			if err == nil {
				ch <- n
			}
		}()
		return pc, ch
	}
	rawSink, rawCh := newSink()
	h3Sink, h3Ch := newSink()

	freePort := func() string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		_ = pc.Close()
		return addr
	}
	l4Addr := freePort()
	cfg := fmt.Sprintf(`{
		"apps": {
			"layer4": {
				"servers": {
					"quic-dispatch": {
						"listen": ["udp/%s"],
						"routes": [
							{
								"match": [{"quic": {"alpn": ["h2c"]}}],
								"handle": [{"handler": "proxy", "upstreams": [{"dial": ["udp/%s"]}]}]
							},
							{
								"handle": [{"handler": "proxy", "proxy_protocol": "v2", "upstreams": [{"dial": ["udp/%s"]}]}]
							}
						]
					}
				}
			}
		}
	}`, l4Addr, rawSink.LocalAddr().String(), h3Sink.LocalAddr().String())

	loadCaddyWithJSON(t, []byte(cfg))
	defer stopCaddy(t)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, pkt := range initials {
		if _, err = client.WriteTo(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portOf(l4Addr)}); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case n := <-rawCh:
		if n < len(initials[0]) {
			t.Fatalf("raw upstream got %d bytes, want at least %d", n, len(initials[0]))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ClientHello-matching Initial was not routed to raw upstream")
	}
	select {
	case n := <-h3Ch:
		t.Fatalf("h3 upstream unexpectedly got %d bytes", n)
	case <-time.After(500 * time.Millisecond):
	}
}

func portOf(address string) int {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		panic(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}
	return n
}

// TestQUICRouteWithVerifyingClient models the production setup: the internal
// h3 route is matched by `not quic alpn h2c`, while raw QUIC clients offer
// h2c and must reach the catch-all route. The client verifies the upstream
// certificate, as real clients do. The matcher must not need the client to
// trust its own generated certificate in order to decide the ALPN match.
func TestQUICRouteWithVerifyingClient(t *testing.T) {
	h3Upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer h3Upstream.Close()
	go func() {
		buf := make([]byte, 9000)
		for {
			if _, _, err := h3Upstream.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	freePort := func() string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		_ = pc.Close()
		return addr
	}
	rawAddr := freePort()
	cert := startVerifiedQUICUpstream(t, rawAddr)
	l4Addr := freePort()

	cfg := fmt.Sprintf(`{
	"apps": {
		"layer4": {
			"servers": {
				"quic-dispatch": {
					"listen": ["udp/%s"],
					"routes": [
						{
							"match": [{"not": [{"quic": {"alpn": ["h2c"]}}]}],
							"handle": [{"handler": "proxy", "proxy_protocol": "v2", "upstreams": [{"dial": ["udp/%s"]}]}]
						},
						{
							"handle": [{"handler": "proxy", "upstreams": [{"dial": ["udp/%s"]}]}]
						}
					]
				}
			}
		}
	}
}`, l4Addr, h3Upstream.LocalAddr().String(), rawAddr)

	loadCaddyWithJSON(t, []byte(cfg))
	defer stopCaddy(t)

	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, l4Addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		NextProtos: []string{"h2c"},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("raw QUIC dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	_, _ = stream.Write([]byte("raw-client"))
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if got, want := string(buf[:n]), "echo:raw-client"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}

}

// TestQUICRouteSurvivesDCIDChange reproduces the raw-QUIC routing failure:
// a client that completes a QUIC handshake through `not quic alpn h2c` may
// resend its Initial with a different DCID (Retry / version negotiation)
// while the upstream is already answering. The flow must stay on the same
// route; ending it would make the client's remaining packets start a new
// flow that is misrouted to the proxy-protocol route.
func TestQUICRouteSurvivesDCIDChange(t *testing.T) {
	// Stand-in for the h3-upstream route: it must never receive these clients.
	wrong, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	go func() {
		buf := make([]byte, 9000)
		for {
			if _, _, err := wrong.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	freePort := func() string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		_ = pc.Close()
		return addr
	}
	upAddr := freePort()
	startQUICUpstream(t, upAddr)
	l4Addr := freePort()

	cfg := fmt.Sprintf(`{
	"apps": {
		"layer4": {
			"servers": {
				"quic-dispatch": {
					"listen": ["udp/%s"],
					"routes": [
						{
							"match": [{"not": [{"quic": {"alpn": ["h2c"]}}]}],
							"handle": [{"handler": "proxy", "proxy_protocol": "v2", "upstreams": [{"dial": ["udp/%s"]}]}]
						},
						{
							"handle": [{"handler": "proxy", "upstreams": [{"dial": ["udp/%s"]}]}]
						}
					]
				}
			}
		}
	}
}`, l4Addr, wrong.LocalAddr().String(), upAddr)

	loadCaddyWithJSON(t, []byte(cfg))
	defer stopCaddy(t)

	for _, id := range []string{"client-1", "client-2"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := quic.DialAddr(ctx, l4Addr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3", "h2c"},
		}, &quic.Config{})
		if err != nil {
			cancel()
			t.Fatalf("%s dial: %v", id, err)
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			cancel()
			t.Fatalf("%s open stream: %v", id, err)
		}
		_, _ = stream.Write([]byte(id))
		buf := make([]byte, 64)
		_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := stream.Read(buf)
		cancel()
		_ = conn.CloseWithError(0, "")
		if err != nil && err != io.EOF {
			t.Fatalf("%s read: %v", id, err)
		}
		if got, want := string(buf[:n]), "echo:"+id; got != want {
			t.Fatalf("%s response = %q, want %q", id, got, want)
		}
	}
}

// TestQUICRouteConcurrentLiveClients verifies that multiple QUIC clients can
// connect and stay connected simultaneously without breaking each other.
func TestQUICRouteConcurrentLiveClients(t *testing.T) {
	wrong, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	go func() {
		buf := make([]byte, 9000)
		for {
			if _, _, err := wrong.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	freePort := func() string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		_ = pc.Close()
		return addr
	}
	upAddr := freePort()
	startQUICUpstream(t, upAddr)
	l4Addr := freePort()

	cfg := fmt.Sprintf(`{
	"apps": {
		"layer4": {
			"servers": {
				"quic-dispatch": {
					"listen": ["udp/%s"],
					"routes": [
						{
							"match": [{"not": [{"quic": {"alpn": ["h2c"]}}]}],
							"handle": [{"handler": "proxy", "proxy_protocol": "v2", "upstreams": [{"dial": ["udp/%s"]}]}]
						},
						{
							"handle": [{"handler": "proxy", "upstreams": [{"dial": ["udp/%s"]}]}]
						}
					]
				}
			}
		}
	}
}`, l4Addr, wrong.LocalAddr().String(), upAddr)

	loadCaddyWithJSON(t, []byte(cfg))
	defer stopCaddy(t)

	const clientCount = 5
	type clientState struct {
		conn   *quic.Conn
		stream *quic.Stream
	}
	clients := make([]clientState, clientCount)

	// Step 1: dial and open a stream on all clients at the same time.
	dialErr := make(chan error, clientCount)
	var dialWG sync.WaitGroup
	for i := 0; i < clientCount; i++ {
		i := i
		dialWG.Add(1)
		go func() {
			defer dialWG.Done()
			id := fmt.Sprintf("client-%d", i+1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, l4Addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3", "h2c"},
			}, &quic.Config{})
			if err != nil {
				dialErr <- fmt.Errorf("%s dial: %w", id, err)
				return
			}
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				_ = conn.CloseWithError(0, "")
				dialErr <- fmt.Errorf("%s open stream: %w", id, err)
				return
			}
			clients[i] = clientState{conn: conn, stream: stream}
		}()
	}
	dialWG.Wait()
	for i := range clients {
		if clients[i].conn != nil {
			conn := clients[i].conn
			t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
		}
	}
	close(dialErr)
	for err := range dialErr {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	// Step 2: all clients transmit concurrently, while every connection is
	// still live, and each response must come back on its own stream.
	exchangeErr := make(chan error, clientCount)
	var exchangeWG sync.WaitGroup
	for i := 0; i < clientCount; i++ {
		i := i
		exchangeWG.Add(1)
		go func() {
			defer exchangeWG.Done()
			id := fmt.Sprintf("client-%d", i+1)
			stream := clients[i].stream
			if _, err := stream.Write([]byte(id)); err != nil {
				exchangeErr <- fmt.Errorf("%s write: %w", id, err)
				return
			}
			buf := make([]byte, 64)
			_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := stream.Read(buf)
			if err != nil && err != io.EOF {
				exchangeErr <- fmt.Errorf("%s read: %w", id, err)
				return
			}
			if got, want := string(buf[:n]), "echo:"+id; got != want {
				exchangeErr <- fmt.Errorf("%s response = %q, want %q", id, got, want)
			}
		}()
	}
	exchangeWG.Wait()
	close(exchangeErr)
	for err := range exchangeErr {
		t.Error(err)
	}
}
