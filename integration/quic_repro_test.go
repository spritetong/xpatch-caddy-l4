package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
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
