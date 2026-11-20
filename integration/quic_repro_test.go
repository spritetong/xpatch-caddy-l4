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
