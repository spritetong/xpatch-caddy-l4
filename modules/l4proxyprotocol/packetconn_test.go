package l4proxyprotocol

import (
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/pires/go-proxyproto"
)

func TestPacketConnWrapper(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer inner.Close()

	wrapper := &PacketConnWrapper{
		Allow: []string{"127.0.0.1/32"},
	}
	if err := wrapper.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	wrapped := wrapper.WrapPacketConn(inner)
	defer wrapped.Close()

	// Client socket
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Build PROXY protocol v2 datagram
	clientVirtualAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 54321}
	serverVirtualAddr := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}

	header := proxyproto.HeaderProxyFromAddrs(2, clientVirtualAddr, serverVirtualAddr)
	payload := []byte("QUIC-PAYLOAD-TEST")

	datagram, err := header.FormatUDPDatagram(payload)
	if err != nil {
		t.Fatalf("failed to format datagram: %v", err)
	}

	// Send datagram from client to wrapped listener
	_, err = client.WriteTo(datagram, inner.LocalAddr())
	if err != nil {
		t.Fatalf("failed to write datagram: %v", err)
	}

	// Read from wrapped connection
	readBuf := make([]byte, 1024)
	_ = wrapped.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, srcAddr, err := wrapped.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("failed to read from wrapped: %v", err)
	}

	if string(readBuf[:n]) != string(payload) {
		t.Errorf("expected payload %q, got %q", payload, readBuf[:n])
	}

	if srcAddr.String() != clientVirtualAddr.String() {
		t.Errorf("expected virtual client address %s, got %s", clientVirtualAddr, srcAddr)
	}

	// Send reply back to virtual client address through wrapped
	replyPayload := []byte("QUIC-REPLY-TEST")
	_, err = wrapped.WriteTo(replyPayload, srcAddr)
	if err != nil {
		t.Fatalf("failed to write reply: %v", err)
	}

	// Client reads reply
	clientReadBuf := make([]byte, 1024)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	clientN, replyFrom, err := client.ReadFrom(clientReadBuf)
	if err != nil {
		t.Fatalf("client failed to read reply: %v", err)
	}

	if string(clientReadBuf[:clientN]) != string(replyPayload) {
		t.Errorf("client expected %q, got %q", replyPayload, clientReadBuf[:clientN])
	}

	if replyFrom.String() != inner.LocalAddr().String() {
		t.Errorf("expected reply from %s, got %s", inner.LocalAddr(), replyFrom)
	}
}
