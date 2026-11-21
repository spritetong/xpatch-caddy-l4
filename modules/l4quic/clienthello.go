package l4quic

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
)

var errBadClientHello = errors.New("invalid TLS ClientHello")

// reassembleCrypto merges CRYPTO fragments by offset into a contiguous byte
// stream. QUIC Retry and retransmission can deliver the same offset more than
// once, so duplicates that agree are ignored. The returned bool reports
// whether the stream starting at offset 0 is complete through the TLS
// handshake header's declared length.
func reassembleCrypto(fragments []cryptoFragment) ([]byte, bool) {
	if len(fragments) == 0 {
		return nil, false
	}
	// Stable sort by offset; identical offsets keep arrival order.
	sorted := append([]cryptoFragment(nil), fragments...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].offset < sorted[j].offset })

	var out []byte
	next := uint64(0)
	for _, f := range sorted {
		if f.offset > next {
			break // gap: need more fragments
		}
		if f.offset < next {
			// Overlap with bytes already collected. Only accept if it agrees;
			// a conflicting retransmission is not trustworthy.
			skip := next - f.offset
			if int(skip) > len(f.payload) || !bytes.Equal(out[next-skip:next], f.payload[:skip]) {
				continue
			}
			f.payload = f.payload[skip:]
			f.offset = next
		}
		if len(f.payload) == 0 {
			continue
		}
		out = append(out, f.payload...)
		next += uint64(len(f.payload))

		// A TLS handshake message is 1 byte type + 3 byte length.
		if len(out) >= 4 {
			total := 4 + int(binary.BigEndian.Uint32(append([]byte{0}, out[1:4]...)))
			if len(out) >= total {
				return out[:total], true
			}
		}
	}
	return out, false
}

// sniffedHello holds the TLS ClientHello fields the layer4 matchers use.
type sniffedHello struct {
	serverName        string
	supportedProtos   []string
	cipherSuites      []uint16
	supportedVersions []uint16
}

// parseClientHello parses a TLS ClientHello handshake message (including its
// 4-byte header) into the fields used by caddytls.ConnectionMatcher. Unknown
// or malformed extensions are skipped, matching crypto/tls' tolerant behavior
// during parsing.
func parseClientHello(msg []byte) (*sniffedHello, error) {
	if len(msg) < 4 || msg[0] != 0x01 { // handshake type: client_hello
		return nil, errBadClientHello
	}
	bodyLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if bodyLen != len(msg)-4 {
		return nil, errBadClientHello
	}
	r := bytes.NewReader(msg[4:])

	// legacy_version + random
	if _, err := r.Seek(2+32, io.SeekCurrent); err != nil {
		return nil, errBadClientHello
	}
	// legacy_session_id
	sidLen, err := r.ReadByte()
	if err != nil || sidLen > 32 {
		return nil, errBadClientHello
	}
	if _, err := r.Seek(int64(sidLen), io.SeekCurrent); err != nil {
		return nil, errBadClientHello
	}
	// cipher_suites
	csLen, err := readUint16(r)
	if err != nil || csLen%2 != 0 || int(csLen) > r.Len() {
		return nil, errBadClientHello
	}
	cipherSuites := make([]uint16, 0, csLen/2)
	for i := uint16(0); i < csLen; i += 2 {
		v, _ := readUint16(r)
		cipherSuites = append(cipherSuites, v)
	}
	// legacy_compression_methods
	compLen, err := r.ReadByte()
	if err != nil || int(compLen) > r.Len() {
		return nil, errBadClientHello
	}
	if _, err := r.Seek(int64(compLen), io.SeekCurrent); err != nil {
		return nil, errBadClientHello
	}
	// extensions
	extLen, err := readUint16(r)
	if err != nil || int(extLen) > r.Len() {
		return nil, errBadClientHello
	}
	extensions := make([]byte, extLen)
	if _, err := io.ReadFull(r, extensions); err != nil {
		return nil, errBadClientHello
	}

	hello := &sniffedHello{cipherSuites: cipherSuites}
	extReader := bytes.NewReader(extensions)
	for extReader.Len() > 0 {
		extType, err := readUint16(extReader)
		if err != nil {
			break
		}
		extDataLen, err := readUint16(extReader)
		if err != nil || int(extDataLen) > extReader.Len() {
			break
		}
		extData := make([]byte, extDataLen)
		if _, err := io.ReadFull(extReader, extData); err != nil {
			break
		}
		switch extType {
		case 0x0000: // server_name
			hello.serverName = parseServerName(extData)
		case 0x0010: // application_layer_protocol_negotiation
			hello.supportedProtos = parseALPN(extData)
		case 0x002b: // supported_versions
			hello.supportedVersions = parseSupportedVersions(extData)
		}
	}
	return hello, nil
}

func parseServerName(data []byte) string {
	r := bytes.NewReader(data)
	listLen, err := readUint16(r)
	if err != nil || int(listLen) > r.Len() {
		return ""
	}
	for r.Len() > 0 {
		nameType, err := r.ReadByte()
		if err != nil {
			return ""
		}
		nameLen, err := readUint16(r)
		if err != nil || int(nameLen) > r.Len() {
			return ""
		}
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(r, name); err != nil {
			return ""
		}
		if nameType == 0 { // host_name
			return string(name)
		}
	}
	return ""
}

func parseALPN(data []byte) []string {
	r := bytes.NewReader(data)
	listLen, err := readUint16(r)
	if err != nil || int(listLen) > r.Len() {
		return nil
	}
	var protos []string
	for r.Len() > 0 {
		n, err := r.ReadByte()
		if err != nil || int(n) > r.Len() {
			break
		}
		proto := make([]byte, n)
		if _, err := io.ReadFull(r, proto); err != nil {
			break
		}
		protos = append(protos, string(proto))
	}
	return protos
}

func parseSupportedVersions(data []byte) []uint16 {
	if len(data) == 0 {
		return nil
	}
	listLen := int(data[0])
	if listLen > len(data)-1 || listLen%2 != 0 {
		return nil
	}
	versions := make([]uint16, 0, listLen/2)
	r := bytes.NewReader(data[1 : 1+listLen])
	for r.Len() > 0 {
		v, err := readUint16(r)
		if err != nil {
			break
		}
		versions = append(versions, v)
	}
	return versions
}

func readUint16(r *bytes.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// clientHelloInfo mirrors the structure built after a successful handshake in
// the original matcher. SupportedProtos contains the full ALPN list offered by
// the client, which is exactly what l4tls.MatchALPN expects.
func clientHelloInfo(cx net.Conn, hello *sniffedHello) *tls.ClientHelloInfo {
	versions := hello.supportedVersions
	if len(versions) == 0 {
		versions = []uint16{tls.VersionTLS13}
	}
	ciphers := hello.cipherSuites
	if len(ciphers) == 0 {
		ciphers = []uint16{tls.TLS_AES_128_GCM_SHA256}
	}
	return &tls.ClientHelloInfo{
		CipherSuites:      ciphers,
		ServerName:        hello.serverName,
		SupportedProtos:   hello.supportedProtos,
		SupportedVersions: versions,
		Conn:              cx,
	}
}
