package l4quic

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// QUIC versions supported by the Initial sniffer.
const (
	quicVersionDraft29 uint32 = 0xff00001d
	quicVersion1       uint32 = 0x00000001
	quicVersion2       uint32 = 0x6b3343cf
)

// Initial salts, RFC 9001 §5.2 and RFC 9369 §5.2.
var (
	quicSaltDraft29 = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltV1      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2      = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

var (
	errNotQUICInitial      = errors.New("not a QUIC Initial packet")
	errUnsupportedQUICVer  = errors.New("unsupported QUIC version")
	errInitialTooShort     = errors.New("QUIC Initial packet too short")
	errInitialTruncated    = errors.New("QUIC Initial packet truncated")
	errBadHeaderProtection = errors.New("QUIC Initial header protection failed")
)

// cryptoFragment is a piece of the QUIC CRYPTO stream. CRYPTO frames carry an
// offset so fragments from multiple Initial datagrams can be reassembled.
type cryptoFragment struct {
	offset  uint64
	payload []byte
}

// decryptedInitial is the result of decrypting one Initial datagram.
type decryptedInitial struct {
	version   uint32
	fragments []cryptoFragment
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446 §7.1 with an
// empty context, as used for QUIC Initial key derivation.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1)
	binary.BigEndian.PutUint16(b, uint16(length)) //nolint:gosec // HKDF output length is small
	b[2] = byte(6 + len(label))                   //nolint:gosec // TLS labels are short, bounded by the caller
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = append(b, 0) // context length = 0
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(crypto.SHA256.New, secret, b), out); err != nil {
		// HKDF-Expand with a valid hash and length cannot fail here.
		panic(fmt.Errorf("quic sniffer: HKDF-Expand-Label: %w", err))
	}
	return out
}

// readUvarint reads a QUIC variable-length integer (RFC 9000 §16).
func readUvarint(r *bytes.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << ((first & 0xc0) >> 6)
	v := uint64(first & 0x3f)
	for i := 1; i < n; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// initialSalt returns the Initial salt for a supported version.
func initialSalt(version uint32) []byte {
	switch version {
	case quicVersion1:
		return quicSaltV1
	case quicVersion2:
		return quicSaltV2
	case quicVersionDraft29:
		return quicSaltDraft29
	default:
		return nil
	}
}

// isGreaseVersion reports whether v is a reserved GREASE version. RFC 9000
// §6.3 reserves versions of the form 0x?a?a?a?a for version negotiation.
// Such a packet uses the framing and Initial keys of a supported version,
// so the sniffer derives keys from that version instead of rejecting it.
func isGreaseVersion(v uint32) bool {
	return v&0x0f0f0f0f == 0x0a0a0a0a
}

// initialKeyAndIV derives the client Initial key and IV from the DCID.
// QUIC Initial keys are public: RFC 9001 §5.2 states this encryption level
// provides no confidentiality, only integrity. That is what makes passive
// ClientHello sniffing possible without a handshake.
func initialKeyAndIV(dcid []byte, version uint32) (key, iv []byte) {
	salt := initialSalt(version)
	initialSecret := hkdf.Extract(crypto.SHA256.New, dcid, salt)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())

	keyLabel, ivLabel := "quic key", "quic iv"
	if version == quicVersion2 {
		keyLabel, ivLabel = "quicv2 key", "quicv2 iv"
	}
	return hkdfExpandLabel(clientSecret, keyLabel, 16),
		hkdfExpandLabel(clientSecret, ivLabel, 12)
}

// headerProtectionKey derives the client Initial header-protection key.
func headerProtectionKey(dcid []byte, version uint32) []byte {
	salt := initialSalt(version)
	initialSecret := hkdf.Extract(crypto.SHA256.New, dcid, salt)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())
	label := "quic hp"
	if version == quicVersion2 {
		label = "quicv2 hp"
	}
	return hkdfExpandLabel(clientSecret, label, 16)
}

// decryptInitialPayload opens the AES-GCM protected payload of an Initial
// packet. QUIC XORs the packet number into the last 8 bytes of the IV.
func decryptInitialPayload(key, iv []byte, pn uint64, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, iv)
	var pnBytes [8]byte
	binary.BigEndian.PutUint64(pnBytes[:], pn)
	for i := range pnBytes {
		nonce[4+i] ^= pnBytes[i]
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// decryptInitial decrypts one client Initial datagram and returns its CRYPTO
// frames. Reserved GREASE versions are keyed using the v1 or v2 format their
// packet type impersonates. It is a pure function with no mutable state, so
// it is safe to call from concurrently handled connections.
func decryptInitial(pkt []byte) (*decryptedInitial, error) {
	if len(pkt) < 1+4+2 {
		return nil, errInitialTooShort
	}

	r := bytes.NewReader(pkt)
	first, err := r.ReadByte()
	if err != nil {
		return nil, errInitialTooShort
	}
	// Long header (bit 7) and fixed bit (bit 6) must both be set.
	if first&0xc0 != 0xc0 {
		return nil, errNotQUICInitial
	}

	var version uint32
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, errInitialTooShort
	}
	// Long packet type occupies bits 4-5 and is not covered by header
	// protection. v1/draft-29 encode Initial as 0, v2 as 2. A GREASE version
	// impersonates one of those formats; its packet type tells us which key
	// schedule to use. Report the impersonated version so callers get a
	// meaningful protocol name.
	packetType := (first & 0x30) >> 4
	var keyVersion uint32
	switch version {
	case quicVersion1, quicVersionDraft29:
		if packetType != 0 {
			return nil, errNotQUICInitial
		}
		keyVersion = version
	case quicVersion2:
		if packetType != 2 {
			return nil, errNotQUICInitial
		}
		keyVersion = version
	default:
		if !isGreaseVersion(version) {
			return nil, errUnsupportedQUICVer
		}
		switch packetType {
		case 0:
			keyVersion = quicVersion1
		case 2:
			keyVersion = quicVersion2
		default:
			return nil, errNotQUICInitial
		}
	}

	dcidLen, err := r.ReadByte()
	if err != nil || dcidLen == 0 || dcidLen > 20 {
		return nil, errInitialTooShort
	}
	dcid := make([]byte, dcidLen)
	if _, err := io.ReadFull(r, dcid); err != nil {
		return nil, errInitialTooShort
	}
	scidLen, err := r.ReadByte()
	if err != nil {
		return nil, errInitialTooShort
	}
	if _, err := r.Seek(int64(scidLen), io.SeekCurrent); err != nil {
		return nil, errInitialTooShort
	}
	tokenLen, err := readUvarint(r)
	if err != nil {
		return nil, errInitialTooShort
	}
	if tokenLen > uint64(len(pkt)) {
		return nil, errInitialTooShort
	}
	if _, err := r.Seek(int64(tokenLen), io.SeekCurrent); err != nil { //nolint:gosec // tokenLen bounded by packet length above
		return nil, errInitialTooShort
	}
	packetLen, err := readUvarint(r)
	if err != nil {
		return nil, errInitialTooShort
	}

	// hdrLen is the offset of the (protected) packet number field.
	hdrLen := len(pkt) - r.Len()
	if packetLen == 0 || packetLen > uint64(len(pkt)-hdrLen) { //nolint:gosec // len(pkt)-hdrLen is non-negative
		return nil, errInitialTruncated
	}
	// Header protection sample starts 4 bytes after the packet number field.
	sampleStart := hdrLen + 4
	if sampleStart+16 > len(pkt) {
		return nil, errInitialTooShort
	}

	block, err := aes.NewCipher(headerProtectionKey(dcid, keyVersion))
	if err != nil {
		return nil, errBadHeaderProtection
	}
	var mask [16]byte
	block.Encrypt(mask[:], pkt[sampleStart:sampleStart+16])

	plain := append([]byte(nil), pkt...)
	plain[0] ^= mask[0] & 0x0f
	// XOR the first four bytes; bytes beyond the actual packet number are
	// restored below once the real length is known.
	for i := range 4 {
		plain[hdrLen+i] ^= mask[i+1]
	}
	pnLen := int(plain[0]&0x03) + 1
	if pnLen > 4 || hdrLen+pnLen > len(pkt) {
		return nil, errBadHeaderProtection
	}
	extHdrLen := hdrLen + pnLen
	copy(plain[extHdrLen:hdrLen+4], pkt[extHdrLen:hdrLen+4])

	var pn uint64
	for i := range pnLen {
		pn = pn<<8 | uint64(plain[hdrLen+i])
	}

	key, iv := initialKeyAndIV(dcid, keyVersion)
	payloadLen := int(packetLen) //nolint:gosec // bounded by packetLen <= len(pkt)-hdrLen
	payload, err := decryptInitialPayload(key, iv, pn,
		plain[extHdrLen:hdrLen+payloadLen], plain[:extHdrLen])
	if err != nil {
		return nil, err
	}

	fragments, err := parseCryptoFrames(payload)
	if err != nil {
		return nil, err
	}
	return &decryptedInitial{version: keyVersion, fragments: fragments}, nil
}

// parseCryptoFrames extracts CRYPTO frames from a decrypted Initial payload.
// Frames that cannot appear in a client Initial are skipped conservatively so
// a single unrecognized frame does not discard an otherwise usable ClientHello.
func parseCryptoFrames(payload []byte) ([]cryptoFragment, error) {
	r := bytes.NewReader(payload)
	var fragments []cryptoFragment
	for r.Len() > 0 {
		frameType, err := r.ReadByte()
		if err != nil {
			break
		}
		switch frameType {
		case 0x00: // PADDING
			continue
		case 0x01: // PING
			continue
		case 0x06: // CRYPTO
			offset, err := readUvarint(r)
			if err != nil {
				return nil, errInitialTruncated
			}
			length, err := readUvarint(r)
			if err != nil || length > uint64(r.Len()) { //nolint:gosec // r.Len() is non-negative
				return nil, errInitialTruncated
			}
			data := make([]byte, int(length)) //nolint:gosec // length bounded by r.Len() above
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, errInitialTruncated
			}
			fragments = append(fragments, cryptoFragment{offset: offset, payload: data})
		case 0x02, 0x03: // ACK, ACK_2
			if err := skipACK(r, frameType); err != nil {
				return nil, err
			}
		case 0x1c, 0x1d: // CONNECTION_CLOSE
			if _, err := readUvarint(r); err != nil { // error code
				return nil, err
			}
			if _, err := readUvarint(r); err != nil { // frame type
				return nil, err
			}
			reasonLen, err := readUvarint(r)
			if err != nil || reasonLen > uint64(r.Len()) { //nolint:gosec // r.Len() is non-negative
				return nil, errInitialTruncated
			}
			if _, err := r.Seek(int64(reasonLen), io.SeekCurrent); err != nil { //nolint:gosec // reasonLen bounded by r.Len() above
				return nil, errInitialTruncated
			}
		default:
			// Unknown frame: the payload is probably not a client Initial.
			return nil, fmt.Errorf("quic sniffer: unexpected frame type 0x%x", frameType)
		}
	}
	return fragments, nil
}

func skipACK(r *bytes.Reader, frameType byte) error {
	// ACK: Largest Acknowledged, ACK Delay, ACK Range Count, First ACK Range.
	for range 3 {
		if _, err := readUvarint(r); err != nil {
			return err
		}
	}
	ackRangeCount, err := readUvarint(r)
	if err != nil {
		return err
	}
	if _, err := readUvarint(r); err != nil { // First ACK Range
		return err
	}
	for range ackRangeCount {
		if _, err := readUvarint(r); err != nil { // Gap
			return err
		}
		if _, err := readUvarint(r); err != nil { // ACK Range Length
			return err
		}
	}
	if frameType == 0x03 { // ACK_2 adds ECT0/ECT1/ECN-CE counts
		for range 3 {
			if _, err := readUvarint(r); err != nil {
				return err
			}
		}
	}
	return nil
}
