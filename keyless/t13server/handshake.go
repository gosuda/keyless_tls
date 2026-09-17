package t13server

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	handshakeTypeClientHello         = 0x01
	handshakeTypeServerHello         = 0x02
	handshakeTypeEncryptedExtensions = 0x08
	handshakeTypeCertificate         = 0x0b
	handshakeTypeCertificateVerify   = 0x0f
	handshakeTypeFinished            = 0x14

	extensionServerName           = 0x0000
	extensionSupportedGroups      = 0x000a
	extensionSignatureAlgorithms  = 0x000d
	extensionALPN                 = 0x0010
	extensionSupportedVersions    = 0x002b
	extensionKeyShare             = 0x0033

	groupX25519 = 0x001d
	versionTLS13 = 0x0304

	// Supported signature schemes
	SignatureSchemeECDSAP256SHA256 = 0x0403
	SignatureSchemeRSAPSSSHA256    = 0x0804
	SignatureSchemeEd25519         = 0x0807
)

type clientHelloInfo struct {
	raw                []byte
	random             []byte
	legacySessionID    []byte
	serverName         string
	alpnProtocols      []string
	signatureSchemes   []uint16
	x25519KeyShare     []byte
	hasTLS13Version    bool
}

func parseClientHello(data []byte) (*clientHelloInfo, error) {
	if len(data) < 4 {
		return nil, errors.New("client hello too short")
	}
	if data[0] != handshakeTypeClientHello {
		return nil, fmt.Errorf("unexpected handshake type %x, want ClientHello (0x01)", data[0])
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return nil, errors.New("incomplete client hello message")
	}

	payload := data[4 : 4+msgLen]
	pos := 0

	// legacy_version (2 bytes)
	if len(payload) < pos+2 {
		return nil, errors.New("truncated client hello (version)")
	}
	pos += 2

	// random (32 bytes)
	if len(payload) < pos+32 {
		return nil, errors.New("truncated client hello (random)")
	}
	random := payload[pos : pos+32]
	pos += 32

	// legacy_session_id (1 byte len + bytes)
	if len(payload) < pos+1 {
		return nil, errors.New("truncated client hello (session id len)")
	}
	sessionIDLen := int(payload[pos])
	pos++
	if len(payload) < pos+sessionIDLen {
		return nil, errors.New("truncated client hello (session id)")
	}
	sessionID := payload[pos : pos+sessionIDLen]
	pos += sessionIDLen

	// cipher_suites (2 bytes len + bytes)
	if len(payload) < pos+2 {
		return nil, errors.New("truncated client hello (cipher suites len)")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if len(payload) < pos+cipherSuitesLen {
		return nil, errors.New("truncated client hello (cipher suites)")
	}
	pos += cipherSuitesLen

	// legacy_compression_methods (1 byte len + bytes)
	if len(payload) < pos+1 {
		return nil, errors.New("truncated client hello (compression len)")
	}
	compressionLen := int(payload[pos])
	pos++
	if len(payload) < pos+compressionLen {
		return nil, errors.New("truncated client hello (compression)")
	}
	pos += compressionLen

	// extensions
	if len(payload) < pos+2 {
		return nil, errors.New("missing extensions in client hello")
	}
	extTotalLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if len(payload) < pos+extTotalLen {
		return nil, errors.New("truncated client hello extensions")
	}

	extData := payload[pos : pos+extTotalLen]
	info := &clientHelloInfo{
		raw:             data[:4+msgLen],
		random:          random,
		legacySessionID: sessionID,
	}

	extPos := 0
	for extPos+4 <= len(extData) {
		extType := binary.BigEndian.Uint16(extData[extPos : extPos+2])
		extLen := int(binary.BigEndian.Uint16(extData[extPos+2 : extPos+4]))
		extPos += 4
		if extPos+extLen > len(extData) {
			return nil, errors.New("malformed extension length")
		}
		body := extData[extPos : extPos+extLen]
		extPos += extLen

		switch extType {
		case extensionSupportedVersions:
			// List of versions: 1 byte len + list of uint16
			if len(body) >= 1 {
				vLen := int(body[0])
				for i := 1; i+2 <= 1+vLen && i+2 <= len(body); i += 2 {
					ver := binary.BigEndian.Uint16(body[i : i+2])
					if ver == versionTLS13 {
						info.hasTLS13Version = true
					}
				}
			}
		case extensionKeyShare:
			// client_shares: 2 bytes len + list of (group uint16, len uint16, key_exchange bytes)
			if len(body) >= 2 {
				sharesLen := int(binary.BigEndian.Uint16(body[:2]))
				sPos := 2
				for sPos+4 <= 2+sharesLen && sPos+4 <= len(body) {
					grp := binary.BigEndian.Uint16(body[sPos : sPos+2])
					kLen := int(binary.BigEndian.Uint16(body[sPos+2 : sPos+4]))
					sPos += 4
					if sPos+kLen > len(body) {
						break
					}
					if grp == groupX25519 && kLen == 32 {
						info.x25519KeyShare = body[sPos : sPos+kLen]
					}
					sPos += kLen
				}
			}
		case extensionServerName:
			// server_name_list: 2 bytes len + list of (name_type byte, name_len uint16, name)
			if len(body) >= 2 {
				snLen := int(binary.BigEndian.Uint16(body[:2]))
				sPos := 2
				for sPos+3 <= 2+snLen && sPos+3 <= len(body) {
					nameType := body[sPos]
					nameLen := int(binary.BigEndian.Uint16(body[sPos+1 : sPos+3]))
					sPos += 3
					if sPos+nameLen > len(body) {
						break
					}
					if nameType == 0 { // host_name
						info.serverName = string(body[sPos : sPos+nameLen])
					}
					sPos += nameLen
				}
			}
		case extensionALPN:
			// protocol_name_list: 2 bytes len + list of (proto_len byte, proto_name)
			if len(body) >= 2 {
				alpnLen := int(binary.BigEndian.Uint16(body[:2]))
				aPos := 2
				for aPos < 2+alpnLen && aPos < len(body) {
					pLen := int(body[aPos])
					aPos++
					if aPos+pLen > len(body) {
						break
					}
					info.alpnProtocols = append(info.alpnProtocols, string(body[aPos:aPos+pLen]))
					aPos += pLen
				}
			}
		case extensionSignatureAlgorithms:
			// 2 bytes len + list of uint16
			if len(body) >= 2 {
				saLen := int(binary.BigEndian.Uint16(body[:2]))
				for i := 2; i+2 <= 2+saLen && i+2 <= len(body); i += 2 {
					scheme := binary.BigEndian.Uint16(body[i : i+2])
					info.signatureSchemes = append(info.signatureSchemes, scheme)
				}
			}
		}
	}

	return info, nil
}

func buildServerHello(sessionID []byte, serverX25519Pub []byte) ([]byte, error) {
	// Extensions:
	// 1. supported_versions (type=0x002b, len=2, 0x0304) -> 6 bytes
	// 2. key_share (type=0x0033, len=36: group=0x001d, kLen=32, key=32 bytes) -> 40 bytes
	var extBuf []byte
	// supported_versions
	extBuf = append(extBuf, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	// key_share
	extBuf = append(extBuf, 0x00, 0x33, 0x00, 0x24) // extType 0x0033, extLen 36 (0x0024)
	extBuf = append(extBuf, 0x00, 0x1d)             // group X25519
	extBuf = append(extBuf, 0x00, 0x20)             // key_exchange length 32
	extBuf = append(extBuf, serverX25519Pub...)

	bodyLen := 2 + 32 + 1 + len(sessionID) + 2 + 1 + 2 + len(extBuf)
	out := make([]byte, 4+bodyLen)
	out[0] = handshakeTypeServerHello
	out[1] = byte(bodyLen >> 16)
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen)

	pos := 4
	// legacy_version (0x0303)
	out[pos] = 0x03
	out[pos+1] = 0x03
	pos += 2

	// random (32 bytes)
	if _, err := rand.Read(out[pos : pos+32]); err != nil {
		return nil, fmt.Errorf("generate server random: %w", err)
	}
	pos += 32

	// legacy_session_id_echo
	out[pos] = byte(len(sessionID))
	pos++
	copy(out[pos:], sessionID)
	pos += len(sessionID)

	// cipher_suite = TLS_AES_128_GCM_SHA256 (0x1301)
	out[pos] = 0x13
	out[pos+1] = 0x01
	pos += 2

	// legacy_compression_method = 0
	out[pos] = 0x00
	pos++

	// extensions length
	binary.BigEndian.PutUint16(out[pos:pos+2], uint16(len(extBuf)))
	pos += 2
	copy(out[pos:], extBuf)

	return out, nil
}

func buildEncryptedExtensions(negotiatedALPN string) []byte {
	var extBuf []byte
	if negotiatedALPN != "" {
		alpnBytes := []byte(negotiatedALPN)
		protoListLen := 1 + len(alpnBytes)
		extLen := 2 + protoListLen

		extBuf = append(extBuf, 0x00, 0x10) // extension type ALPN
		extBuf = append(extBuf, byte(extLen>>8), byte(extLen))
		extBuf = append(extBuf, byte(protoListLen>>8), byte(protoListLen))
		extBuf = append(extBuf, byte(len(alpnBytes)))
		extBuf = append(extBuf, alpnBytes...)
	}

	bodyLen := 2 + len(extBuf)
	out := make([]byte, 4+bodyLen)
	out[0] = handshakeTypeEncryptedExtensions
	out[1] = byte(bodyLen >> 16)
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen)

	binary.BigEndian.PutUint16(out[4:6], uint16(len(extBuf)))
	if len(extBuf) > 0 {
		copy(out[6:], extBuf)
	}
	return out
}

func buildCertificateMessage(certDERs [][]byte) []byte {
	// certificate_request_context: 0 bytes
	var certListBuf []byte
	for _, der := range certDERs {
		certLen := len(der)
		// 3 bytes cert length
		certListBuf = append(certListBuf, byte(certLen>>16), byte(certLen>>8), byte(certLen))
		certListBuf = append(certListBuf, der...)
		// extensions length: 0 (2 bytes)
		certListBuf = append(certListBuf, 0x00, 0x00)
	}

	listLen := len(certListBuf)
	bodyLen := 1 + 3 + listLen // 1 byte context len (0) + 3 bytes list len + list
	out := make([]byte, 4+bodyLen)
	out[0] = handshakeTypeCertificate
	out[1] = byte(bodyLen >> 16)
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen)

	out[4] = 0x00 // context length 0
	out[5] = byte(listLen >> 16)
	out[6] = byte(listLen >> 8)
	out[7] = byte(listLen)
	copy(out[8:], certListBuf)

	return out
}

func buildCertificateVerify(signatureScheme uint16, signature []byte) []byte {
	bodyLen := 2 + 2 + len(signature)
	out := make([]byte, 4+bodyLen)
	out[0] = handshakeTypeCertificateVerify
	out[1] = byte(bodyLen >> 16)
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen)

	binary.BigEndian.PutUint16(out[4:6], signatureScheme)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(signature)))
	copy(out[8:], signature)
	return out
}

func buildFinishedMessage(verifyData []byte) []byte {
	bodyLen := len(verifyData)
	out := make([]byte, 4+bodyLen)
	out[0] = handshakeTypeFinished
	out[1] = byte(bodyLen >> 16)
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen)
	copy(out[4:], verifyData)
	return out
}

func parseFinished(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("finished message too short")
	}
	if data[0] != handshakeTypeFinished {
		return nil, fmt.Errorf("unexpected handshake type %x, want Finished (0x14)", data[0])
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return nil, errors.New("incomplete finished message")
	}
	return data[4 : 4+msgLen], nil
}
