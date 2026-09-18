package t13server

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// hkdfLabel constructs the TLS 1.3 HkdfLabel structure according to RFC 8446 Section 7.1.
//
//	struct {
//	    uint16 length;
//	    opaque label<7..255>;
//	    opaque context<0..255>;
//	};
func hkdfLabel(length int, label string, context []byte) []byte {
	fullLabel := "tls13 " + label
	out := make([]byte, 2+1+len(fullLabel)+1+len(context))
	binary.BigEndian.PutUint16(out[0:2], uint16(length))
	out[2] = byte(len(fullLabel))
	copy(out[3:], fullLabel)
	out[3+len(fullLabel)] = byte(len(context))
	copy(out[4+len(fullLabel):], context)
	return out
}

// hkdfExpandLabel performs HKDF-Expand-Label as specified in RFC 8446 Section 7.1.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	info := hkdfLabel(length, label, context)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic("hkdf expand failed: " + err.Error())
	}
	return out
}

// deriveSecret performs Derive-Secret(Secret, Label, Transcript-Hash) as defined in RFC 8446 Section 7.1.
func deriveSecret(secret []byte, label string, transcriptHash []byte) []byte {
	return hkdfExpandLabel(secret, label, transcriptHash, sha256.Size)
}
