package t13server

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	recordTypeChangeCipherSpec = 0x14
	recordTypeAlert            = 0x15
	recordTypeHandshake        = 0x16
	recordTypeApplicationData  = 0x17

	maxPlaintextLength  = 16384 // 2^14 bytes
	maxCiphertextLength = 16384 + 256
)

var (
	errBadRecordType   = errors.New("unexpected record type")
	errBadRecordLength = errors.New("record length exceeds maximum")
	errClosedRecord    = errors.New("tls connection closed by peer")
)

type recordCipher struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newRecordCipher(key, iv []byte) (*recordCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm cipher: %w", err)
	}
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	return &recordCipher{
		aead: gcm,
		iv:   ivCopy,
		seq:  0,
	}, nil
}

func (rc *recordCipher) computeNonce() []byte {
	nonce := make([]byte, 12)
	copy(nonce, rc.iv)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], rc.seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}
	return nonce
}

func (rc *recordCipher) encryptRecord(innerContentType byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) > maxPlaintextLength {
		return nil, errBadRecordLength
	}

	payloadWithInner := make([]byte, len(plaintext)+1)
	copy(payloadWithInner, plaintext)
	payloadWithInner[len(plaintext)] = innerContentType

	nonce := rc.computeNonce()
	rc.seq++

	ciphertextLen := len(payloadWithInner) + rc.aead.Overhead()
	header := [5]byte{
		recordTypeApplicationData,
		0x03, 0x03, // Legacy TLS 1.2 version
		byte(ciphertextLen >> 8),
		byte(ciphertextLen),
	}

	record := make([]byte, 5, 5+ciphertextLen)
	copy(record, header[:])
	record = rc.aead.Seal(record, nonce, payloadWithInner, header[:])
	return record, nil
}

func (rc *recordCipher) decryptRecord(r io.Reader) (byte, []byte, error) {
	for {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return 0, nil, err
		}

		recType := header[0]
		length := binary.BigEndian.Uint16(header[3:5])
		if length > maxCiphertextLength {
			return 0, nil, errBadRecordLength
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}

		// Middlebox compatibility dummy ChangeCipherSpec record: ignore and read next
		if recType == recordTypeChangeCipherSpec {
			continue
		}

		if recType == recordTypeAlert {
			// Alert in plaintext before encryption or fatal alert
			if len(payload) >= 2 && payload[0] == 2 { // Fatal alert
				return 0, nil, fmt.Errorf("peer sent fatal alert: %d", payload[1])
			}
			return 0, nil, errClosedRecord
		}

		if recType != recordTypeApplicationData {
			return 0, nil, fmt.Errorf("%w: got %x, want %x", errBadRecordType, recType, recordTypeApplicationData)
		}

		nonce := rc.computeNonce()
		rc.seq++

		plaintextWithInner, err := rc.aead.Open(nil, nonce, payload, header[:])
		if err != nil {
			return 0, nil, fmt.Errorf("aead decrypt: %w", err)
		}

		// Parse inner content type (strip trailing 0x00 padding)
		idx := len(plaintextWithInner) - 1
		for idx >= 0 && plaintextWithInner[idx] == 0x00 {
			idx--
		}
		if idx < 0 {
			return 0, nil, errors.New("empty record content after padding removal")
		}

		innerType := plaintextWithInner[idx]
		content := plaintextWithInner[:idx]

		if innerType == recordTypeAlert {
			if len(content) >= 2 && content[0] == 2 {
				return 0, nil, fmt.Errorf("peer sent encrypted fatal alert: %d", content[1])
			}
			return 0, nil, errClosedRecord
		}

		return innerType, content, nil
	}
}

// readPlaintextRecord reads an unencrypted TLS record (such as initial ClientHello).
func readPlaintextRecord(r io.Reader) (byte, []byte, error) {
	for {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return 0, nil, err
		}

		recType := header[0]
		length := binary.BigEndian.Uint16(header[3:5])
		if length > maxCiphertextLength {
			return 0, nil, errBadRecordLength
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}

		if recType == recordTypeChangeCipherSpec {
			continue
		}

		return recType, payload, nil
	}
}

// formatPlaintextRecord wraps plaintext into a TLS record with the given record type.
func formatPlaintextRecord(recType byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = recType
	out[1] = 0x03
	out[2] = 0x03
	binary.BigEndian.PutUint16(out[3:5], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}
