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

	recordHeaderLen           = 5
	maxPlaintextLength        = 16384 // 2^14 bytes
	maxCiphertextLength       = 16384 + 256
	maxHandshakeMessageLength = 65536
)

var (
	errBadRecordType   = errors.New("unexpected record type")
	errBadRecordLength = errors.New("record length exceeds maximum")
	errClosedRecord    = errors.New("tls connection closed by peer")
)

// recordReader reads whole TLS records from r. Received bytes stay in buf
// until their record has arrived in full, so a Read of r that fails part way
// through a record, such as on a read deadline, loses nothing: the next call
// resumes that record. It never reads past the record it is assembling, so a
// Conn's handshake and application data share one recordReader without
// either side holding bytes that belong to the other.
type recordReader struct {
	r   io.Reader
	buf []byte // received prefix of the next record
}

// next returns the header and payload of the next record. Both alias the
// reader's buffer and are valid only until the following call.
func (rr *recordReader) next() (header, payload []byte, err error) {
	if err := rr.fill(recordHeaderLen); err != nil {
		return nil, nil, err
	}
	length := int(binary.BigEndian.Uint16(rr.buf[3:recordHeaderLen]))
	if length > maxCiphertextLength {
		return nil, nil, errBadRecordLength
	}
	if err := rr.fill(recordHeaderLen + length); err != nil {
		return nil, nil, err
	}
	record := rr.buf
	rr.buf = rr.buf[:0]
	return record[:recordHeaderLen], record[recordHeaderLen:], nil
}

// fill reads from r until the first n bytes of the record are buffered.
func (rr *recordReader) fill(n int) error {
	if cap(rr.buf) < n {
		grown := make([]byte, len(rr.buf), n)
		copy(grown, rr.buf)
		rr.buf = grown
	}
	for len(rr.buf) < n {
		m, err := rr.r.Read(rr.buf[len(rr.buf):n])
		rr.buf = rr.buf[:len(rr.buf)+m]
		if err != nil && len(rr.buf) < n {
			if err == io.EOF && len(rr.buf) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

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

func (rc *recordCipher) decryptRecord(rr *recordReader) (byte, []byte, error) {
	for {
		header, payload, err := rr.next()
		if err != nil {
			return 0, nil, err
		}

		recType := header[0]
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

		plaintextWithInner, err := rc.aead.Open(nil, nonce, payload, header)
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

// readPlaintextRecord reads an unencrypted TLS record (such as initial
// ClientHello). The payload aliases rr's buffer, as in recordReader.next.
func readPlaintextRecord(rr *recordReader) (byte, []byte, error) {
	for {
		header, payload, err := rr.next()
		if err != nil {
			return 0, nil, err
		}

		recType := header[0]
		if recType == recordTypeChangeCipherSpec {
			continue
		}

		return recType, payload, nil
	}
}

// readPlaintextHandshakeMessage reads plaintext TLS records from rr until a complete
// handshake message is accumulated across record boundaries.
// It skips middlebox compatibility ChangeCipherSpec records.
func readPlaintextHandshakeMessage(rr *recordReader) ([]byte, error) {
	var msgBuf []byte
	for {
		recType, recPayload, err := readPlaintextRecord(rr)
		if err != nil {
			return nil, err
		}
		if recType != recordTypeHandshake {
			return nil, fmt.Errorf("%w: expected handshake record (0x16), got 0x%02x", errBadRecordType, recType)
		}
		msgBuf = append(msgBuf, recPayload...)

		if len(msgBuf) >= 4 {
			msgLen := int(msgBuf[1])<<16 | int(msgBuf[2])<<8 | int(msgBuf[3])
			fullLen := 4 + msgLen
			if fullLen > maxHandshakeMessageLength {
				return nil, errors.New("handshake message exceeds maximum allowed length")
			}
			if len(msgBuf) >= fullLen {
				return msgBuf[:fullLen], nil
			}
		}
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
