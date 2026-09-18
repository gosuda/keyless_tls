package t13server

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestConn_PostHandshakeHandshakeMessageRejected(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	key := make([]byte, 16)
	iv := make([]byte, 12)
	inCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	outCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}

	conn := &Conn{
		raw:               c1,
		inCipher:          inCipher,
		outCipher:         outCipher,
		handshakeComplete: true,
	}
	conn.handshakeOnce.Do(func() {}) // mark handshake done

	// Send encrypted handshake record from c2
	go func() {
		// KeyUpdate message payload: type 0x18, length 1, update_not_requested (0)
		keyUpdatePayload := []byte{0x18, 0x00, 0x00, 0x01, 0x00}
		rec, _ := outCipher.encryptRecord(recordTypeHandshake, keyUpdatePayload)
		_, _ = c2.Write(rec)
	}()

	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected error reading post-handshake handshake message, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported post-handshake handshake message type 0x18") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestConn_UnsupportedInnerTypeRejected(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	key := make([]byte, 16)
	iv := make([]byte, 12)
	inCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	outCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}

	conn := &Conn{
		raw:               c1,
		inCipher:          inCipher,
		outCipher:         outCipher,
		handshakeComplete: true,
	}
	conn.handshakeOnce.Do(func() {})

	go func() {
		rec, _ := outCipher.encryptRecord(0x99, []byte("mystery payload"))
		_, _ = c2.Write(rec)
	}()

	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected error reading unsupported inner type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported record inner type 0x99") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestConn_ZeroLengthApplicationDataRecordSkipped(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	key := make([]byte, 16)
	iv := make([]byte, 12)
	inCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	outCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}

	conn := &Conn{
		raw:               c1,
		inCipher:          inCipher,
		outCipher:         outCipher,
		handshakeComplete: true,
	}
	conn.handshakeOnce.Do(func() {})

	// Peer sends:
	// 1. Zero-length application data record
	// 2. Real application data record with payload "hello world"
	go func() {
		emptyRec, _ := outCipher.encryptRecord(recordTypeApplicationData, []byte{})
		_, _ = c2.Write(emptyRec)

		dataRec, _ := outCipher.encryptRecord(recordTypeApplicationData, []byte("hello world"))
		_, _ = c2.Write(dataRec)
	}()

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if n == 0 {
		t.Fatal("Read returned (0, nil) instead of consuming zero-length record and reading next record")
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("unexpected payload: %q", string(buf[:n]))
	}
}

func TestConn_ReadEncryptedHandshakeMessageReassemblesFragments(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	key := make([]byte, 16)
	iv := make([]byte, 12)
	writerCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	readerCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}

	conn := &Conn{raw: c1}

	body := make([]byte, 40000)
	for i := range body {
		body[i] = byte(i)
	}
	msg := append([]byte{0x0b, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	want := append([]byte(nil), msg...)

	go func() {
		defer c2.Close()
		start := 0
		for start < len(msg) {
			// Small first fragments split the 4-byte handshake header across
			// records; later fragments include a full 16 KiB record.
			n := maxPlaintextLength
			switch start {
			case 0:
				n = 2
			case 2:
				n = 3
			case 5:
				n = 4096
			}
			if start+n > len(msg) {
				n = len(msg) - start
			}
			rec, err := writerCipher.encryptRecord(recordTypeHandshake, msg[start:start+n])
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := c2.Write(rec); err != nil {
				t.Error(err)
				return
			}
			start += n
		}
	}()

	got, err := conn.readEncryptedHandshakeMessage(readerCipher)
	if err != nil {
		t.Fatalf("read encrypted handshake message: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reassembled message mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestConn_ReadEncryptedHandshakeMessageRejectsOversize(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	key := make([]byte, 16)
	iv := make([]byte, 12)
	writerCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	readerCipher, err := newRecordCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}

	conn := &Conn{raw: c1}

	go func() {
		defer c2.Close()
		// Declared body length exceeds maxHandshakeMessageLength.
		declaredLen := maxHandshakeMessageLength + 1
		oversize := []byte{0x0b, byte(declaredLen >> 16), byte(declaredLen >> 8), byte(declaredLen), 0x01, 0x02}
		rec, err := writerCipher.encryptRecord(recordTypeHandshake, oversize)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := c2.Write(rec); err != nil {
			t.Error(err)
			return
		}
	}()

	if _, err := conn.readEncryptedHandshakeMessage(readerCipher); err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed length") {
		t.Fatalf("expected max-length error, got: %v", err)
	}
}
