package t13server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/relay/signrpc"
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
		in: recordReader{r: c1},
		sess: &session{
			inCipher:  inCipher,
			outCipher: outCipher,
		},
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
		in: recordReader{r: c1},
		sess: &session{
			inCipher:  inCipher,
			outCipher: outCipher,
		},
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
		in: recordReader{r: c1},
		sess: &session{
			inCipher:  inCipher,
			outCipher: outCipher,
		},
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

	conn := &Conn{in: recordReader{r: c1}}

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

	conn := &Conn{in: recordReader{r: c1}}

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

type countingTranscriptSigner struct {
	calls atomic.Int32
}

func (s *countingTranscriptSigner) SignTranscript(
	_ context.Context, _ *signrpc.TranscriptSignRequest,
) (*signrpc.TranscriptSignResponse, error) {
	s.calls.Add(1)
	return nil, errors.New("signing should not be reached")
}

func TestHandshakeAdmission_RejectsBeforeTranscriptSigning(t *testing.T) {
	certPEM, _, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	remoteSigner := &countingTranscriptSigner{}
	server, err := NewServer(Config{
		CertPEM:                      certPEM,
		KeyID:                        "key",
		TranscriptSigner:             remoteSigner,
		MaxConcurrentHandshakes:      1,
		MaxHandshakesPerSource:       1,
		HandshakesPerSourcePerSecond: 1,
		HandshakeBurstPerSource:      1,
	})
	if err != nil {
		t.Fatal(err)
	}

	client1, raw1 := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer client1.Close()
	firstDone := make(chan error, 1)
	go func() {
		_, err := server.ServeConn(ctx, raw1, nil)
		firstDone <- err
	}()

	// This write completes only once the first handshake has acquired its
	// admission slot and begun reading the incomplete ClientHello.
	if err := client1.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client1.Write([]byte{0x16}); err != nil {
		t.Fatalf("first handshake never began reading: %v", err)
	}

	client2, raw2 := net.Pipe()
	defer client2.Close()
	if _, err := server.ServeConn(context.Background(), raw2, nil); !errors.Is(err, ErrHandshakeOverloaded) {
		t.Fatalf("excess handshake error = %v, want ErrHandshakeOverloaded", err)
	}
	if got := remoteSigner.calls.Load(); got != 0 {
		t.Fatalf("overloaded handshake invoked remote signer %d times", got)
	}
	if got := server.RejectedHandshakes(); got != 1 {
		t.Fatalf("overload metric = %d, want 1", got)
	}

	cancel()
	_ = client1.Close()
	select {
	case <-firstDone:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled handshake did not release its capacity")
	}
}

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestSourceIdentityUsesIPNotPort(t *testing.T) {
	first, other := net.Pipe()
	defer first.Close()
	defer other.Close()
	ip := net.ParseIP("203.0.113.10")
	c1 := &remoteAddrConn{Conn: first, remote: &net.TCPAddr{IP: ip, Port: 1234}}
	c2 := &remoteAddrConn{Conn: first, remote: &net.TCPAddr{IP: ip, Port: 5678}}
	if sourceIdentity(c1) != sourceIdentity(c2) {
		t.Fatal("ephemeral source port bypassed handshake identity")
	}
}
