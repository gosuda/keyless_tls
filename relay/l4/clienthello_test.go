package l4

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestInspectClientHello_SuccessAndReplay(t *testing.T) {
	record := captureClientHelloRecord(t, "App1.Example.Com.", []string{"h2", "http/1.1"})
	tail := []byte("TAIL")

	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write(append(record, tail...))
	}()

	info, wrapped, err := InspectClientHello(server, time.Second)
	if err != nil {
		t.Fatalf("InspectClientHello() error = %v", err)
	}
	defer wrapped.Close()

	if got, want := info.ServerName, "app1.example.com"; got != want {
		t.Fatalf("server name = %q, want %q", got, want)
	}
	if got := len(info.ALPNProtocols); got != 2 {
		t.Fatalf("ALPN protocol count = %d, want 2", got)
	}

	replayed := make([]byte, len(record)+len(tail))
	if _, err := io.ReadFull(wrapped, replayed); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed, append(record, tail...)) {
		t.Fatal("replayed bytes do not match original payload")
	}
}

func TestInspectClientHello_NonTLSRecord(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	payload := []byte("HELLO")
	go func() {
		defer client.Close()
		_, _ = client.Write(payload)
	}()

	_, wrapped, err := InspectClientHello(server, time.Second)
	if !errors.Is(err, ErrNotTLSRecord) {
		t.Fatalf("error = %v, want %v", err, ErrNotTLSRecord)
	}
	defer wrapped.Close()

	replayed := make([]byte, len(payload))
	if _, err := io.ReadFull(wrapped, replayed); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed, payload) {
		t.Fatal("replayed bytes mismatch")
	}
}

func TestInspectClientHello_ECHOffered(t *testing.T) {
	record := captureClientHelloRecord(t, "public.example.com", []string{"h2"})
	record = appendClientHelloExtension(t, record, extEncryptedClientHello, []byte{1})

	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write(record)
	}()

	info, wrapped, err := InspectClientHello(server, time.Second)
	if err != nil {
		t.Fatalf("InspectClientHello() error = %v", err)
	}
	defer wrapped.Close()

	if !info.ECHOffered {
		t.Fatal("expected ECHOffered to be true")
	}
	if got, want := info.ServerName, "public.example.com"; got != want {
		t.Fatalf("server name = %q, want %q", got, want)
	}
	if got := len(info.ALPNProtocols); got != 1 || info.ALPNProtocols[0] != "h2" {
		t.Fatalf("ALPN protocols = %v, want [h2]", info.ALPNProtocols)
	}
}

func TestProxy_DialByClientHelloReceivesParseError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	upstream, peer := net.Pipe()
	defer peer.Close()

	called := make(chan error, 1)
	p := &Proxy{
		DialByClientHello: func(_ context.Context, _ ClientHelloInfo, parseErr error) (net.Conn, error) {
			called <- parseErr
			return upstream, nil
		},
		ClientHelloTimeout: time.Second,
	}

	go p.handleConn(context.Background(), server)

	go func() {
		defer client.Close()
		_, _ = client.Write([]byte("HELLO"))
	}()

	select {
	case parseErr := <-called:
		if !errors.Is(parseErr, ErrNotTLSRecord) {
			t.Fatalf("parse error = %v, want %v", parseErr, ErrNotTLSRecord)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DialByClientHello was not called")
	}
}

func TestProxy_DialByClientHello_ReceivesSNIAndForwards(t *testing.T) {
	record := captureClientHelloRecord(t, "api.example.com", []string{"h2"})
	appPayload := []byte("PING")

	client, server := net.Pipe()
	defer client.Close()

	upstream, peer := net.Pipe()
	defer peer.Close()

	called := make(chan ClientHelloInfo, 1)
	p := &Proxy{
		DialByClientHello: func(_ context.Context, info ClientHelloInfo, parseErr error) (net.Conn, error) {
			if parseErr != nil {
				t.Fatalf("unexpected parse error: %v", parseErr)
			}
			called <- info
			return upstream, nil
		},
		ClientHelloTimeout: time.Second,
	}

	go p.handleConn(context.Background(), server)

	go func() {
		_, _ = client.Write(append(record, appPayload...))
	}()

	relayed := make([]byte, len(record)+len(appPayload))
	if _, err := io.ReadFull(peer, relayed); err != nil {
		t.Fatalf("read relayed data: %v", err)
	}
	if !bytes.Equal(relayed, append(record, appPayload...)) {
		t.Fatal("upstream did not receive full relayed payload")
	}

	select {
	case info := <-called:
		if info.ServerName != "api.example.com" {
			t.Fatalf("server name = %q, want %q", info.ServerName, "api.example.com")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DialByClientHello was not called")
	}

	go func() {
		_, _ = peer.Write([]byte("PONG"))
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read response from proxy: %v", err)
	}
	if string(buf) != "PONG" {
		t.Fatalf("response = %q, want %q", string(buf), "PONG")
	}
}

func captureClientHelloRecord(t *testing.T, serverName string, alpn []string) []byte {
	t.Helper()

	client, server := net.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)
		tlsConn := tls.Client(client, &tls.Config{
			ServerName:         serverName,
			NextProtos:         alpn,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		_ = tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("read TLS header: %v", err)
	}
	recordLen := int(header[3])<<8 | int(header[4])
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("read TLS body: %v", err)
	}
	_ = server.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TLS client goroutine did not exit")
	}

	return append(header, body...)
}

func appendClientHelloExtension(t *testing.T, record []byte, extType uint16, extData []byte) []byte {
	t.Helper()

	if len(record) < tlsRecordHeaderLen+4 {
		t.Fatal("record too short")
	}
	if record[0] != tlsContentTypeHandshake {
		t.Fatal("record is not a TLS handshake record")
	}

	recordLen := int(record[3])<<8 | int(record[4])
	if tlsRecordHeaderLen+recordLen != len(record) {
		t.Fatalf("record length = %d, want %d", recordLen, len(record)-tlsRecordHeaderLen)
	}

	body := record[tlsRecordHeaderLen:]
	if body[0] != tlsHandshakeTypeClientHi {
		t.Fatal("handshake is not ClientHello")
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+msgLen != len(body) {
		t.Fatalf("handshake length = %d, want %d", msgLen, len(body)-4)
	}

	msg := body[4:]
	i := 34
	if i >= len(msg) {
		t.Fatal("ClientHello missing session ID")
	}
	sessLen := int(msg[i])
	i++
	if i+sessLen > len(msg) {
		t.Fatal("ClientHello session ID truncated")
	}
	i += sessLen

	if i+2 > len(msg) {
		t.Fatal("ClientHello missing cipher suites")
	}
	cipherLen := int(msg[i])<<8 | int(msg[i+1])
	i += 2 + cipherLen
	if i >= len(msg) {
		t.Fatal("ClientHello missing compression methods")
	}
	compLen := int(msg[i])
	i++
	if i+compLen > len(msg) {
		t.Fatal("ClientHello compression methods truncated")
	}
	i += compLen

	if i+2 > len(msg) {
		t.Fatal("ClientHello missing extensions")
	}
	extLenOffset := tlsRecordHeaderLen + 4 + i
	extLen := int(record[extLenOffset])<<8 | int(record[extLenOffset+1])
	extEnd := extLenOffset + 2 + extLen
	if extEnd != len(record) {
		t.Fatalf("extensions end offset = %d, want %d", extEnd, len(record))
	}

	encodedExt := make([]byte, 4+len(extData))
	encodedExt[0] = byte(extType >> 8)
	encodedExt[1] = byte(extType)
	encodedExt[2] = byte(len(extData) >> 8)
	encodedExt[3] = byte(len(extData))
	copy(encodedExt[4:], extData)

	out := append([]byte(nil), record...)
	out = append(out[:extEnd], append(encodedExt, out[extEnd:]...)...)

	extLen += len(encodedExt)
	msgLen += len(encodedExt)
	recordLen += len(encodedExt)

	out[3] = byte(recordLen >> 8)
	out[4] = byte(recordLen)
	out[6] = byte(msgLen >> 16)
	out[7] = byte(msgLen >> 8)
	out[8] = byte(msgLen)
	out[extLenOffset] = byte(extLen >> 8)
	out[extLenOffset+1] = byte(extLen)

	return out
}

func wrapHandshakeRecord(handshake []byte) []byte {
	out := make([]byte, tlsRecordHeaderLen+len(handshake))
	out[0] = tlsContentTypeHandshake
	out[1] = 0x03
	out[2] = 0x01
	out[3] = byte(len(handshake) >> 8)
	out[4] = byte(len(handshake))
	copy(out[tlsRecordHeaderLen:], handshake)
	return out
}

func splitBytes(b []byte, parts int) [][]byte {
	out := make([][]byte, 0, parts)
	size := (len(b) + parts - 1) / parts
	for len(b) > 0 {
		n := size
		if n > len(b) {
			n = len(b)
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

func TestInspectClientHello_FragmentedAcrossRecords(t *testing.T) {
	record := captureClientHelloRecord(t, "split.example.com", []string{"h2", "http/1.1"})
	message := record[tlsRecordHeaderLen:]

	for _, parts := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("records_%d", parts), func(t *testing.T) {
			wire := []byte(nil)
			for _, chunk := range splitBytes(message, parts) {
				wire = append(wire, wrapHandshakeRecord(chunk)...)
			}
			tail := []byte("TAIL")
			wire = append(wire, tail...)

			client, server := net.Pipe()
			defer client.Close()

			go func() {
				defer client.Close()
				_, _ = client.Write(wire)
			}()

			info, wrapped, err := InspectClientHello(server, time.Second)
			if err != nil {
				t.Fatalf("InspectClientHello() error = %v", err)
			}
			defer wrapped.Close()

			if got, want := info.ServerName, "split.example.com"; got != want {
				t.Fatalf("server name = %q, want %q", got, want)
			}
			if got := len(info.ALPNProtocols); got != 2 {
				t.Fatalf("ALPN protocol count = %d, want 2", got)
			}
			if !bytes.Equal(info.HandshakeMessage, message) {
				t.Fatal("handshake message span does not match the original hello")
			}

			replayed := make([]byte, len(wire))
			if _, err := io.ReadFull(wrapped, replayed); err != nil {
				t.Fatalf("read replayed bytes: %v", err)
			}
			if !bytes.Equal(replayed, wire) {
				t.Fatal("replayed bytes do not match the original payload")
			}
		})
	}
}

func TestInspectClientHello_RejectsOversizedMessageLength(t *testing.T) {
	message := make([]byte, 64)
	message[0] = tlsHandshakeTypeClientHi
	message[1] = 0x10 // 1 MiB claim, far beyond maxClientHelloMessage

	wire := wrapHandshakeRecord(message)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer client.Close()
		_, _ = client.Write(wire)
	}()

	_, wrapped, err := InspectClientHello(server, time.Second)
	if !errors.Is(err, ErrNotClientHello) {
		t.Fatalf("error = %v, want %v", err, ErrNotClientHello)
	}
	defer wrapped.Close()

	replayed := make([]byte, len(wire))
	if _, err := io.ReadFull(wrapped, replayed); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed, wire) {
		t.Fatal("replayed bytes mismatch")
	}
}

func TestInspectClientHello_RejectsNonHandshakeRecordMidMessage(t *testing.T) {
	message := captureClientHelloRecord(t, "mid.example.com", nil)[tlsRecordHeaderLen:]
	wire := wrapHandshakeRecord(message[:4])
	appData := make([]byte, tlsRecordHeaderLen+8)
	appData[0] = 23 // application_data may not interrupt a handshake message
	appData[3], appData[4] = 0, 8
	wire = append(wire, appData...)
	captured := wire[:len(wire)-8]

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer client.Close()
		_, _ = client.Write(wire)
	}()

	_, wrapped, err := InspectClientHello(server, time.Second)
	if !errors.Is(err, ErrNotTLSRecord) {
		t.Fatalf("error = %v, want %v", err, ErrNotTLSRecord)
	}
	defer wrapped.Close()

	replayed := make([]byte, len(captured))
	if _, err := io.ReadFull(wrapped, replayed); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed, captured) {
		t.Fatal("replayed bytes mismatch")
	}
}

func TestInspectClientHello_ErrorsAndReplaysWhenHelloNeverCompletes(t *testing.T) {
	message := captureClientHelloRecord(t, "stall.example.com", nil)[tlsRecordHeaderLen:]
	wire := wrapHandshakeRecord(message[:4])

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer client.Close()
		_, _ = client.Write(wire)
	}()

	_, wrapped, err := InspectClientHello(server, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error for an incomplete hello")
	}
	if wrapped == nil {
		t.Fatal("expected the wrapped connection on error")
	}
	defer wrapped.Close()

	replayed := make([]byte, len(wire))
	if _, err := io.ReadFull(wrapped, replayed); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed, wire) {
		t.Fatal("replayed bytes mismatch")
	}
}

func TestClientHelloSpan(t *testing.T) {
	record := captureClientHelloRecord(t, "span.example.com", nil)
	message := record[tlsRecordHeaderLen:]

	single, err := ClientHelloSpan(record)
	if err != nil {
		t.Fatalf("ClientHelloSpan() error = %v", err)
	}
	if !bytes.Equal(single, message) {
		t.Fatal("single-record span mismatch")
	}

	multi := append(wrapHandshakeRecord(message[:7]), wrapHandshakeRecord(message[7:])...)
	split, err := ClientHelloSpan(multi)
	if err != nil {
		t.Fatalf("ClientHelloSpan() error = %v", err)
	}
	if !bytes.Equal(split, message) {
		t.Fatal("multi-record span mismatch")
	}

	if _, err := ClientHelloSpan(multi[:len(multi)-1]); err == nil {
		t.Fatal("expected error for a truncated record")
	}
	if _, err := ClientHelloSpan([]byte("HELLO")); !errors.Is(err, ErrNotTLSRecord) {
		t.Fatalf("error = %v, want %v", err, ErrNotTLSRecord)
	}
}
