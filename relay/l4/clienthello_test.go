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
	if !bytes.Equal(info.HandshakeMessage, record[tlsRecordHeaderLen:]) {
		t.Fatal("handshake message does not match original ClientHello handshake bytes")
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

func TestInspectClientHello_HandshakeMessage_Fragmented(t *testing.T) {
	record := captureClientHelloRecord(t, "fragmented-span.example.com", []string{"h2", "http/1.1"})
	expectedHandshake := record[tlsRecordHeaderLen:]

	for _, parts := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("parts_%d", parts), func(t *testing.T) {
			var wire []byte
			for _, chunk := range splitBytes(expectedHandshake, parts) {
				wire = append(wire, testHandshakeRecord(record[:tlsRecordHeaderLen], chunk)...)
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

			if got, want := info.ServerName, "fragmented-span.example.com"; got != want {
				t.Fatalf("server name = %q, want %q", got, want)
			}
			if !bytes.Equal(info.HandshakeMessage, expectedHandshake) {
				t.Fatal("handshake message does not match expected assembled ClientHello bytes")
			}

			replayed := make([]byte, len(wire))
			if _, err := io.ReadFull(wrapped, replayed); err != nil {
				t.Fatalf("read replayed bytes: %v", err)
			}
			if !bytes.Equal(replayed, wire) {
				t.Fatal("replayed bytes do not match original payload")
			}
		})
	}
}

func TestInspectClientHello_HandshakeMessage_ExcludesExtraBytes(t *testing.T) {
	record := captureClientHelloRecord(t, "extra.example.com", []string{"h2"})
	expectedHandshake := record[tlsRecordHeaderLen:]

	// Extra bytes appended within the same TLS record body after declared ClientHello length
	extraBytes := []byte("TRAILING_HANDSHAKE_DATA")
	bodyWithExtra := append(append([]byte(nil), expectedHandshake...), extraBytes...)
	recordWithExtra := testHandshakeRecord(record[:tlsRecordHeaderLen], bodyWithExtra)
	wire1 := append(recordWithExtra, []byte("STREAM_TAIL")...)

	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer client.Close()
		_, _ = client.Write(wire1)
	}()

	info, wrapped, err := InspectClientHello(server, time.Second)
	if err != nil {
		t.Fatalf("InspectClientHello() error = %v", err)
	}
	defer wrapped.Close()

	if !bytes.Equal(info.HandshakeMessage, expectedHandshake) {
		t.Fatalf("HandshakeMessage included extra bytes: got %d bytes, want %d bytes", len(info.HandshakeMessage), len(expectedHandshake))
	}

	replayed := make([]byte, len(wire1))
	if _, err := io.ReadFull(wrapped, replayed); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed, wire1) {
		t.Fatal("replayed bytes mismatch")
	}

	// Extra bytes in a second record following ClientHello record
	record2 := testHandshakeRecord(record[:tlsRecordHeaderLen], []byte("ANOTHER_RECORD"))
	wire2 := append(append([]byte(nil), record...), record2...)

	client2, server2 := net.Pipe()
	defer client2.Close()

	go func() {
		defer client2.Close()
		_, _ = client2.Write(wire2)
	}()

	info2, wrapped2, err := InspectClientHello(server2, time.Second)
	if err != nil {
		t.Fatalf("InspectClientHello() error = %v", err)
	}
	defer wrapped2.Close()

	if !bytes.Equal(info2.HandshakeMessage, expectedHandshake) {
		t.Fatalf("HandshakeMessage mismatch: got %d bytes, want %d bytes", len(info2.HandshakeMessage), len(expectedHandshake))
	}

	replayed2 := make([]byte, len(wire2))
	if _, err := io.ReadFull(wrapped2, replayed2); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(replayed2, wire2) {
		t.Fatal("replayed bytes mismatch")
	}
}
