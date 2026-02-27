package l4

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
