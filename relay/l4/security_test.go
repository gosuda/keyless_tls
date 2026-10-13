package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestInspectClientHelloRejectsOversizedRecordBeforeBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	header := []byte{tlsContentTypeHandshake, 3, 3, 0x40, 0x01}
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(header)
		writeDone <- err
	}()

	_, replay, err := InspectClientHello(server, time.Second)
	if !errors.Is(err, ErrTLSRecordTooLarge) {
		t.Fatalf("InspectClientHello() error = %v, want %v", err, ErrTLSRecordTooLarge)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write TLS header: %v", err)
	}
	got := make([]byte, len(header))
	if _, err := io.ReadFull(replay, got); err != nil {
		t.Fatalf("read replayed header: %v", err)
	}
	if !bytes.Equal(got, header) {
		t.Fatalf("replayed header = %x, want %x", got, header)
	}
}

func TestInspectClientHelloRejectsOversizedHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// A valid-sized TLS record advertises a ClientHello larger than the inspection budget.
	payload := []byte{tlsHandshakeTypeClientHi, 0x01, 0x00, 0x00}
	record := tlsHandshakeRecord(payload)
	go func() {
		_, _ = client.Write(record)
	}()

	_, _, err := InspectClientHello(server, time.Second)
	if !errors.Is(err, ErrClientHelloTooLarge) {
		t.Fatalf("InspectClientHello() error = %v, want %v", err, ErrClientHelloTooLarge)
	}
}

func TestInspectClientHelloFragmentedRecordsAndReplay(t *testing.T) {
	record := captureClientHelloRecord(t, "App.Example.Com.", []string{"h2"})
	body := record[tlsRecordHeaderLen:]
	wire := append(tlsHandshakeRecord(body[:2]), tlsHandshakeRecord(body[2:11])...)
	wire = append(wire, tlsHandshakeRecord(body[11:])...)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(wire)
	}()

	info, replay, err := InspectClientHello(server, time.Second)
	if err != nil {
		t.Fatalf("InspectClientHello() error = %v", err)
	}
	if info.ServerName != "app.example.com" {
		t.Fatalf("server name = %q, want app.example.com", info.ServerName)
	}
	got := make([]byte, len(wire))
	if _, err := io.ReadFull(replay, got); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatal("replayed fragmented records do not match the wire")
	}
}

func tlsHandshakeRecord(body []byte) []byte {
	record := []byte{tlsContentTypeHandshake, 3, 3, byte(len(body) >> 8), byte(len(body))}
	return append(record, body...)
}

func TestProxyConnectionAdmission(t *testing.T) {
	tests := []struct {
		name      string
		maxGlobal int
		maxPerIP  int
	}{
		{name: "global", maxGlobal: 1, maxPerIP: 8},
		{name: "per-ip", maxGlobal: 8, maxPerIP: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstreams := make(chan net.Conn, 3)
			p := &Proxy{
				MaxConnections:      tc.maxGlobal,
				MaxConnectionsPerIP: tc.maxPerIP,
				IdleTimeout:         time.Minute,
				DialTimeout: func(context.Context) (net.Conn, error) {
					upstream, peer := net.Pipe()
					upstreams <- peer
					return upstream, nil
				},
			}
			addr, cancel, done := startTestRelay(t, p)
			defer func() {
				cancel()
				awaitRelayExit(t, done)
				for {
					select {
					case peer := <-upstreams:
						_ = peer.Close()
					default:
						return
					}
				}
			}()

			first, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial first client: %v", err)
			}
			defer first.Close()
			select {
			case <-upstreams: // An upstream proves the first connection is admitted.
			case <-time.After(time.Second):
				t.Fatal("first client was not admitted")
			}

			second, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial second client: %v", err)
			}
			defer second.Close()
			_ = second.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err := second.Read(one[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("read rejected connection = %v, want EOF", err)
			}
		})
	}
}

func TestProxyClosesIdlePipe(t *testing.T) {
	ready := make(chan net.Conn, 1)
	p := &Proxy{
		IdleTimeout: 80 * time.Millisecond,
		DialTimeout: func(context.Context) (net.Conn, error) {
			upstream, peer := net.Pipe()
			ready <- peer
			return upstream, nil
		},
	}
	addr, cancel, done := startTestRelay(t, p)
	defer func() { cancel(); awaitRelayExit(t, done) }()

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	defer client.Close()
	var peer net.Conn
	select {
	case peer = <-ready:
	case <-time.After(time.Second):
		t.Fatal("upstream was not dialed")
	}
	defer peer.Close()

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := client.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read idle client = %v, want EOF", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read idle upstream = %v, want EOF", err)
	}
}

func TestProxyRefreshesIdleDeadlineOnTraffic(t *testing.T) {
	ready := make(chan net.Conn, 1)
	p := &Proxy{
		IdleTimeout: 250 * time.Millisecond,
		DialTimeout: func(context.Context) (net.Conn, error) {
			upstream, peer := net.Pipe()
			ready <- peer
			return upstream, nil
		},
	}
	addr, cancel, done := startTestRelay(t, p)
	defer func() { cancel(); awaitRelayExit(t, done) }()

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	defer client.Close()
	var peer net.Conn
	select {
	case peer = <-ready:
	case <-time.After(time.Second):
		t.Fatal("upstream was not dialed")
	}
	defer peer.Close()

	for i := 0; i < 8; i++ {
		time.Sleep(55 * time.Millisecond)
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := client.Write([]byte{'x'}); err != nil {
			t.Fatalf("send activity %d: %v", i, err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := io.ReadFull(peer, b[:]); err != nil || b[0] != 'x' {
			t.Fatalf("receive activity %d: byte=%q error=%v", i, b[0], err)
		}
	}
}

func TestProxyCancelsActivePipes(t *testing.T) {
	ready := make(chan net.Conn, 1)
	p := &Proxy{
		IdleTimeout: time.Minute,
		DialTimeout: func(context.Context) (net.Conn, error) {
			upstream, peer := net.Pipe()
			ready <- peer
			return upstream, nil
		},
	}
	addr, cancel, done := startTestRelay(t, p)
	client, err := net.Dial("tcp", addr)
	if err != nil {
		cancel()
		t.Fatalf("dial client: %v", err)
	}
	defer client.Close()
	var peer net.Conn
	select {
	case peer = <-ready:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("upstream was not dialed")
	}
	defer peer.Close()

	cancel()
	awaitRelayExit(t, done)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := client.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read canceled client = %v, want EOF", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read canceled upstream = %v, want EOF", err)
	}
}

func TestProxyRejectsNegativeLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Proxy)
	}{
		{name: "global", edit: func(p *Proxy) { p.MaxConnections = -1 }},
		{name: "per-ip", edit: func(p *Proxy) { p.MaxConnectionsPerIP = -1 }},
		{name: "idle", edit: func(p *Proxy) { p.IdleTimeout = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{
				ListenAddr: "127.0.0.1:0",
				DialTimeout: func(context.Context) (net.Conn, error) { return nil, nil },
			}
			tc.edit(p)
			if err := p.Serve(context.Background()); err == nil {
				t.Fatal("Serve() accepted a negative resource limit")
			}
		})
	}
}

func startTestRelay(t *testing.T, p *Proxy) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.serve(ctx, listener) }()
	return listener.Addr().String(), cancel, done
}

func awaitRelayExit(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relay exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not exit after cancellation")
	}
}
