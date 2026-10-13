package l4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestInspectClientHelloRejectsOversizedRecordBeforeBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	header := []byte{tlsContentTypeHandshake, 3, 3, 0xff, 0xff}
	written := make(chan error, 1)
	go func() {
		_, err := client.Write(header)
		written <- err
	}()

	_, replay, err := InspectClientHello(server, time.Second)
	if !errors.Is(err, ErrTLSRecordTooLarge) {
		t.Fatalf("error = %v, want ErrTLSRecordTooLarge", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("write header: %v", err)
	}

	got := make([]byte, len(header))
	if _, err := io.ReadFull(replay, got); err != nil {
		t.Fatalf("read captured header: %v", err)
	}
	if !bytes.Equal(got, header) {
		t.Fatalf("replayed header = %x, want %x", got, header)
	}
}

func TestProxyRejectsOversizedRecordWithoutDialing(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	dialed := make(chan struct{}, 1)
	done := make(chan struct{})
	p := &Proxy{
		DialByClientHello: func(context.Context, ClientHelloInfo, error) (net.Conn, error) {
			dialed <- struct{}{}
			return nil, nil
		},
	}
	go func() {
		p.handleConn(context.Background(), server)
		close(done)
	}()

	_, err := client.Write([]byte{tlsContentTypeHandshake, 3, 3, 0xff, 0xff})
	if err != nil {
		t.Fatalf("write oversized record header: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not reject oversized record")
	}
	select {
	case <-dialed:
		t.Fatal("proxy forwarded oversized record to dial callback")
	default:
	}
}

func TestInspectClientHelloReassemblesFragmentedHandshake(t *testing.T) {
	record := captureClientHelloRecord(t, "split.example.com", []string{"h2"})
	body := record[tlsRecordHeaderLen:]
	first := testHandshakeRecord(record[:tlsRecordHeaderLen], body[:2])
	second := testHandshakeRecord(record[:tlsRecordHeaderLen], body[2:])
	payload := append(append(append([]byte(nil), first...), second...), []byte("TAIL")...)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(payload)
	}()

	info, replay, err := InspectClientHello(server, time.Second)
	if err != nil {
		t.Fatalf("InspectClientHello() error = %v", err)
	}
	if info.ServerName != "split.example.com" {
		t.Fatalf("server name = %q", info.ServerName)
	}
	if len(info.ALPNProtocols) != 1 || info.ALPNProtocols[0] != "h2" {
		t.Fatalf("ALPN = %v", info.ALPNProtocols)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(replay, got); err != nil {
		t.Fatalf("read replayed payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fragmented ClientHello replay mismatch")
	}
}

func TestInspectClientHelloRejectsOversizedHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// The handshake declares 65,536 bytes, exceeding the inspection cap.
	record := []byte{tlsContentTypeHandshake, 3, 3, 0, 4, tlsHandshakeTypeClientHi, 1, 0, 0}
	go func() {
		_, _ = client.Write(record)
	}()

	_, _, err := InspectClientHello(server, time.Second)
	if !errors.Is(err, ErrClientHelloTooLarge) {
		t.Fatalf("error = %v, want ErrClientHelloTooLarge", err)
	}
}

func testHandshakeRecord(header, body []byte) []byte {
	record := append([]byte(nil), header...)
	record[3] = byte(len(body) >> 8)
	record[4] = byte(len(body))
	return append(record, body...)
}

func TestInspectClientHelloBoundsRecordFragmentation(t *testing.T) {
	record := captureClientHelloRecord(t, "fragmented.example.com", []string{"h2"})
	body := record[tlsRecordHeaderLen:]
	if len(body) <= maxClientHelloRecords {
		t.Fatal("test ClientHello must exceed the record limit when split into single bytes")
	}
	for _, count := range []int{maxClientHelloRecords, maxClientHelloRecords + 1} {
		t.Run(fmt.Sprintf("records_%d", count), func(t *testing.T) {
			var payload []byte
			for i := 0; i < count-1; i++ {
				payload = append(payload, testHandshakeRecord(record[:tlsRecordHeaderLen], body[i:i+1])...)
			}
			payload = append(payload, testHandshakeRecord(record[:tlsRecordHeaderLen], body[count-1:])...)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() { _, _ = client.Write(payload) }()
			info, replay, err := InspectClientHello(server, time.Second)
			if count == maxClientHelloRecords {
				if err != nil || info.ServerName != "fragmented.example.com" {
					t.Fatalf("allowed fragmentation: name=%q, error=%v", info.ServerName, err)
				}
			} else if !errors.Is(err, ErrClientHelloTooLarge) {
				t.Fatalf("excessive fragmentation error = %v, want ErrClientHelloTooLarge", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(replay, got); err != nil {
				t.Fatalf("read replay: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("fragmented record replay changed the byte stream")
			}
		})
	}
}

func TestProxyAdmissionRejectsExcessConnections(t *testing.T) {
	for _, tt := range []struct {
		name             string
		maxConnections   int
		maxConnectionsIP int
	}{
		{name: "global", maxConnections: 1, maxConnectionsIP: 2},
		{name: "per-IP", maxConnections: 2, maxConnectionsIP: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			peers := make(chan net.Conn, 2)
			p := &Proxy{
				MaxConnections:      tt.maxConnections,
				MaxConnectionsPerIP: tt.maxConnectionsIP,
				IdleTimeout:         2 * time.Second,
				DialTimeout: func(context.Context) (net.Conn, error) {
					upstream, peer := net.Pipe()
					peers <- peer
					return upstream, nil
				},
			}
			addr, cancel, done := startTestProxy(t, p)
			defer cancel()

			first, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatalf("first dial: %v", err)
			}
			defer first.Close()

			var upstreamPeer net.Conn
			select {
			case upstreamPeer = <-peers:
			case <-time.After(time.Second):
				t.Fatal("first connection was not admitted")
			}
			defer upstreamPeer.Close()

			second, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatalf("second dial: %v", err)
			}
			defer second.Close()

			_ = second.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := second.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("excess connection read error = %v, want EOF", err)
			}
			select {
			case peer := <-peers:
				_ = peer.Close()
				t.Fatal("excess connection reached upstream dial")
			default:
			}

			cancel()
			assertServeStopped(t, done)
		})
	}
}

func TestProxyIdleTimeoutRefreshesWithTraffic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	upstream, peer := net.Pipe()
	defer peer.Close()

	p := &Proxy{
		IdleTimeout: 350 * time.Millisecond,
		DialTimeout: func(context.Context) (net.Conn, error) {
			return upstream, nil
		},
	}
	done := make(chan struct{})
	go func() {
		p.handleConn(context.Background(), server)
		close(done)
	}()

	for i := 0; i < 4; i++ {
		if i != 0 {
			time.Sleep(90 * time.Millisecond)
		}
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatalf("write after activity %d: %v", i, err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := io.ReadFull(peer, b[:]); err != nil || b[0] != 'x' {
			t.Fatalf("relay traffic %d = %q, err = %v", i, b, err)
		}
		select {
		case <-done:
			t.Fatal("connection expired despite recent traffic")
		default:
		}
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle connection did not expire")
	}
}

func TestProxyServeCancellationClosesActivePair(t *testing.T) {
	peers := make(chan net.Conn, 1)
	p := &Proxy{
		DialTimeout: func(context.Context) (net.Conn, error) {
			upstream, peer := net.Pipe()
			peers <- peer
			return upstream, nil
		},
	}
	addr, cancel, done := startTestProxy(t, p)
	defer cancel()

	client, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer client.Close()

	var peer net.Conn
	select {
	case peer = <-peers:
	case <-time.After(time.Second):
		t.Fatal("upstream was not connected")
	}
	defer peer.Close()

	cancel()
	assertServeStopped(t, done)

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client after Serve cancellation = %v, want EOF", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("upstream after Serve cancellation = %v, want EOF", err)
	}
}

func startTestProxy(t *testing.T, p *Proxy) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- p.serve(ctx, lis)
	}()
	t.Cleanup(func() {
		cancel()
		_ = lis.Close()
	})
	return lis.Addr().String(), cancel, done
}

func assertServeStopped(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after cancellation")
	}
}
