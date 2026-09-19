package t13server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/internal/testutil"
	"github.com/gosuda/keyless_tls/keyless/t13server"
	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

const (
	exportTestLabel   = "EXPERIMENTAL mitm-probe"
	exportTestContext = "probe-context"
)

// newExporterTestListener starts one t13server over a raw TCP listener and
// returns the server certificate (for client trust pools), the raw
// listener, the wrapped listener, and a channel of accepted conns. The
// validator decides whether transcript signatures succeed, which doubles as
// the failed-handshake lever for the negative tests.
func newExporterTestListener(t *testing.T, validator signer.TranscriptValidatorFunc) ([]byte, net.Listener, *t13server.Listener, <-chan net.Conn) {
	t.Helper()

	certPEM, keyPEM, err := testutil.GenerateCert("example.com", false)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	priv, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	srv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            "test-relay-key",
		NextProtos:       []string{"proto-a"},
		TranscriptSigner: &signer.Service{Store: &mockCryptoSignerStore{priv: priv}, TranscriptValidator: validator},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = rawLis.Close() })

	lis := t13server.NewListener(rawLis, srv, nil)
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	return certPEM, rawLis, lis, accepted
}

func acceptAnyTranscript(context.Context, *signrpc.TranscriptSignRequest) error { return nil }

func rejectAllTranscripts(context.Context, *signrpc.TranscriptSignRequest) error {
	return errors.New("binding rejected by test")
}

func exportTestClientConfig(t *testing.T, certPEM []byte) *tls.Config {
	t.Helper()

	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append relay certificate to root pool")
	}
	return &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootPool,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
}

// dialExportTestClientAsync starts the client handshake on a goroutine and
// returns the outcome later. The server side runs its handshake lazily, so
// the client dial only completes once the test drives the server conn; a
// synchronous tls.Dial here would deadlock against the not-yet-handshaken
// server side. The error is delivered to the caller: tests decide whether a
// failed dial is the assertion (failed-handshake case) or a bug.
func dialExportTestClientAsync(t *testing.T, addr string, conf *tls.Config) <-chan dialedClient {
	t.Helper()

	done := make(chan dialedClient, 1)
	go func() {
		conn, err := tls.Dial("tcp", addr, conf)
		if conn != nil {
			t.Cleanup(func() { _ = conn.Close() })
		}
		done <- dialedClient{conn: conn, err: err}
	}()
	return done
}

type dialedClient struct {
	conn *tls.Conn
	err  error
}

// exportServerSideConn waits for one accepted conn and narrows it to the
// t13server conn so the handshake and exporter can be driven directly.
func exportServerSideConn(t *testing.T, accepted <-chan net.Conn) *t13server.Conn {
	t.Helper()

	select {
	case conn := <-accepted:
		srvConn, ok := conn.(*t13server.Conn)
		if !ok {
			t.Fatal("listener returned a non-t13server conn")
		}
		return srvConn
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for accepted conn")
		return nil
	}
}

func completeServerHandshake(t *testing.T, srvConn *t13server.Conn) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srvConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// TestConnExportKeyingMaterialMatchesCryptoTLSPeer covers the issue #9
// interoperability acceptance: both ends of the same TLS 1.3 session derive
// byte-identical exporter output for the same label, context, and length,
// labels and contexts are independent, and independent sessions derive
// unrelated output.
func TestConnExportKeyingMaterialMatchesCryptoTLSPeer(t *testing.T) {
	certPEM, rawLis, _, accepted := newExporterTestListener(t, acceptAnyTranscript)
	conf := exportTestClientConfig(t, certPEM)

	client1Ch := dialExportTestClientAsync(t, rawLis.Addr().String(), conf)
	srvConn1 := exportServerSideConn(t, accepted)
	completeServerHandshake(t, srvConn1)
	client1 := <-client1Ch
	if client1.err != nil {
		t.Fatalf("first client handshake: %v", client1.err)
	}

	clientState := client1.conn.ConnectionState()
	client1Export, err := clientState.ExportKeyingMaterial(exportTestLabel, []byte(exportTestContext), 32)
	if err != nil {
		t.Fatalf("client export: %v", err)
	}
	server1, err := srvConn1.ExportKeyingMaterial(exportTestLabel, []byte(exportTestContext), 32)
	if err != nil {
		t.Fatalf("server export: %v", err)
	}
	if !bytes.Equal(client1Export, server1) {
		t.Fatal("exporter output of the same session differs between crypto/tls client and t13server")
	}

	// Concurrent exports must be race-free and stable; -race exercises this.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := srvConn1.ExportKeyingMaterial(exportTestLabel, []byte(exportTestContext), 32)
			if err != nil {
				t.Errorf("concurrent export: %v", err)
				return
			}
			if !bytes.Equal(out, server1) {
				t.Error("concurrent export drifted from the first export")
			}
		}()
	}
	wg.Wait()

	// Different label and different context derive independent output.
	otherLabel, err := srvConn1.ExportKeyingMaterial("EXPERIMENTAL other-label", []byte(exportTestContext), 32)
	if err != nil {
		t.Fatalf("other-label export: %v", err)
	}
	otherContext, err := srvConn1.ExportKeyingMaterial(exportTestLabel, []byte("other-context"), 32)
	if err != nil {
		t.Fatalf("other-context export: %v", err)
	}
	if bytes.Equal(otherLabel, server1) {
		t.Fatal("different label produced identical exporter output")
	}
	if bytes.Equal(otherContext, server1) {
		t.Fatal("different context produced identical exporter output")
	}

	// A second independent session derives unrelated output on both ends.
	client2Ch := dialExportTestClientAsync(t, rawLis.Addr().String(), conf)
	srvConn2 := exportServerSideConn(t, accepted)
	completeServerHandshake(t, srvConn2)
	client2 := <-client2Ch
	if client2.err != nil {
		t.Fatalf("second client handshake: %v", client2.err)
	}

	client2State := client2.conn.ConnectionState()
	client2Export, err := client2State.ExportKeyingMaterial(exportTestLabel, []byte(exportTestContext), 32)
	if err != nil {
		t.Fatalf("second client export: %v", err)
	}
	server2, err := srvConn2.ExportKeyingMaterial(exportTestLabel, []byte(exportTestContext), 32)
	if err != nil {
		t.Fatalf("second server export: %v", err)
	}
	if bytes.Equal(server2, server1) {
		t.Fatal("two independent sessions produced identical server exporter output")
	}
	if bytes.Equal(client2Export, client1Export) {
		t.Fatal("two independent sessions produced identical client exporter output")
	}
	if !bytes.Equal(client2Export, server2) {
		t.Fatal("second session exporter output differs between ends")
	}
}

// TestConnExportKeyingMaterialFailsBeforeHandshake pins the pre-handshake
// acceptance criterion: a freshly accepted conn has no exporter secret yet,
// because Accept returns before the handshake runs.
func TestConnExportKeyingMaterialFailsBeforeHandshake(t *testing.T) {
	_, _, lis, accepted := newExporterTestListener(t, acceptAnyTranscript)

	raw, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	srvConn := exportServerSideConn(t, accepted)
	if out, err := srvConn.ExportKeyingMaterial(exportTestLabel, []byte(exportTestContext), 32); err == nil {
		t.Fatalf("export before handshake succeeded with %d bytes", len(out))
	}
}

// TestConnExportKeyingMaterialFailsAfterFailedHandshake pins the
// failed-handshake acceptance criterion: when the transcript signature is
// rejected the handshake fails on both ends, and the conn must never hand
// out exporter material for a session that never completed.
func TestConnExportKeyingMaterialFailsAfterFailedHandshake(t *testing.T) {
	certPEM, rawLis, _, accepted := newExporterTestListener(t, rejectAllTranscripts)
	conf := exportTestClientConfig(t, certPEM)

	clientCh := dialExportTestClientAsync(t, rawLis.Addr().String(), conf)
	srvConn := exportServerSideConn(t, accepted)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srvConn.HandshakeContext(ctx); err == nil {
		t.Fatal("expected server handshake to fail when the transcript signature is rejected")
	}
	// The server side does not write a TLS alert on transcript rejection, so
	// close the conn the way a relay would: the pending client handshake
	// must observe the failure instead of waiting forever.
	_ = srvConn.Close()
	if result := <-clientCh; result.err == nil {
		t.Fatal("expected client handshake to fail when the transcript signature is rejected")
	}
	if out, err := srvConn.ExportKeyingMaterial(exportTestLabel, []byte(exportTestContext), 32); err == nil {
		t.Fatalf("export after failed handshake succeeded with %d bytes", len(out))
	}
}
