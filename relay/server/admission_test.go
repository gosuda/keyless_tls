package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

func admissionRequestBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(signrpc.TranscriptSignRequest{
		KeyID:               "key",
		Algorithm:           signrpc.AlgorithmRSAPSSSHA256,
		Nonce:               "nonce",
		ClientHello:         []byte("ch"),
		ServerHello:         []byte("sh"),
		EncryptedExtensions: []byte("ee"),
		Certificate:         []byte("cert"),
		TimestampUnix:       time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func serveSignRequest(h http.Handler, body []byte, identity string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, signrpc.SignPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte(identity)}}}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestSignHandlerPerIdentityRateLimit(t *testing.T) {
	svc := &signer.Service{Store: staticStore{signer: mustRSAKey(t)}}
	h := signHandlerWithLimits(svc, 1, 1, 2, 1)
	body := admissionRequestBody(t)

	if got := serveSignRequest(h, body, "client-a").Code; got != http.StatusOK {
		t.Fatalf("first identity request = %d, want 200", got)
	}
	denied := serveSignRequest(h, body, "client-a")
	if denied.Code != http.StatusTooManyRequests || denied.Header().Get("Retry-After") != "1" {
		t.Fatalf("repeated identity request = %d, Retry-After = %q", denied.Code, denied.Header().Get("Retry-After"))
	}
	if got := serveSignRequest(h, body, "client-b").Code; got != http.StatusOK {
		t.Fatalf("independent identity request = %d, want 200", got)
	}
}

type httpBlockingSigner struct {
	entered chan struct{}
	release <-chan struct{}
}

func (s *httpBlockingSigner) Public() crypto.PublicKey { return nil }
func (s *httpBlockingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.entered <- struct{}{}
	<-s.release
	return []byte("signature"), nil
}

func TestSignHandlerOverloadReturns429(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	svc := &signer.Service{
		Store:                    staticStore{signer: &httpBlockingSigner{entered: entered, release: release}},
		MaxConcurrentSigns:       1,
		MaxConcurrentSignsPerKey: 1,
	}
	h := signHandlerWithLimits(svc, 100, 100, 8, 1)
	body := admissionRequestBody(t)
	first := make(chan int, 1)
	go func() {
		first <- serveSignRequest(h, body, "client-a").Code
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first sign did not start")
	}

	// Same identity is denied by HTTP admission; another identity reaches
	// the signer and is denied by its independent global signing limit.
	for _, identity := range []string{"client-a", "client-b"} {
		rr := serveSignRequest(h, body, identity)
		if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "1" {
			t.Fatalf("%s: status = %d, Retry-After = %q", identity, rr.Code, rr.Header().Get("Retry-After"))
		}
	}
	if got := svc.RejectedSignatures(); got != 1 {
		t.Fatalf("signer overload count = %d, want 1", got)
	}
	unblock()
	select {
	case got := <-first:
		if got != http.StatusOK {
			t.Fatalf("admitted request status = %d, want 200", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted HTTP request did not complete")
	}
}
