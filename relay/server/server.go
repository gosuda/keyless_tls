package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/keyless_tls/internal/admission"
	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type Config struct {
	ListenAddr    string
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	ClientCAPEM   []byte
	SignerService *signer.Service
	// AllowInsecureNoClientAuth permits omitting the client CA only for local demos.
	// Never enable it on a network-reachable signer.
	AllowInsecureNoClientAuth bool
	Limits                    Limits // Zero fields use safe defaults.

	// Per-mTLS-certificate request controls; zero selects the defaults.
	MaxConcurrentRequestsPerClient int
	RequestsPerClientPerSecond     int
	ClientBurst                    int
}

const (
	defaultMaxClientConcurrency = 4
	defaultClientRate           = 20
	defaultClientBurst          = 40
)

func clientLimits(cfg Config) admission.Limits {
	concurrent := cfg.MaxConcurrentRequestsPerClient
	if concurrent == 0 {
		concurrent = defaultMaxClientConcurrency
	}
	rate := cfg.RequestsPerClientPerSecond
	if rate == 0 {
		rate = defaultClientRate
	}
	burst := cfg.ClientBurst
	if burst == 0 {
		burst = defaultClientBurst
	}
	return admission.Limits{
		MaxConcurrent:  max(128, concurrent),
		MaxPerIdentity: concurrent,
		MaxIdentities:  4096,
		RatePerSecond:  rate,
		Burst:          burst,
	}
}

func ListenAndServe(ctx context.Context, cfg Config) error {
	if cfg.ListenAddr == "" {
		return errors.New("listen addr is required")
	}
	if cfg.SignerService == nil {
		return errors.New("signer service is required")
	}
	if cfg.MaxConcurrentRequestsPerClient < 0 || cfg.RequestsPerClientPerSecond < 0 || cfg.ClientBurst < 0 {
		return errors.New("client admission limits must not be negative")
	}

	limits, err := cfg.Limits.withDefaults()
	if err != nil {
		return err
	}

	tlsConf, err := serverTLSConfig(cfg.ServerCertPEM, cfg.ServerKeyPEM, cfg.ClientCAPEM, cfg.AllowInsecureNoClientAuth)
	if err != nil {
		return err
	}

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen signer server: %w", err)
	}
	return serve(ctx, lis, tlsConf, signHandlerWithLimits(cfg.SignerService, clientLimits(cfg)), limits)
}

func serve(ctx context.Context, lis net.Listener, tlsConf *tls.Config, handler http.Handler, limits Limits) error {
	// Limit raw sockets before clients can complete TLS authentication.
	tlsLis := tls.NewListener(newConnectionLimitListener(lis, limits), tlsConf)
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: limits.ReadHeaderTimeout, // Also bounds the TLS handshake.
		ReadTimeout:       limits.ReadTimeout,
		WriteTimeout:      limits.WriteTimeout,
		IdleTimeout:       limits.IdleTimeout,
		MaxHeaderBytes:    limits.MaxHeaderBytes,
	}

	stopShutdown := context.AfterFunc(ctx, func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	})
	defer stopShutdown()

	return httpServer.Serve(tlsLis)
}

func signHandler(service *signer.Service) http.Handler {
	return signHandlerWithLimits(service, clientLimits(Config{}))
}

func signHandlerWithLimits(service *signer.Service, limits admission.Limits) http.Handler {
	clients := admission.New(limits)
	mux := http.NewServeMux()
	mux.HandleFunc(signrpc.SignPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			writeJSONError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return
		}

		identity := clientIdentity(r)
		if !clients.TryAcquire(identity) {
			w.Header().Set("Retry-After", "1")
			writeJSONError(w, http.StatusTooManyRequests, "client signing rate or concurrency limit exceeded")
			return
		}
		defer clients.Release(identity)

		r.Body = http.MaxBytesReader(w, r.Body, 512<<10) // 512 KiB for full cert chains and handshake fragments
		defer r.Body.Close()
		var req signrpc.TranscriptSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json body")
			return
		}

		resp, err := service.SignTranscript(r.Context(), &req)
		if err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, signer.ErrInvalidArgument):
				status = http.StatusBadRequest
			case errors.Is(err, signer.ErrPermissionDenied):
				status = http.StatusForbidden
			case errors.Is(err, signer.ErrOverloaded):
				status = http.StatusTooManyRequests
				w.Header().Set("Retry-After", "1")
			}
			writeJSONError(w, status, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to encode response")
			return
		}
	})

	return mux
}

// Identify authenticated clients by certificate, not an attacker-controlled HTTP
// header. In explicit no-mTLS/demo mode, apply the same policy per source IP.
func clientIdentity(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		return "cert:" + hex.EncodeToString(sum[:])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return "ip:" + host
	}
	return "ip:" + r.RemoteAddr
}

func writeJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: message})
}

func serverTLSConfig(certPEM, keyPEM, clientCAPEM []byte, allowInsecureNoClientAuth bool) (*tls.Config, error) {
	if len(clientCAPEM) == 0 && !allowInsecureNoClientAuth {
		return nil, errors.New("client CA PEM is required (set AllowInsecureNoClientAuth only for local demos)")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse server key pair: %w", err)
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	if len(clientCAPEM) == 0 {
		tlsConf.ClientAuth = tls.NoClientCert
		return tlsConf, nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("failed to parse client CA PEM")
	}
	tlsConf.ClientCAs = pool

	return tlsConf, nil
}
