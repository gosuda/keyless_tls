package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gosuda/keyless_tls/relay/signer"
	"github.com/gosuda/keyless_tls/relay/signrpc"
)

type Config struct {
	ListenAddr    string
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	ClientCAPEM   []byte
	SignerService *signer.Service
}

func ListenAndServe(ctx context.Context, cfg Config) error {
	if cfg.ListenAddr == "" {
		return errors.New("listen addr is required")
	}
	if cfg.SignerService == nil {
		return errors.New("signer service is required")
	}

	tlsConf, err := serverTLSConfig(cfg.ServerCertPEM, cfg.ServerKeyPEM, cfg.ClientCAPEM)
	if err != nil {
		return err
	}

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen signer server: %w", err)
	}
	tlsLis := tls.NewListener(lis, tlsConf)

	httpServer := &http.Server{Handler: signHandler(cfg.SignerService)}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	return httpServer.Serve(tlsLis)
}

func signHandler(service *signer.Service) http.Handler {
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

		r.Body = http.MaxBytesReader(w, r.Body, 4<<10) // 4 KiB
		defer r.Body.Close()
		var req signrpc.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json body")
			return
		}

		resp, err := service.Sign(r.Context(), &req)
		if err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, signer.ErrInvalidArgument):
				status = http.StatusBadRequest
			case errors.Is(err, signer.ErrPermissionDenied):
				status = http.StatusForbidden
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

func writeJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(signrpc.ErrorResponse{Error: message})
}

func serverTLSConfig(certPEM, keyPEM, clientCAPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse server key pair: %w", err)
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, // overridden below when client CA is provided
	}

	if len(clientCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(clientCAPEM) {
			return nil, errors.New("failed to parse client CA PEM")
		}
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConf.ClientCAs = pool
	}

	return tlsConf, nil
}
