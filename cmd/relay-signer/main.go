package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gosuda/keyless_tls/relay/server"
	"github.com/gosuda/keyless_tls/relay/signer"
)

func main() {
	var (
		listenAddr                = flag.String("listen", ":9443", "HTTPS signer listen address")
		keyID                     = flag.String("key-id", "default", "key identifier exposed to clients")
		certPath                  = flag.String("tls-cert", "", "server TLS certificate PEM path")
		keyPath                   = flag.String("tls-key", "", "server TLS private key PEM path")
		clientCA                  = flag.String("client-ca", "", "client CA PEM path")
		signKey                   = flag.String("sign-key", "", "keyless signing private key PEM path")
		allowInsecureNoClientAuth = flag.Bool("allow-insecure-no-client-auth", false, "permit running without client certificate verification (-client-ca) (insecure/demo mode)")
		maxSigns = flag.Int("max-signs", 32, "maximum concurrent private-key operations across all keys")
		maxSignsPerKey = flag.Int("max-signs-per-key", 8, "maximum concurrent private-key operations per key")
		maxClientConcurrent = flag.Int("max-client-concurrent", 4, "maximum concurrent requests per mTLS client")
		clientRate = flag.Int("client-rate", 20, "maximum sustained sign requests per second per mTLS client")
		clientBurst = flag.Int("client-burst", 40, "maximum burst requests per mTLS client")
	)
	flag.Parse()

	required(*certPath, "tls-cert")
	required(*keyPath, "tls-key")
	required(*signKey, "sign-key")
	if *maxSigns <= 0 || *maxSignsPerKey <= 0 || *maxClientConcurrent <= 0 || *clientRate <= 0 || *clientBurst <= 0 {
		log.Fatal("all signing admission limits must be positive")
	}
	if *clientCA == "" {
		if !*allowInsecureNoClientAuth {
			log.Fatal("-client-ca is required by default (or set -allow-insecure-no-client-auth for insecure local/demo operation)")
		}
		log.Println("WARNING: -client-ca not set and -allow-insecure-no-client-auth is enabled, mTLS client verification disabled")
	}
	log.Println("WARNING: no transcript validator is configured; any client that completes TLS client auth can obtain CertificateVerify signatures. Deployments that enforce binding semantics must run a signer with a TranscriptValidator.")

	certPEM := mustRead(*certPath)
	keyPEM := mustRead(*keyPath)
	var caPEM []byte
	if *clientCA != "" {
		caPEM = mustRead(*clientCA)
	}
	signKeyPEM := mustRead(*signKey)

	signingKey, err := signer.ParsePrivateKeyPEM(signKeyPEM)
	if err != nil {
		log.Fatalf("parse signing key: %v", err)
	}

	store := signer.NewStaticKeyStore()
	if err := store.Put(*keyID, signingKey); err != nil {
		log.Fatalf("register signing key: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = server.ListenAndServe(ctx, server.Config{
		ListenAddr:    *listenAddr,
		ServerCertPEM: certPEM,
		ServerKeyPEM:  keyPEM,
		ClientCAPEM:   caPEM,
		SignerService: &signer.Service{
			Store: store,
			MaxConcurrentSigns: *maxSigns,
			MaxConcurrentSignsPerKey: *maxSignsPerKey,
		},
		MaxConcurrentRequestsPerClient: *maxClientConcurrent,
		RequestsPerClientPerSecond: *clientRate,
		ClientBurst: *clientBurst,
	})
	if err != nil {
		log.Fatalf("signer server exited: %v", err)
	}
}

func mustRead(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	return data
}

func required(v, flagName string) {
	if v != "" {
		return
	}
	log.Fatalf("-%s is required", flagName)
}
