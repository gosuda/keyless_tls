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
	)
	flag.Parse()

	required(*certPath, "tls-cert")
	required(*keyPath, "tls-key")
	required(*signKey, "sign-key")
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
		},
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
