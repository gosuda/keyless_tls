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
		listenAddr = flag.String("listen", ":9443", "HTTPS signer listen address")
		keyID      = flag.String("key-id", "default", "key identifier exposed to clients")
		certPath   = flag.String("tls-cert", "", "server TLS certificate PEM path")
		keyPath    = flag.String("tls-key", "", "server TLS private key PEM path")
		enableMTLS = flag.Bool("enable-mtls", false, "require and verify client certificate for signer HTTPS")
		clientCA   = flag.String("client-ca", "", "client CA PEM path")
		signKey    = flag.String("sign-key", "", "keyless signing private key PEM path")
	)
	flag.Parse()

	required(*certPath, "tls-cert")
	required(*keyPath, "tls-key")
	required(*signKey, "sign-key")
	if *enableMTLS {
		required(*clientCA, "client-ca")
	}

	certPEM := mustRead(*certPath)
	keyPEM := mustRead(*keyPath)
	var caPEM []byte
	if *enableMTLS {
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
		EnableMTLS:    *enableMTLS,
		ClientCAPEM:   caPEM,
		SignerService: &signer.Service{Store: store},
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
