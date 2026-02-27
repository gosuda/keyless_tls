package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"keyless_tls/keyless"
)

func main() {
	var (
		listenAddr     = flag.String("listen", ":8443", "HTTPS listen address")
		certPath       = flag.String("cert", "", "public certificate PEM path")
		signerAddr     = flag.String("signer-addr", "", "HTTPS signer address (host:port or https://host:port)")
		signerName     = flag.String("signer-name", "", "TLS server name for signer")
		keyID          = flag.String("key-id", "default", "remote key identifier")
		enableMTLS     = flag.Bool("enable-mtls", false, "enable client certificate for signer mTLS")
		clientCertPath = flag.String("client-cert", "", "client cert PEM path for signer mTLS")
		clientKeyPath  = flag.String("client-key", "", "client key PEM path for signer mTLS")
		rootCAPath     = flag.String("root-ca", "", "signer root CA PEM path")
	)
	flag.Parse()

	required(*certPath, "cert")
	required(*signerAddr, "signer-addr")
	required(*signerName, "signer-name")
	required(*rootCAPath, "root-ca")
	if *enableMTLS {
		required(*clientCertPath, "client-cert")
		required(*clientKeyPath, "client-key")
	}

	certPEM := mustRead(*certPath)
	remoteSignerCfg := keyless.RemoteSignerConfig{
		Endpoint:   *signerAddr,
		ServerName: *signerName,
		KeyID:      *keyID,
		EnableMTLS: *enableMTLS,
		RootCAPEM:  mustRead(*rootCAPath),
	}
	if *enableMTLS {
		remoteSignerCfg.ClientCertPEM = mustRead(*clientCertPath)
		remoteSignerCfg.ClientKeyPEM = mustRead(*clientKeyPath)
	}

	rSigner, err := keyless.NewRemoteSigner(remoteSignerCfg, certPEM)
	if err != nil {
		log.Fatalf("create remote signer: %v", err)
	}
	defer rSigner.Close()

	tlsConf, err := keyless.NewServerTLSConfig(keyless.ServerTLSConfig{CertPEM: certPEM, Signer: rSigner})
	if err != nil {
		log.Fatalf("create tls config: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("keyless tls tunnel app\n"))
	})

	srv := &http.Server{Addr: *listenAddr, Handler: mux, TLSConfig: tlsConf}
	log.Printf("tunnel app listening on %s", *listenAddr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("http server exited: %v", err)
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
