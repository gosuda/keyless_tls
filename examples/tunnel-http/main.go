package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/gosuda/keyless_tls/keyless"
	"github.com/gosuda/keyless_tls/keyless/t13server"
)

// tlsListener wraps raw TCP connections into transcript-bound keyless TLS
// connections. Each accepted connection performs its TLS 1.3 handshake with a
// remotely signed CertificateVerify, so the tunnel app never holds the
// certificate private key.
type tlsListener struct {
	net.Listener
	tlsSrv *t13server.Server
}

// connBinding is the application-specific value bound into every
// CertificateVerify transcript this example produces. A real deployment
// would derive it per connection (e.g. tenant or route identity) and a
// relay-side TranscriptValidator would authorize against it.
var connBinding = []byte("examples/tunnel-http")

func (l *tlsListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.tlsSrv.NewConn(raw, connBinding), nil
}

func main() {
	var (
		listenAddr     = flag.String("listen", ":8443", "keyless TLS listen address")
		certPath       = flag.String("cert", "", "public certificate PEM path")
		signerAddr     = flag.String("signer-addr", "", "HTTPS signer address (host:port or https://host:port)")
		signerName     = flag.String("signer-name", "", "TLS server name for signer")
		keyID          = flag.String("key-id", "default", "remote key identifier")
		clientCertPath = flag.String("client-cert", "", "client cert PEM path for signer mTLS")
		clientKeyPath  = flag.String("client-key", "", "client key PEM path for signer mTLS")
		rootCAPath     = flag.String("root-ca", "", "signer root CA PEM path")
	)
	flag.Parse()

	required(*certPath, "cert")
	required(*signerAddr, "signer-addr")
	required(*signerName, "signer-name")

	certPEM := mustRead(*certPath)
	remoteSignerCfg := keyless.RemoteSignerConfig{
		Endpoint:   *signerAddr,
		ServerName: *signerName,
		KeyID:      *keyID,
	}
	if *clientCertPath != "" {
		remoteSignerCfg.ClientCertPEM = mustRead(*clientCertPath)
	}
	if *clientKeyPath != "" {
		remoteSignerCfg.ClientKeyPEM = mustRead(*clientKeyPath)
	}
	if *rootCAPath != "" {
		remoteSignerCfg.RootCAPEM = mustRead(*rootCAPath)
	}

	rSigner, err := keyless.NewRemoteSigner(remoteSignerCfg, certPEM)
	if err != nil {
		log.Fatalf("create remote transcript signer: %v", err)
	}
	defer rSigner.Close()

	tlsSrv, err := t13server.NewServer(t13server.Config{
		CertPEM:          certPEM,
		KeyID:            *keyID,
		TranscriptSigner: rSigner,
	})
	if err != nil {
		log.Fatalf("create keyless tls server: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("keyless tls tunnel app\n"))
	})

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	srv := &http.Server{Handler: mux}
	log.Printf("tunnel app listening on %s (transcript-bound keyless TLS)", *listenAddr)
	if err := srv.Serve(&tlsListener{Listener: lis, tlsSrv: tlsSrv}); err != nil {
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
