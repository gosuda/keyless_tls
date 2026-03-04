package keyless

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
)

type HTTPServerAttachConfig struct {
	CertPEM          []byte
	RemoteSigner     RemoteSignerConfig
	NextProtos       []string
	MinTLSVersion    uint16
	PreserveExisting bool

	// ClientCAPEM is PEM-encoded CA certificate(s) for verifying client certs.
	// When set, the server will request (or require) client certificates
	// depending on RequireClientCert.
	ClientCAPEM []byte
	// RequireClientCert controls the client auth policy when ClientCAPEM is
	// provided:
	//   true  → tls.RequireAndVerifyClientCert
	//   false → tls.VerifyClientCertIfGiven
	// Ignored when ClientCAPEM is empty.
	RequireClientCert bool
}

func AttachToHTTPServer(server *http.Server, cfg HTTPServerAttachConfig) (*RemoteSigner, error) {
	if server == nil {
		return nil, errors.New("http server is required")
	}

	remoteSigner, err := NewRemoteSigner(cfg.RemoteSigner, cfg.CertPEM)
	if err != nil {
		return nil, err
	}

	// Resolve client-auth settings from the convenience PEM/bool fields.
	var clientCAs *x509.CertPool
	var clientAuth tls.ClientAuthType

	if len(cfg.ClientCAPEM) > 0 {
		clientCAs = x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(cfg.ClientCAPEM) {
			_ = remoteSigner.Close()
			return nil, fmt.Errorf("failed to parse client CA PEM")
		}
		if cfg.RequireClientCert {
			clientAuth = tls.RequireAndVerifyClientCert
		} else {
			clientAuth = tls.VerifyClientCertIfGiven
		}
	}

	tlsConf, err := NewServerTLSConfig(ServerTLSConfig{
		CertPEM:    cfg.CertPEM,
		Signer:     remoteSigner,
		NextProtos: cfg.NextProtos,
		MinVersion: cfg.MinTLSVersion,
		ClientCAs:  clientCAs,
		ClientAuth: clientAuth,
	})
	if err != nil {
		_ = remoteSigner.Close()
		return nil, err
	}

	if cfg.PreserveExisting && server.TLSConfig != nil {
		server.TLSConfig.Certificates = tlsConf.Certificates
		if server.TLSConfig.MinVersion == 0 {
			server.TLSConfig.MinVersion = tlsConf.MinVersion
		}
		if len(server.TLSConfig.NextProtos) == 0 {
			server.TLSConfig.NextProtos = tlsConf.NextProtos
		}
		if tlsConf.ClientCAs != nil {
			server.TLSConfig.ClientCAs = tlsConf.ClientCAs
			server.TLSConfig.ClientAuth = tlsConf.ClientAuth
		}
	} else {
		server.TLSConfig = tlsConf
	}

	return remoteSigner, nil
}
