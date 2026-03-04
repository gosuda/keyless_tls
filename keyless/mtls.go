package keyless

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// NewClientTLSConfig builds a client-side *tls.Config with optional mTLS.
//
// All parameters are optional:
//   - clientCertPEM/clientKeyPEM: if both provided, presents a client certificate. Partial material errors.
//   - rootCAPEM: if provided, pins the server CA. Otherwise uses the system cert pool.
//   - serverName: if non-empty, sets the TLS ServerName for SNI.
func NewClientTLSConfig(clientCertPEM, clientKeyPEM, rootCAPEM []byte, serverName string) (*tls.Config, error) {
	hasCert := len(clientCertPEM) > 0
	hasKey := len(clientKeyPEM) > 0
	if hasCert != hasKey {
		return nil, errors.New("client certificate and key must both be provided or both be empty")
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	}

	if len(rootCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(rootCAPEM) {
			return nil, errors.New("failed to parse root CA PEM")
		}
		tlsConf.RootCAs = pool
	}

	if hasCert {
		cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse client key pair: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	return tlsConf, nil
}
