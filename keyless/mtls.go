package keyless

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

func NewClientMTLSConfig(clientCertPEM, clientKeyPEM, rootCAPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client key pair: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootCAPEM) {
		return nil, errors.New("failed to parse root CA PEM")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}, nil
}
