package keyless

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type ServerTLSConfig struct {
	CertPEM    []byte
	Signer     crypto.Signer
	NextProtos []string
	MinVersion uint16
}

func NewServerTLSConfig(cfg ServerTLSConfig) (*tls.Config, error) {
	if len(cfg.CertPEM) == 0 {
		return nil, errors.New("certificate PEM is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("remote signer is required")
	}

	cert, err := newCertificate(cfg.CertPEM, cfg.Signer)
	if err != nil {
		return nil, err
	}

	minVersion := cfg.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS13
	}

	tlsConf := &tls.Config{
		MinVersion:   minVersion,
		Certificates: []tls.Certificate{cert},
		NextProtos:   cfg.NextProtos,
	}

	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{"h2", "http/1.1"}
	}

	return tlsConf, nil
}

func newCertificate(certPEM []byte, signer crypto.Signer) (tls.Certificate, error) {
	blocks := make([][]byte, 0, 2)
	rest := certPEM
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block.Bytes)
		}
		rest = next
	}

	if len(blocks) == 0 {
		return tls.Certificate{}, errors.New("no certificate blocks found")
	}

	leaf, err := x509.ParseCertificate(blocks[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: blocks,
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}
