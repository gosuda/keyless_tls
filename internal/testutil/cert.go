// Package testutil provides shared helpers for tests across the module.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// GenerateCert creates a self-signed ECDSA P-256 certificate and private key
// in PEM format. The certificate's Subject CN and DNSNames are set to cn.
// If isCA is true, the certificate is marked as a CA with KeyUsageCertSign
// in addition to KeyUsageDigitalSignature. Validity spans from 1 minute ago
// to 1 hour from now, with the serial derived from time.Now().UnixNano().
func GenerateCert(cn string, isCA bool) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              []string{cn},
	}
	if isCA {
		tpl.IsCA = true
		tpl.KeyUsage |= x509.KeyUsageCertSign
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
