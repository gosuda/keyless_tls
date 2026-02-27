package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParsePrivateKeyPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}

	if pk, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return asSigner(pk)
	}
	if pk, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return pk, nil
	}
	if pk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return pk, nil
	}

	return nil, errors.New("unsupported private key format")
}

func asSigner(pk any) (crypto.Signer, error) {
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", k)
	}
}
