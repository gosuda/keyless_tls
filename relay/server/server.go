package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"keyless_tls/relay/signer"
	"keyless_tls/relay/signrpc"
)

type Config struct {
	ListenAddr    string
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	EnableMTLS    bool
	ClientCAPEM   []byte
	SignerService *signer.Service
}

func ListenAndServe(ctx context.Context, cfg Config) error {
	if cfg.ListenAddr == "" {
		return errors.New("listen addr is required")
	}
	if cfg.SignerService == nil {
		return errors.New("signer service is required")
	}

	tlsConf, err := serverTLSConfig(cfg.ServerCertPEM, cfg.ServerKeyPEM, cfg.ClientCAPEM, cfg.EnableMTLS)
	if err != nil {
		return err
	}

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen signer server: %w", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
	signrpc.RegisterSignerServiceServer(grpcServer, cfg.SignerService)

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	return grpcServer.Serve(lis)
}

func serverTLSConfig(certPEM, keyPEM, clientCAPEM []byte, enableMTLS bool) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse server key pair: %w", err)
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}

	if !enableMTLS {
		return tlsConf, nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("failed to parse client CA PEM")
	}

	tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConf.ClientCAs = pool

	return tlsConf, nil
}
