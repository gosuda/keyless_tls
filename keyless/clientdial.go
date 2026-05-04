package keyless

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
)

type ClientDialConfig struct {
	TLSConfig        *tls.Config
	Dialer           *net.Dialer
	AllowECHFallback bool
}

func DialClientTLS(ctx context.Context, network, addr string, cfg ClientDialConfig) (*tls.Conn, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("tls config is required")
	}

	conn, err := dialClientTLS(ctx, network, addr, cfg)
	if err == nil {
		return conn, nil
	}
	if !shouldFallbackFromECH(err, cfg.TLSConfig, cfg.AllowECHFallback) {
		return nil, err
	}

	fallbackCfg := cfg
	fallbackCfg.TLSConfig = cloneWithoutECH(cfg.TLSConfig)
	return dialClientTLS(ctx, network, addr, fallbackCfg)
}

func dialClientTLS(ctx context.Context, network, addr string, cfg ClientDialConfig) (*tls.Conn, error) {
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, cfg.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func shouldFallbackFromECH(err error, tlsConf *tls.Config, allowFallback bool) bool {
	if !allowFallback || tlsConf == nil || len(tlsConf.EncryptedClientHelloConfigList) == 0 {
		return false
	}

	var echErr *tls.ECHRejectionError
	return errors.As(err, &echErr)
}

func cloneWithoutECH(tlsConf *tls.Config) *tls.Config {
	clone := tlsConf.Clone()
	clone.EncryptedClientHelloConfigList = nil
	clone.EncryptedClientHelloRejectionVerify = nil
	return clone
}
