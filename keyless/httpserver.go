package keyless

import (
	"errors"
	"net/http"
)

type HTTPServerAttachConfig struct {
	CertPEM          []byte
	RemoteSigner     RemoteSignerConfig
	NextProtos       []string
	MinTLSVersion    uint16
	PreserveExisting bool
}

func AttachToHTTPServer(server *http.Server, cfg HTTPServerAttachConfig) (*RemoteSigner, error) {
	if server == nil {
		return nil, errors.New("http server is required")
	}

	remoteSigner, err := NewRemoteSigner(cfg.RemoteSigner, cfg.CertPEM)
	if err != nil {
		return nil, err
	}

	tlsConf, err := NewServerTLSConfig(ServerTLSConfig{
		CertPEM:    cfg.CertPEM,
		Signer:     remoteSigner,
		NextProtos: cfg.NextProtos,
		MinVersion: cfg.MinTLSVersion,
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
	} else {
		server.TLSConfig = tlsConf
	}

	return remoteSigner, nil
}
