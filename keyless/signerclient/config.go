package signerclient

import "time"

type RemoteSignerConfig struct {
	Endpoint      string
	ServerName    string
	KeyID         string
	EnableMTLS    bool
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	RootCAPEM     []byte
	Timeout       time.Duration
}

func (c *RemoteSignerConfig) applyDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
}
