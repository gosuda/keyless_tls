package signerclient

import (
	"net/http"
	"time"
)

type RemoteSignerConfig struct {
	Endpoint      string
	ServerName    string
	KeyID         string
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	RootCAPEM     []byte
	Timeout       time.Duration
	// Headers returns additional HTTP headers to attach to each /v1/sign request.
	// It is called for every Sign invocation so callers can supply rotating tokens.
	// Implementations must be safe for concurrent use.
	Headers func() http.Header
}

func (c *RemoteSignerConfig) applyDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
}
