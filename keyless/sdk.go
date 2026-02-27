package keyless

import "github.com/gosuda/keyless_tls/keyless/signerclient"

type RemoteSignerConfig = signerclient.RemoteSignerConfig
type RemoteSigner = signerclient.RemoteSigner

func NewRemoteSigner(cfg RemoteSignerConfig, certPEM []byte) (*RemoteSigner, error) {
	return signerclient.NewRemoteSigner(cfg, certPEM)
}
