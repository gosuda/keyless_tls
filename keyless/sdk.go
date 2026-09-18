package keyless

import "github.com/gosuda/keyless_tls/keyless/signerclient"

type RemoteSignerConfig = signerclient.RemoteSignerConfig
type RemoteSigner = signerclient.RemoteSigner

func NewRemoteSigner(cfg RemoteSignerConfig) (*RemoteSigner, error) {
	return signerclient.NewRemoteSigner(cfg)
}
