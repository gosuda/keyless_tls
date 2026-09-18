package t13server

import (
	"net"
)

type BindingProvider func(raw net.Conn) ([]byte, error)

type Listener struct {
	inner           net.Listener
	server          *Server
	bindingProvider BindingProvider
}

func NewListener(inner net.Listener, server *Server, bindingProvider BindingProvider) *Listener {
	return &Listener{
		inner:           inner,
		server:          server,
		bindingProvider: bindingProvider,
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		var binding []byte
		if l.bindingProvider != nil {
			b, err := l.bindingProvider(raw)
			if err != nil {
				_ = raw.Close()
				continue
			}
			binding = b
		}

		return l.server.NewConn(raw, binding), nil
	}
}

func (l *Listener) Close() error {
	return l.inner.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.inner.Addr()
}
