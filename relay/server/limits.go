package server

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultMaxConnections      = 256
	defaultMaxConnectionsPerIP = 64
	defaultReadHeaderTimeout   = 5 * time.Second
	defaultReadTimeout         = 10 * time.Second
	defaultWriteTimeout        = 15 * time.Second
	defaultIdleTimeout         = 30 * time.Second
	defaultMaxHeaderBytes      = 16 << 10
)

// Limits bounds the resources held by signer clients, including peers that
// have not completed TLS authentication. Zero fields use safe defaults.
type Limits struct {
	MaxConnections      int
	MaxConnectionsPerIP int
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxHeaderBytes      int
}

func (l Limits) withDefaults() (Limits, error) {
	for _, field := range []struct {
		name  string
		value int64
	}{
		{"MaxConnections", int64(l.MaxConnections)},
		{"MaxConnectionsPerIP", int64(l.MaxConnectionsPerIP)},
		{"ReadHeaderTimeout", int64(l.ReadHeaderTimeout)},
		{"ReadTimeout", int64(l.ReadTimeout)},
		{"WriteTimeout", int64(l.WriteTimeout)},
		{"IdleTimeout", int64(l.IdleTimeout)},
		{"MaxHeaderBytes", int64(l.MaxHeaderBytes)},
	} {
		if field.value < 0 {
			return Limits{}, fmt.Errorf("signer %s must not be negative", field.name)
		}
	}

	if l.MaxConnections == 0 {
		l.MaxConnections = defaultMaxConnections
	}
	if l.MaxConnectionsPerIP == 0 {
		l.MaxConnectionsPerIP = min(defaultMaxConnectionsPerIP, l.MaxConnections)
	}
	if l.MaxConnectionsPerIP > l.MaxConnections {
		return Limits{}, fmt.Errorf("signer MaxConnectionsPerIP (%d) exceeds MaxConnections (%d)", l.MaxConnectionsPerIP, l.MaxConnections)
	}
	if l.ReadHeaderTimeout == 0 {
		l.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if l.ReadTimeout == 0 {
		l.ReadTimeout = defaultReadTimeout
	}
	if l.WriteTimeout == 0 {
		l.WriteTimeout = defaultWriteTimeout
	}
	if l.IdleTimeout == 0 {
		l.IdleTimeout = defaultIdleTimeout
	}
	if l.MaxHeaderBytes == 0 {
		l.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	return l, nil
}

type connectionLimitListener struct {
	net.Listener
	mu          sync.Mutex
	active      int
	connections map[netip.Addr]int
	maxTotal    int
	maxPerIP    int
}

func newConnectionLimitListener(listener net.Listener, limits Limits) *connectionLimitListener {
	return &connectionLimitListener{
		Listener:    listener,
		connections: make(map[netip.Addr]int),
		maxTotal:    limits.MaxConnections,
		maxPerIP:    limits.MaxConnectionsPerIP,
	}
}

func (l *connectionLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("signer listener expected TCP peer, got %T", conn.RemoteAddr())
		}
		ip := remote.AddrPort().Addr().Unmap()

		l.mu.Lock()
		allowed := l.active < l.maxTotal && l.connections[ip] < l.maxPerIP
		if allowed {
			l.active++
			l.connections[ip]++
		}
		l.mu.Unlock()

		if !allowed {
			_ = conn.Close()
			continue
		}

		return &limitedConn{
			Conn: conn,
			release: func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				l.active--
				l.connections[ip]--
				if l.connections[ip] == 0 {
					delete(l.connections, ip)
				}
			},
		}, nil
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
