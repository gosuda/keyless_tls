package server

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	defaultReadHeaderTimeout   = 5 * time.Second
	defaultReadTimeout         = 10 * time.Second
	defaultWriteTimeout        = 15 * time.Second
	defaultIdleTimeout         = 30 * time.Second
	defaultMaxHeaderBytes      = 16 << 10
	defaultMaxConnections      = 256
	defaultMaxConnectionsPerIP = 64
)

// Limits bounds resource use even before a peer has completed mTLS.
// Zero values use conservative defaults; negative values are invalid.
type Limits struct {
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxHeaderBytes      int
	MaxConnections      int
	MaxConnectionsPerIP int
}

func (l Limits) withDefaults() (Limits, error) {
	for _, field := range []struct {
		name  string
		value int64
	}{
		{"read header timeout", int64(l.ReadHeaderTimeout)},
		{"read timeout", int64(l.ReadTimeout)},
		{"write timeout", int64(l.WriteTimeout)},
		{"idle timeout", int64(l.IdleTimeout)},
		{"max header bytes", int64(l.MaxHeaderBytes)},
		{"max connections", int64(l.MaxConnections)},
		{"max connections per IP", int64(l.MaxConnectionsPerIP)},
	} {
		if field.value < 0 {
			return Limits{}, fmt.Errorf("%s must not be negative", field.name)
		}
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
	if l.MaxConnections == 0 {
		l.MaxConnections = defaultMaxConnections
	}
	if l.MaxConnectionsPerIP == 0 {
		l.MaxConnectionsPerIP = defaultMaxConnectionsPerIP
	}
	return l, nil
}

type limitedListener struct {
	net.Listener
	maxConnections      int
	maxConnectionsPerIP int
	mu                  sync.Mutex
	active              int
	perIP               map[string]int
}

func newLimitedListener(lis net.Listener, maxConnections, maxConnectionsPerIP int) *limitedListener {
	if maxConnections <= 0 || maxConnectionsPerIP <= 0 {
		panic("connection limits must be positive")
	}
	return &limitedListener{
		Listener:            lis,
		maxConnections:      maxConnections,
		maxConnectionsPerIP: maxConnectionsPerIP,
		perIP:               make(map[string]int),
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = conn.Close()
			continue
		}
		ip := addr.IP.String()
		l.mu.Lock()
		if l.active >= l.maxConnections || l.perIP[ip] >= l.maxConnectionsPerIP {
			l.mu.Unlock()
			_ = conn.Close()
			continue
		}
		l.active++
		l.perIP[ip]++
		l.mu.Unlock()

		return &limitedConn{
			Conn: conn,
			release: func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				l.active--
				if l.perIP[ip] == 1 {
					delete(l.perIP, ip)
				} else {
					l.perIP[ip]--
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
