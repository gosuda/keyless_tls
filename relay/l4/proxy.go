package l4

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	DefaultMaxConnections      = 1024
	DefaultMaxConnectionsPerIP = 64
	DefaultIdleTimeout         = 5 * time.Minute
)

type Proxy struct {
	ListenAddr         string
	DialTimeout        func(context.Context) (net.Conn, error)
	DialByClientHello  func(context.Context, ClientHelloInfo, error) (net.Conn, error)
	ClientHelloTimeout  time.Duration
	MaxConnections      int
	MaxConnectionsPerIP int
	IdleTimeout         time.Duration
}

func (p *Proxy) Serve(ctx context.Context) error {
	if p.ListenAddr == "" {
		return fmt.Errorf("listen addr is required")
	}
	if p.DialTimeout == nil && p.DialByClientHello == nil {
		return fmt.Errorf("dial function is required")
	}
	if p.MaxConnections < 0 || p.MaxConnectionsPerIP < 0 || p.IdleTimeout < 0 {
		return fmt.Errorf("connection limits and idle timeout must not be negative")
	}

	lis, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen proxy: %w", err)
	}
	return p.serve(ctx, lis)
}

func (p *Proxy) serve(ctx context.Context, lis net.Listener) error {
	maxConnections := p.MaxConnections
	if maxConnections == 0 {
		maxConnections = DefaultMaxConnections
	}
	maxPerIP := p.MaxConnectionsPerIP
	if maxPerIP == 0 {
		maxPerIP = DefaultMaxConnectionsPerIP
	}
	connections := newConnectionRegistry(maxConnections, maxPerIP)

	watchDone := make(chan struct{})
	defer func() {
		close(watchDone)
		_ = lis.Close()
		connections.shutdown()
		connections.wg.Wait()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = lis.Close()
			connections.shutdown()
		case <-watchDone:
		}
	}()

	for {
		clientConn, acceptErr := lis.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", acceptErr)
		}
		if ctx.Err() != nil || !connections.acquire(clientConn) {
			_ = clientConn.Close()
			continue
		}

		go func() {
			defer connections.release(clientConn)
			p.handleConnTracked(ctx, clientConn, connections)
		}()
	}
}

func (p *Proxy) handleConn(ctx context.Context, clientConn net.Conn) {
	p.handleConnTracked(ctx, clientConn, nil)
}

func (p *Proxy) handleConnTracked(ctx context.Context, clientConn net.Conn, connections *connectionRegistry) {
	acceptedConn := clientConn
	defer acceptedConn.Close()

	var upstream net.Conn
	var err error
	if p.DialByClientHello != nil {
		var info ClientHelloInfo
		var helloErr error
		info, clientConn, helloErr = InspectClientHello(clientConn, p.ClientHelloTimeout)
		if ctx.Err() != nil {
			return
		}
		upstream, err = p.DialByClientHello(ctx, info, helloErr)
	} else {
		upstream, err = p.DialTimeout(ctx)
	}
	if err != nil {
		return
	}
	defer upstream.Close()

	if connections != nil && !connections.attach(acceptedConn, upstream) {
		return
	}

	idleTimeout := p.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout
	}
	pipe(clientConn, upstream, idleTimeout)
}

func pipe(clientConn, upstream net.Conn, idleTimeout time.Duration) {
	tracker := &idleTracker{conns: [2]net.Conn{clientConn, upstream}, timeout: idleTimeout}
	if err := tracker.refresh(); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&activityConn{Conn: upstream, tracker: tracker}, &activityConn{Conn: clientConn, tracker: tracker})
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&activityConn{Conn: clientConn, tracker: tracker}, &activityConn{Conn: upstream, tracker: tracker})
		closeWrite(clientConn)
	}()
	wg.Wait()
}

type activityConn struct {
	net.Conn
	tracker *idleTracker
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if deadlineErr := c.tracker.refresh(); deadlineErr != nil {
			return n, deadlineErr
		}
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		if deadlineErr := c.tracker.refresh(); deadlineErr != nil {
			return n, deadlineErr
		}
	}
	return n, err
}

type idleTracker struct {
	mu      sync.Mutex
	conns   [2]net.Conn
	timeout time.Duration
}

func (t *idleTracker) refresh() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	deadline := time.Now().Add(t.timeout)
	for _, conn := range t.conns {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	return nil
}

type connectionState struct {
	source   string
	upstream net.Conn
}

type connectionRegistry struct {
	mu          sync.Mutex
	wg          sync.WaitGroup
	closed      bool
	maxActive   int
	maxPerIP    int
	active      map[net.Conn]*connectionState
	sourceCount map[string]int
}

func newConnectionRegistry(maxActive, maxPerIP int) *connectionRegistry {
	return &connectionRegistry{
		maxActive:   maxActive,
		maxPerIP:    maxPerIP,
		active:      make(map[net.Conn]*connectionState),
		sourceCount: make(map[string]int),
	}
}

func (r *connectionRegistry) acquire(client net.Conn) bool {
	source := sourceIP(client.RemoteAddr())
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(r.active) >= r.maxActive || r.sourceCount[source] >= r.maxPerIP {
		return false
	}
	r.active[client] = &connectionState{source: source}
	r.sourceCount[source]++
	r.wg.Add(1)
	return true
}

func (r *connectionRegistry) attach(client, upstream net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.active[client]
	if !ok || r.closed {
		return false
	}
	state.upstream = upstream
	return true
}

func (r *connectionRegistry) release(client net.Conn) {
	r.mu.Lock()
	state := r.active[client]
	delete(r.active, client)
	r.sourceCount[state.source]--
	if r.sourceCount[state.source] == 0 {
		delete(r.sourceCount, state.source)
	}
	r.mu.Unlock()
	r.wg.Done()
}

func (r *connectionRegistry) shutdown() {
	r.mu.Lock()
	r.closed = true
	toClose := make([]net.Conn, 0, len(r.active)*2)
	for client, state := range r.active {
		toClose = append(toClose, client)
		if state.upstream != nil {
			toClose = append(toClose, state.upstream)
		}
	}
	r.mu.Unlock()
	for _, conn := range toClose {
		_ = conn.Close()
	}
}

func sourceIP(addr net.Addr) string {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcpAddr.IP); ok {
			return ip.Unmap().String()
		}
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	} else if wrapped, ok := conn.(*preloadedConn); ok {
		closeWrite(wrapped.Conn)
	}
}
