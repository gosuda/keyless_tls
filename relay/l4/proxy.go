package l4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultMaxConnections      = 1024
	defaultMaxConnectionsPerIP = 64
	defaultIdleTimeout         = 2 * time.Minute
)

type Proxy struct {
	ListenAddr          string
	DialTimeout         func(context.Context) (net.Conn, error)
	DialByClientHello   func(context.Context, ClientHelloInfo, error) (net.Conn, error)
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
		return fmt.Errorf("connection limits and idle timeout must be non-negative")
	}

	lis, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen proxy: %w", err)
	}
	return p.serve(ctx, lis)
}

// serve owns lis and waits for admitted connections to exit before returning.
func (p *Proxy) serve(ctx context.Context, lis net.Listener) error {
	defer lis.Close()

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopAccept := context.AfterFunc(serveCtx, func() { _ = lis.Close() })
	defer stopAccept()

	limits := newAdmissionLimits(p.MaxConnections, p.MaxConnectionsPerIP)
	var handlers sync.WaitGroup
	var serveErr error

	for {
		clientConn, err := lis.Accept()
		if err != nil {
			if ctx.Err() == nil {
				serveErr = fmt.Errorf("accept: %w", err)
			}
			break
		}
		if serveCtx.Err() != nil {
			_ = clientConn.Close()
			break
		}

		source := sourceKey(clientConn.RemoteAddr())
		if !limits.admit(source) {
			_ = clientConn.Close()
			continue
		}

		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer limits.release(source)
			p.handleConn(serveCtx, clientConn)
		}()
	}

	cancel()
	handlers.Wait()
	return serveErr
}

func (p *Proxy) handleConn(ctx context.Context, clientConn net.Conn) {
	// Close the raw connection during cancellation, even during inspection.
	defer clientConn.Close()
	stopClient := context.AfterFunc(ctx, func() { _ = clientConn.Close() })
	defer stopClient()

	if ctx.Err() != nil {
		return
	}

	forwardConn := clientConn
	var upstream net.Conn
	var err error
	if p.DialByClientHello != nil {
		var info ClientHelloInfo
		var parseErr error
		info, forwardConn, parseErr = InspectClientHello(clientConn, p.ClientHelloTimeout)
		// Resource-bound violations cannot be routed to a fallback upstream.
		if ctx.Err() != nil || errors.Is(parseErr, ErrTLSRecordTooLarge) || errors.Is(parseErr, ErrClientHelloTooLarge) {
			return
		}
		upstream, err = p.DialByClientHello(ctx, info, parseErr)
	} else {
		upstream, err = p.DialTimeout(ctx)
	}
	if err != nil {
		if upstream != nil {
			_ = upstream.Close()
		}
		return
	}
	if upstream == nil {
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	if ctx.Err() != nil {
		return
	}

	idleTimeout := p.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultIdleTimeout
	}
	pipe(forwardConn, upstream, idleTimeout)
}

type admissionLimits struct {
	mu          sync.Mutex
	maxTotal    int
	maxPerIP    int
	total       int
	perSource   map[string]int
}

func newAdmissionLimits(maxTotal, maxPerIP int) *admissionLimits {
	if maxTotal == 0 {
		maxTotal = defaultMaxConnections
	}
	if maxPerIP == 0 {
		maxPerIP = defaultMaxConnectionsPerIP
	}
	return &admissionLimits{
		maxTotal:  maxTotal,
		maxPerIP:  maxPerIP,
		perSource: make(map[string]int),
	}
}

func (l *admissionLimits) admit(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.total >= l.maxTotal || l.perSource[source] >= l.maxPerIP {
		return false
	}
	l.total++
	l.perSource[source]++
	return true
}

func (l *admissionLimits) release(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.total--
	l.perSource[source]--
	if l.perSource[source] == 0 {
		delete(l.perSource, source)
	}
}

func sourceKey(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return addr.String()
}

type idlePair struct {
	mu       sync.Mutex
	client   net.Conn
	upstream net.Conn
	timeout  time.Duration
}

// touch refreshes both directions so a one-way stream is not deemed idle.
func (p *idlePair) touch() {
	p.mu.Lock()
	defer p.mu.Unlock()

	deadline := time.Now().Add(p.timeout)
	if p.client.SetDeadline(deadline) != nil || p.upstream.SetDeadline(deadline) != nil {
		_ = p.client.Close()
		_ = p.upstream.Close()
	}
}

type trafficReader struct {
	io.Reader
	pair *idlePair
}

func (r trafficReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 {
		r.pair.touch()
	}
	return n, err
}

// writerOnly prevents io.Copy from bypassing the trafficReader via ReadFrom.
type writerOnly struct{ io.Writer }

func pipe(clientConn, upstream net.Conn, idleTimeout time.Duration) {
	activity := &idlePair{
		client:   clientConn,
		upstream: upstream,
		timeout:  idleTimeout,
	}
	activity.touch()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(writerOnly{upstream}, trafficReader{clientConn, activity})
		closeWrite(upstream)
	}()

	_, _ = io.Copy(writerOnly{clientConn}, trafficReader{upstream, activity})
	closeWrite(clientConn)
	wg.Wait()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}
