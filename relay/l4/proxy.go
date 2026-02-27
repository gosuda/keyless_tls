package l4

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

type Proxy struct {
	ListenAddr  string
	DialTimeout func(context.Context) (net.Conn, error)
}

func (p *Proxy) Serve(ctx context.Context) error {
	if p.ListenAddr == "" {
		return fmt.Errorf("listen addr is required")
	}
	if p.DialTimeout == nil {
		return fmt.Errorf("dial function is required")
	}

	lis, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen proxy: %w", err)
	}
	defer lis.Close()

	go func() {
		<-ctx.Done()
		_ = lis.Close()
	}()

	for {
		clientConn, acceptErr := lis.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", acceptErr)
		}

		go p.handleConn(ctx, clientConn)
	}
}

func (p *Proxy) handleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	upstream, err := p.DialTimeout(ctx)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientConn)
		closeWrite(upstream)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstream)
		closeWrite(clientConn)
	}()

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
