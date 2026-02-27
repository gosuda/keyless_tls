package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os/signal"
	"syscall"
	"time"

	"keyless_tls/relay/l4"
)

func main() {
	var (
		listenAddr = flag.String("listen", ":443", "public relay listen address")
		upstream   = flag.String("upstream", "127.0.0.1:8443", "tunneling app address")
		timeout    = flag.Duration("dial-timeout", 3*time.Second, "upstream dial timeout")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	proxy := &l4.Proxy{
		ListenAddr: *listenAddr,
		DialTimeout: func(ctx context.Context) (net.Conn, error) {
			d := net.Dialer{Timeout: *timeout}
			return d.DialContext(ctx, "tcp", *upstream)
		},
	}

	log.Printf("l4 relay listening on %s, upstream %s", *listenAddr, *upstream)
	if err := proxy.Serve(ctx); err != nil {
		log.Fatalf("l4 relay exited: %v", err)
	}
}
