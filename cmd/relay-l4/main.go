package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
)

func main() {
	var (
		listenAddr         = flag.String("listen", ":443", "public relay listen address")
		defaultUpstream    = flag.String("default-upstream", "", "fallback upstream when SNI route is missing")
		dialTimeout        = flag.Duration("dial-timeout", 3*time.Second, "upstream dial timeout")
		clientHelloTimeout = flag.Duration("clienthello-timeout", 2*time.Second, "TLS ClientHello inspect timeout")
		allowParseError    = flag.Bool("allow-parse-error", true, "if true, allow non-TLS/invalid ClientHello to use default route")
	)
	var routes routeFlag
	flag.Var(&routes, "route", "SNI route in form host=upstream (repeatable)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dialFn := func(ctx context.Context, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: *dialTimeout}
		return d.DialContext(ctx, "tcp", addr)
	}

	if len(routes) == 0 {
		log.Fatal("at least one -route is required")
	}

	proxy := &l4.Proxy{
		ListenAddr:         *listenAddr,
		ClientHelloTimeout: *clientHelloTimeout,
		DialByClientHello: func(ctx context.Context, info l4.ClientHelloInfo, parseErr error) (net.Conn, error) {
			if parseErr != nil {
				if !*allowParseError {
					return nil, fmt.Errorf("clienthello parse error: %w", parseErr)
				}
				if *defaultUpstream == "" {
					return nil, fmt.Errorf("clienthello parse error without default upstream: %w", parseErr)
				}
				return dialFn(ctx, *defaultUpstream)
			}

			if addr, ok := routes[normalizeHost(info.ServerName)]; ok {
				return dialFn(ctx, addr)
			}
			if *defaultUpstream != "" {
				return dialFn(ctx, *defaultUpstream)
			}
			return nil, fmt.Errorf("no route for server name %q", info.ServerName)
		},
	}

	log.Printf("l4 relay listening on %s, routes=%d, default_upstream=%q", *listenAddr, len(routes), *defaultUpstream)
	if err := proxy.Serve(ctx); err != nil {
		log.Fatalf("l4 relay exited: %v", err)
	}
}

type routeFlag map[string]string

func (f *routeFlag) String() string {
	if f == nil {
		return ""
	}
	parts := make([]string, 0, len(*f))
	for host, addr := range *f {
		parts = append(parts, host+"="+addr)
	}
	return strings.Join(parts, ",")
}

func (f *routeFlag) Set(v string) error {
	host, addr, ok := strings.Cut(v, "=")
	if !ok {
		return errors.New("route must be host=upstream")
	}
	host = normalizeHost(host)
	addr = strings.TrimSpace(addr)
	if host == "" || addr == "" {
		return errors.New("route requires non-empty host and upstream")
	}
	if *f == nil {
		*f = make(map[string]string)
	}
	(*f)[host] = addr
	return nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
