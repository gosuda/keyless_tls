package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"keyless_tls/relay/l4"
)

func main() {
	var (
		listenAddr         = flag.String("listen", ":443", "public relay listen address")
		upstreamHost       = flag.String("upstream-host", "127.0.0.1", "target upstream host")
		basePort           = flag.Int("base-port", 9001, "base port for app1..app10")
		domain             = flag.String("domain", "demo.local", "domain suffix for hostnames")
		defaultUpstream    = flag.String("default-upstream", "", "fallback upstream for unknown/non-TLS clients")
		dialTimeout        = flag.Duration("dial-timeout", 3*time.Second, "upstream dial timeout")
		clientHelloTimeout = flag.Duration("clienthello-timeout", 2*time.Second, "TLS ClientHello inspect timeout")
	)
	flag.Parse()

	routes := buildTenRoutes(*upstreamHost, *basePort, *domain)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	proxy := &l4.Proxy{
		ListenAddr:         *listenAddr,
		ClientHelloTimeout: *clientHelloTimeout,
		DialByClientHello:  newDialByClientHello(routes, *defaultUpstream, *dialTimeout),
	}

	log.Printf("relay listening on %s with %d SNI routes", *listenAddr, len(routes))
	for host, addr := range routes {
		log.Printf("route %s -> %s", host, addr)
	}

	if err := proxy.Serve(ctx); err != nil {
		log.Fatalf("relay exited: %v", err)
	}
}

func buildTenRoutes(upstreamHost string, basePort int, domain string) map[string]string {
	routes := make(map[string]string, 10)
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	for i := 1; i <= 10; i++ {
		host := fmt.Sprintf("app%d.%s", i, domain)
		addr := net.JoinHostPort(upstreamHost, strconv.Itoa(basePort+i-1))
		routes[normalizeHost(host)] = addr
	}
	return routes
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func selectUpstream(routes map[string]string, defaultUpstream string, info l4.ClientHelloInfo, parseErr error) (string, error) {
	if parseErr != nil {
		if defaultUpstream == "" {
			return "", fmt.Errorf("clienthello parse error without default upstream: %w", parseErr)
		}
		return defaultUpstream, nil
	}

	if addr, ok := routes[normalizeHost(info.ServerName)]; ok {
		return addr, nil
	}
	if defaultUpstream != "" {
		return defaultUpstream, nil
	}
	return "", fmt.Errorf("no route for server name %q", info.ServerName)
}

func newDialByClientHello(routes map[string]string, defaultUpstream string, dialTimeout time.Duration) func(context.Context, l4.ClientHelloInfo, error) (net.Conn, error) {
	return func(ctx context.Context, info l4.ClientHelloInfo, parseErr error) (net.Conn, error) {
		target, err := selectUpstream(routes, defaultUpstream, info, parseErr)
		if err != nil {
			return nil, err
		}
		d := net.Dialer{Timeout: dialTimeout}
		return d.DialContext(ctx, "tcp", target)
	}
}
