package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gosuda/keyless_tls/relay/l4"
)

func TestBuildTenRoutes(t *testing.T) {
	routes := buildTenRoutes("127.0.0.1", 9001, "demo.local")
	if got, want := len(routes), 10; got != want {
		t.Fatalf("route count = %d, want %d", got, want)
	}

	if got := routes["app1.demo.local"]; got != "127.0.0.1:9001" {
		t.Fatalf("app1 route = %q, want %q", got, "127.0.0.1:9001")
	}
	if got := routes["app10.demo.local"]; got != "127.0.0.1:9010" {
		t.Fatalf("app10 route = %q, want %q", got, "127.0.0.1:9010")
	}
}

func TestSelectUpstream(t *testing.T) {
	routes := map[string]string{"app1.demo.local": "127.0.0.1:9001"}

	t.Run("known sni", func(t *testing.T) {
		upstream, err := selectUpstream(routes, "", l4.ClientHelloInfo{ServerName: "App1.Demo.Local."}, nil)
		if err != nil {
			t.Fatalf("selectUpstream() error = %v", err)
		}
		if upstream != "127.0.0.1:9001" {
			t.Fatalf("upstream = %q, want %q", upstream, "127.0.0.1:9001")
		}
	})

	t.Run("unknown with default", func(t *testing.T) {
		upstream, err := selectUpstream(routes, "127.0.0.1:9999", l4.ClientHelloInfo{ServerName: "unknown.demo.local"}, nil)
		if err != nil {
			t.Fatalf("selectUpstream() error = %v", err)
		}
		if upstream != "127.0.0.1:9999" {
			t.Fatalf("upstream = %q, want %q", upstream, "127.0.0.1:9999")
		}
	})

	t.Run("parse error with default", func(t *testing.T) {
		upstream, err := selectUpstream(routes, "127.0.0.1:9999", l4.ClientHelloInfo{}, errors.New("bad hello"))
		if err != nil {
			t.Fatalf("selectUpstream() error = %v", err)
		}
		if upstream != "127.0.0.1:9999" {
			t.Fatalf("upstream = %q, want %q", upstream, "127.0.0.1:9999")
		}
	})

	t.Run("unknown without default", func(t *testing.T) {
		_, err := selectUpstream(routes, "", l4.ClientHelloInfo{ServerName: "unknown.demo.local"}, nil)
		if err == nil {
			t.Fatal("expected error for unknown route without default")
		}
	})

	t.Run("parse error without default", func(t *testing.T) {
		_, err := selectUpstream(routes, "", l4.ClientHelloInfo{}, errors.New("bad hello"))
		if err == nil {
			t.Fatal("expected error for parse error without default")
		}
	})
}

func TestNewDialByClientHello_RoutesToExpectedTarget(t *testing.T) {
	listenerA := mustTCPListener(t)
	defer listenerA.Close()
	listenerB := mustTCPListener(t)
	defer listenerB.Close()

	acceptedA := acceptOnce(listenerA)
	acceptedB := acceptOnce(listenerB)

	routes := map[string]string{"app1.demo.local": listenerA.Addr().String()}
	dial := newDialByClientHello(routes, listenerB.Addr().String(), time.Second)

	conn, err := dial(context.Background(), l4.ClientHelloInfo{ServerName: "app1.demo.local"}, nil)
	if err != nil {
		t.Fatalf("dial known route: %v", err)
	}
	_ = conn.Close()

	select {
	case <-acceptedA:
	case <-time.After(2 * time.Second):
		t.Fatal("expected known route to connect listener A")
	}

	select {
	case <-acceptedB:
		t.Fatal("known route should not connect default listener B")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNewDialByClientHello_ParseErrorUsesDefault(t *testing.T) {
	defaultListener := mustTCPListener(t)
	defer defaultListener.Close()

	accepted := acceptOnce(defaultListener)

	dial := newDialByClientHello(map[string]string{}, defaultListener.Addr().String(), time.Second)
	conn, err := dial(context.Background(), l4.ClientHelloInfo{}, errors.New("invalid hello"))
	if err != nil {
		t.Fatalf("dial default route on parse error: %v", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("expected parse error route to connect default listener")
	}
}

func mustTCPListener(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	return lis
}

func acceptOnce(lis net.Listener) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		conn, err := lis.Accept()
		if err == nil {
			_ = conn.Close()
			ch <- struct{}{}
		}
	}()
	return ch
}
