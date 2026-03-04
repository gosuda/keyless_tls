# keyless_tls

![keyless_tls logo](assets/keyless-tls-logo.svg)

`keyless_tls` is designed so that the tunnel application handles the TLS handshake and traffic encryption/decryption, while only the `CertificateVerify` signature is delegated to a remote signer.

- TLS engine, session keys, traffic crypto: `tunneling app`
- TLS signing (`CertificateVerify`): remote `relay signer`
- Signer transport: `HTTPS + JSON` with mandatory `mTLS`

This repository supports two usage modes:

1. Use as an SDK library (`keyless` package)
2. Run the provided binaries under `cmd/*`

## Choose your integration path first

- **I want to attach directly to my app (`http.Server`)**: SDK mode
- **I want to run it immediately and validate behavior**: Binary mode

---

## 1) Using the SDK library

### Core concept

The tunnel app keeps only the public certificate chain (`cert PEM`) and does **not** hold the private key.
The `keyless` SDK attaches a remote signer as if it were a `crypto.Signer`, so handshake signing is performed remotely.

### Public APIs

- `keyless.AttachToHTTPServer`: simplest entry point (attach directly to `http.Server`)
- `keyless.NewRemoteSigner`: create a remote signer client explicitly
- `keyless.NewServerTLSConfig`: build `tls.Config` manually

### Easiest setup (`AttachToHTTPServer`)

```go
package main

import (
    "log"
    "net/http"
    "os"

    "github.com/gosuda/keyless_tls/keyless"
)

func main() {
    certPEM := mustRead("certs/public-chain.crt")

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        _, _ = w.Write([]byte("ok\n"))
    })

    srv := &http.Server{
        Addr:    ":8443",
        Handler: mux,
    }

    remoteSigner, err := keyless.AttachToHTTPServer(srv, keyless.HTTPServerAttachConfig{
        CertPEM: certPEM,
        RemoteSigner: keyless.RemoteSignerConfig{
            Endpoint:   "127.0.0.1:9443",
            ServerName: "relay.internal",
            KeyID:      "relay-cert",
            RootCAPEM:  mustRead("certs/relay-ca.crt"),
            ClientCertPEM: mustRead("certs/tunnel-client.crt"),
            ClientKeyPEM:  mustRead("certs/tunnel-client.key"),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer remoteSigner.Close()

    log.Fatal(srv.ListenAndServeTLS("", ""))
}

func mustRead(path string) []byte {
    b, err := os.ReadFile(path)
    if err != nil {
        panic(err)
    }
    return b
}
```

### Advanced setup (`NewRemoteSigner` + `NewServerTLSConfig`)

Use this when you already have your own `tls.Config` construction flow, or when integrating with components other than `http.Server`.

```go
rSigner, err := keyless.NewRemoteSigner(remoteSignerCfg, certPEM)
if err != nil {
    // handle error
}
defer rSigner.Close()

tlsConf, err := keyless.NewServerTLSConfig(keyless.ServerTLSConfig{
    CertPEM:    certPEM,
    Signer:     rSigner,
    NextProtos: []string{"h2", "http/1.1"},
    // MinVersion: tls.VersionTLS13,
})
if err != nil {
    // handle error
}
```

### SDK: SNI metadata for relay routing (caller-controlled)

If you are implementing your own relay/proxy with this library, use the `relay/l4`
APIs to inspect ClientHello and route by SNI/ALPN while keeping all policy in caller code.

- `l4.InspectClientHello(conn, timeout)`: parse `ServerName`/`ALPNProtocols` and return a wrapped `net.Conn`
- `l4.Proxy.DialByClientHello(ctx, info, parseErr)`: caller decides route/fallback/reject policy

How this works in practice:

1) incoming TCP connection arrives
2) library reads only ClientHello metadata (no TLS termination)
3) your callback receives `info.ServerName`, `info.ALPNProtocols`, and `parseErr`
4) your code selects upstream target (or rejects)
5) relay continues raw TCP forwarding with no payload loss

Typical SDK routing policies:

- Multi-tenant host routing: `app1.example.com -> tenant A`, `app2.example.com -> tenant B`
- Protocol-aware routing: `h2` preferred upstream vs `http/1.1` upstream
- Strict security mode: reject when ClientHello parse fails
- Compatibility mode: fallback to default upstream when parse fails

Concrete policy example (easy to adapt):

```go
routes := map[string]string{
    "app1.demo.local": "127.0.0.1:9001",
    "app2.demo.local": "127.0.0.1:9002",
}

proxy := &l4.Proxy{
    ListenAddr:         ":443",
    ClientHelloTimeout: 2 * time.Second,
    DialByClientHello: func(ctx context.Context, info l4.ClientHelloInfo, parseErr error) (net.Conn, error) {
        d := net.Dialer{Timeout: 3 * time.Second}

        // 1) Decide what to do with non-TLS / invalid ClientHello
        if parseErr != nil {
            // strict mode: return nil, parseErr
            // compatibility mode: send to default route
            return d.DialContext(ctx, "tcp", "127.0.0.1:9011")
        }

        // 2) SNI host-based route
        if target, ok := routes[strings.ToLower(strings.TrimSuffix(info.ServerName, "."))]; ok {
            return d.DialContext(ctx, "tcp", target)
        }

        // 3) Optional ALPN-aware split
        for _, proto := range info.ALPNProtocols {
            if proto == "h2" {
                return d.DialContext(ctx, "tcp", "127.0.0.1:9443")
            }
        }

        // 4) Default route
        return d.DialContext(ctx, "tcp", "127.0.0.1:9011")
    },
}
```

For a complete runnable SDK-style routing sample with 10 hosts, see `examples/relay-10-targets`.

### SDK integration checklist

- Deploy only the public certificate chain (`cert PEM`) in the tunnel app
- Configure signer endpoint/server name/`KeyID`/root CA
- Provide mTLS client materials (`client cert/key`)
- Call `remoteSigner.Close()` on shutdown

---

## 2) Using binaries

`cmd/` contains production-oriented `main` packages (runnable binaries).
Example applications are separated under `examples/`.

### Command layout

- `cmd/relay-signer`: remote signer HTTPS server
- `cmd/relay-l4`: L4 TCP relay with optional SNI-based route mapping
- `examples/tunnel-http`: example tunnel HTTP server integrated with the SDK
- `examples/relay-10-targets`: one relay server routing to 10 target hosts via SNI

### SNI/ALPN routing hook for custom relays

If you are building your own relay/proxy, use `relay/l4.InspectClientHello` to read
ClientHello metadata (`ServerName`, `ALPNProtocols`) without terminating TLS.

The helper returns a wrapped `net.Conn` that replays already-read bytes, so your
relay can continue normal TCP forwarding after routing decisions.

`relay/l4.Proxy` also supports callback-based dialing through
`DialByClientHello(ctx, info, parseErr)`, so all policy decisions (fallback, reject,
default route) remain in caller code.

### Quick start with three processes

1) Run signer server

```bash
go run ./cmd/relay-signer \
  -listen :9443 \
  -key-id relay-cert \
  -tls-cert certs/relay-server.crt \
  -tls-key certs/relay-server.key \
  -sign-key certs/relay-signing.key
```

2) Run tunnel app

```bash
go run ./examples/tunnel-http \
  -listen :8443 \
  -cert certs/public-chain.crt \
  -signer-addr 127.0.0.1:9443 \
  -signer-name relay.internal \
  -key-id relay-cert \
  -client-cert certs/tunnel-client.crt \
  -client-key certs/tunnel-client.key \
  -root-ca certs/relay-ca.crt
```

3) Run L4 relay

```bash
go run ./cmd/relay-l4 \
  -listen :443 \
  -route app1.example.com=127.0.0.1:8443 \
  -default-upstream 127.0.0.1:8443
```

SNI route mode (`-route` can be repeated):

```bash
go run ./cmd/relay-l4 \
  -listen :443 \
  -route app1.example.com=127.0.0.1:8441 \
  -route app2.example.com=127.0.0.1:8442 \
  -default-upstream 127.0.0.1:8440
```

`cmd/relay-l4` does not enforce routing policy. Caller-side policy is controlled by flags,
including whether ClientHello parse failures may use the default upstream.

Useful `cmd/relay-l4` route-mode flags:

- `-route host=upstream` (repeatable): explicit SNI mapping
- `-default-upstream`: fallback target for unknown SNI
- `-allow-parse-error`: allow non-TLS/invalid ClientHello to use fallback
- `-clienthello-timeout`: maximum ClientHello inspection time

### Example app: one relay routing 10 target hosts

`examples/relay-10-targets` demonstrates a practical ingress layout:

- one public relay listener
- ten target tunnel apps
- SNI-based target selection implemented by caller code

Run the example relay:

```bash
go run ./examples/relay-10-targets \
  -listen :443 \
  -upstream-host 127.0.0.1 \
  -base-port 9001 \
  -domain demo.local \
  -default-upstream 127.0.0.1:9011
```

Generated static routes:

- `app1.demo.local -> 127.0.0.1:9001`
- `app2.demo.local -> 127.0.0.1:9002`
- `app3.demo.local -> 127.0.0.1:9003`
- `app4.demo.local -> 127.0.0.1:9004`
- `app5.demo.local -> 127.0.0.1:9005`
- `app6.demo.local -> 127.0.0.1:9006`
- `app7.demo.local -> 127.0.0.1:9007`
- `app8.demo.local -> 127.0.0.1:9008`
- `app9.demo.local -> 127.0.0.1:9009`
- `app10.demo.local -> 127.0.0.1:9010`

Policy remains caller-owned:

- known SNI: route to mapped upstream
- unknown SNI: route to `-default-upstream` when configured
- non-TLS or invalid ClientHello: route to `-default-upstream` when configured, otherwise reject

Important flags for `examples/relay-10-targets`:

- `-listen`: public relay address
- `-upstream-host`: host used for generated targets
- `-base-port`: first target port (`app1`)
- `-domain`: host suffix used for SNI matching
- `-default-upstream`: optional fallback upstream
- `-dial-timeout`: upstream dial timeout
- `-clienthello-timeout`: ClientHello inspection timeout

### mTLS is required for signer transport

Signer and tunnel clients must always be configured for mutual TLS.

```bash
go run ./cmd/relay-signer \
  -listen :9443 \
  -key-id relay-cert \
  -tls-cert certs/relay-server.crt \
  -tls-key certs/relay-server.key \
  -client-ca certs/client-ca.crt \
  -sign-key certs/relay-signing.key

go run ./examples/tunnel-http \
  -listen :8443 \
  -cert certs/public-chain.crt \
  -signer-addr 127.0.0.1:9443 \
  -signer-name relay.internal \
  -key-id relay-cert \
  -client-cert certs/tunnel-client.crt \
  -client-key certs/tunnel-client.key \
  -root-ca certs/relay-ca.crt
```

---

## Security and operations notes

- Store private keys only in `relay-signer`; never distribute them to tunnel apps
- Keep only the public certificate chain in tunnel apps
- Enforce signer mTLS and pair it with `KeyID`-scoped ACLs

### Signer API contract (`/v1/sign`)

Request:

```json
{
  "key_id": "relay-cert",
  "algorithm": "RSA_PSS_SHA256",
  "digest": "<base64>",
  "timestamp_unix": 1735628400,
  "nonce": "c4d76ad40f5d8f95a1fe4b2f1c922f4a"
}
```

Response:

```json
{
  "key_id": "relay-cert",
  "algorithm": "RSA_PSS_SHA256",
  "signature": "<base64>"
}
```

## Package structure

- `keyless`: SDK for application developers (tunnel app integration point)
- `keyless/signerclient`: remote signer client implementation
- `relay/signrpc`: signer JSON request/response types
- `relay/signer`: signing service/key store
- `relay/server`: signer HTTPS (mandatory mTLS) server launcher
- `keyless/lifecycle`: per-lease mTLS identity management (issue, renew, validate, disk-backed encrypted store)
- `relay/l4`: TCP passthrough relay + optional ClientHello (SNI/ALPN) inspection hook

## Current status

This implementation is at an early stage. Before production use, consider adding:

- replay cache
- rate limiting
- key rotation policy
- observability (OTel/metrics/log correlation)
