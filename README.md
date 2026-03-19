# webd

## Objectives

- Provide a minimal Go HTTPS reverse proxy daemon for Linux hosts.
- Serve both HTTP (`:80`) and HTTPS (`:443`) with configured TLS material.
- Support zero-downtime reload of TLS cert/key and route config via `SIGHUP`.
- Split binaries by responsibility:
  - `webd` for the HTTP(S) data-plane server.
  - `webctl` for control-plane operations (`reload`, `check`, `setup`, `letsencrypt`).

## Usage

Build a local binary:

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webd ./cmd/webd

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webctl ./cmd/webctl
```

Run the proxy server:

```sh
./bin/webd
```

Reload config + TLS on a running process:

```sh
./bin/webctl reload
```

By default, `webctl reload` only signals `webd` when staged runtime outputs under `/run/webd` actually changed.
Use `./bin/webctl reload --force` (or `-f`) to send `SIGHUP` even when nothing changed.
Use `./bin/webctl reload --only-local-tls` to compare and stage only local TLS cert/key files, skipping config and handler trust-material updates.

Validate and pretty-print config:

```sh
./bin/webctl check --config /etc/webd/config.yaml
```

Host setup (root required):

```sh
sudo ./bin/webctl setup
```

Request and deploy a Let's Encrypt certificate (root required):

```sh
sudo ./bin/webctl letsencrypt --host example.com --email admin@example.com
```

## Configuration

Default config path: `/etc/webd/config.yaml`

Example (`config.example.yaml`):

```yaml
routes:
  - path: /api/
    handler: http://127.0.0.1:8080/api/v1/
    allowed_ipv4:
      - 127.0.0.1
      - 10.0.0.0/8
      - 192.0.2.10-192.0.2.50
  - path: /internal/
    handler: https://api.internal.example.com/v1/
    trusted_ca:
      name: internal-api
      cert_path: /etc/pki/ca-trust/source/anchors/internal-api.crt
  - path: /websocket/
    handler: wss://server.eu.example.com:9000/websocket/
  - path: /static/
    handler: file:///var/www/static
    browse: true
  - path: /legacy/
    redirect: https://www.example.com/new-home/
  - path: /
    handler: http://127.0.0.1:3000
```

Rules:

- `routes` must contain at least one entry.
- `path` must begin with `/` (empty is treated as `/`).
- Each route must set exactly one of `handler` or `redirect`.
- `handler` must be a valid absolute URL.
- `redirect` must be a valid absolute URL and returns `301 Moved Permanently`.
- Supported handler schemes are `http`, `https`, `ws`, `wss`, and `file`.
- For `file://` handlers, the path must be absolute and local.
- For directory paths, `webd` attempts to serve `index.html` first.
- If `browse: true` is set on a `file://` route and no `index.html` is present for a requested directory path, `webd` returns an HTML directory listing (subdirs/files, size, modtime).
- `browse` is supported only for `file://` handlers.
- `allowed_ipv4` is optional and can include IPv4 addresses, IPv4 ranges (`start-end`), and IPv4 CIDRs.
- If a request matches a route prefix with `allowed_ipv4` and the client IPv4 is not in the allow-list, `webd` returns `403 Forbidden` for that route.
- `trusted_ca` is optional and supported only for `https` and `wss` handlers.
- If `trusted_ca` is omitted for an `https` or `wss` handler, `webctl reload` probes the endpoint, verifies it against the OS trust store, and auto-stages a pinned CA bundle (issuing CA and, when present in the system trust store, its root CA) into `/run/webd`.
- `insecure` is optional and supported only for `https` and `wss` handlers.
- If `insecure: true` is set, `webctl reload` fetches the endpoint’s current leaf certificate and pins that exact certificate for the route/handler.
- `insecure: true` does not disable TLS verification; `webd` still checks hostname, certificate validity period, and exact leaf-cert match.
- `insecure` cannot be used with `trusted_ca`.
- `trusted_ca` cannot be used with `redirect` routes.
- `trusted_ca.name` may contain only letters, digits, `.`, `_`, and `-`.
- `trusted_ca.cert_path` must point to a PEM CA bundle that `webctl reload` can read.
- Longest `path` wins.

Config examples:

Simple catch-all route:

```yaml
routes:
  - path: /
    handler: http://127.0.0.1:3000
```

Specific API route plus fallback frontend:

```yaml
routes:
  - path: /api/
    handler: http://127.0.0.1:8080/api/v1/

  - path: /
    handler: http://127.0.0.1:3000
```

HTTPS handler with a pinned trusted CA bundle:

```yaml
routes:
  - path: /internal/
    handler: https://api.internal.example.com/v1/
    trusted_ca:
      name: internal-api
      cert_path: /etc/pki/ca-trust/source/anchors/internal-api.crt

  - path: /
    handler: http://127.0.0.1:3000
```

WebSocket handler over TLS:

```yaml
routes:
  - path: /websocket/
    handler: wss://server.eu.example.com:9000/websocket/

  - path: /
    handler: http://127.0.0.1:3000
```

WebSocket handler with a pinned trusted CA bundle:

```yaml
routes:
  - path: /websocket/
    handler: wss://server.eu.example.com:9000/websocket/
    trusted_ca:
      name: server-ws
      cert_path: /etc/pki/ca-trust/source/anchors/server-ws.crt

  - path: /
    handler: http://127.0.0.1:3000
```

HTTPS handler with endpoint-certificate pinning:

```yaml
routes:
  - path: /selfsigned/
    handler: https://selfsigned.internal.example.com/
    insecure: true

  - path: /
    handler: http://127.0.0.1:3000
```

Local file handler with directory browsing:

```yaml
routes:
  - path: /static/
    handler: file:///var/www/static
    browse: true

  - path: /
    handler: http://127.0.0.1:3000
```

Restrict a route to localhost and an internal subnet:

```yaml
routes:
  - path: /admin/
    handler: http://127.0.0.1:9000/
    allowed_ipv4:
      - 127.0.0.1
      - 10.0.0.0/8

  - path: /
    handler: http://127.0.0.1:3000
```

Restrict a route to explicit IPv4 addresses and a range:

```yaml
routes:
  - path: /url-sub-path/
    handler: http://127.0.0.1:9100/
    allowed_ipv4:
      - 198.51.100.10
      - 198.51.100.11
      - 198.51.100.20-198.51.100.30

  - path: /
    handler: http://127.0.0.1:3000
```

Permanent redirect route:

```yaml
routes:
  - path: /old-docs/
    redirect: https://docs.example.com/new-location/

  - path: /
    handler: http://127.0.0.1:3000
```

TLS notes:

- `--tls-cert` should contain the server certificate chain PEM bundle.
- Bundle order should be leaf cert first, then intermediates.
- `--tls-key` is the private key PEM.

## Let's Encrypt

`webctl letsencrypt` uses ACME HTTP-01 and expects `webd` to be reachable on port 80 for the requested host.

Prerequisites:

- Public DNS for `--host` must point to this machine.
- Port `80/tcp` must be reachable from the internet.
- `webd` must be running during validation.
- Run as root so `webctl` can write cert/key files and deploy runtime artifacts.

How it works:

- `webctl` stages HTTP-01 token files under `/run/webd/acme-challenge/`.
- `webd` serves `/.well-known/acme-challenge/<token>` directly from its chroot jail path `/acme-challenge/<token>`.
- After issuance, `webctl` writes the certificate chain PEM and key to local filesystem paths.
- By default, `webctl` immediately deploys the new cert/key to `webd` through the existing reload workflow.

Examples:

```sh
# Request for local hostname (if publicly resolvable), then deploy
sudo ./bin/webctl letsencrypt --email admin@example.com

# Request for explicit host, save to custom paths, then deploy
sudo ./bin/webctl letsencrypt \
  --host example.com \
  --email admin@example.com \
  --cert-path /etc/pki/tls/certs/example.com.crt \
  --key-path /etc/pki/tls/private/example.com.key

# Request only (no deploy)
sudo ./bin/webctl letsencrypt --host example.com --deploy=false
```

## Implementation

Project layout:

- `cmd/webd/main.go`: data-plane daemon entrypoint.
- `cmd/webctl/main.go`: control-plane utility entrypoint.
- `internal/cli`: control-plane commands, config parsing, reload staging, setup.
- `internal/server`: runtime config model, proxy runtime, request logging, TLS/config SIGHUP reload.
- `internal/app`: defaults and shared option structs.

Runtime behavior highlights:

- Logging is sent to journal via syslog with separate categories:
  - `webd-error` for fatal/runtime errors
  - `webd-ops` for operational events (startup/load/reload/signal)
  - `webd-access` for per-request access entries
- TLS cert/key and routes are reloaded in-process on `SIGHUP`.
- `webctl reload` resolves handler hostnames and writes runtime config with route `path` plus decomposed `handler` targets including `protocol`, `hostname`, `port`, `path`, and `ipv4_addresses`.
- `webctl reload` verifies each HTTPS handler against its configured local trusted CA bundle, extracts the validating intermediate/root certificates when possible, and stages them at `/run/webd/ca-<name>.crt`.
- `webd` loads only `/run/webd/config.json`, dials the staged IPv4 addresses directly, and does not perform DNS lookups for handler routing.
- `webd` uses a staged trusted CA bundle to verify an HTTPS handler when that handler declares `trusted_ca`, or when `webctl reload` auto-pins the handler CA chain for handlers without `trusted_ca`.
- Handler requests include standard proxy headers such as `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP`, and `Forwarded`.
- `webd` accepts no flags/subcommands; control operations are in `webctl`.
- `webd` requires effective UID in the 500-999 range.
- `webd` fails fast if any required runtime file is unreadable.

Implementation call flow:

Server startup (`webd`):

1. `cmd/webd/main.go:main` creates syslog loggers with `syslogx.New`, rejects flags/subcommands, validates the effective UID range, and verifies the required runtime files under `/run/webd`.
2. `main` builds `app.RunOptions` and calls `server.Run`.
3. `internal/server/server.go:Run` creates the daemon loggers, loads the runtime JSON with `LoadJSON`, and validates it through `internal/server/config.go:Validate`.
4. `Run` builds route handlers with `buildRouteProxies`; handler routes use `handlerURL`, `httputil.NewSingleHostReverseProxy`, a wrapped `Director` that calls `setForwardedHeaders`, and `newStaticHandlerTransport`, while redirect routes keep only a redirect target URL.
5. `newStaticHandlerTransport` clones `http.DefaultTransport`, dials only the staged `ipv4_addresses`, and, for HTTPS handlers, loads the staged CA bundle with `loadTrustedCertPool` and sets `TLSClientConfig.ServerName` to the handler hostname.
6. `Run` wraps the router with `accessLogMiddleware`, creates the TLS reloader with `newCertReloader`, then starts the cleartext server with `http.Server.ListenAndServe` and the TLS server with `tls.Listen` plus `http.Server.Serve`.
7. `Run` also installs a `SIGHUP` handler that reloads the runtime config with `LoadJSON`, rebuilds routes with `buildRouteProxies`, swaps them atomically, and refreshes the serving certificate with `certReloader.Reload`.

HTTP request proxying:

1. The per-request handler created inside `internal/server/server.go:Run` reads the current route table from `atomic.Value` and picks the first prefix match, after `buildRouteProxies` sorted routes by descending prefix length.
2. The matched route either returns `301 Moved Permanently` to its configured `redirect` URL or executes `routeProxy.proxy.ServeHTTP` for handler proxy routes.
3. The proxy `Director` first applies the standard handler rewrite from `httputil.NewSingleHostReverseProxy`, then calls `setForwardedHeaders` to set `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, and `Forwarded`.
4. The proxy transport is the `http.RoundTripper` returned by `newStaticHandlerTransport`; it uses a custom `DialContext` to try the staged IPv4 list in order and connects to `hostname:port` only for TLS verification and URL shaping, not for DNS resolution.
5. For HTTPS handlers, the transport verifies the peer certificate against either the system pool or the staged `trusted_ca` bundle loaded by `loadTrustedCertPool`.
6. Proxy failures are handled by the custom `ErrorHandler` installed in `buildRouteProxies`, which returns `502 Bad Gateway` and logs the handler/path/error.
7. The outer `accessLogMiddleware` records the final status, response size, duration, method, URI, and client IP after the proxied request completes.

Control-plane reload (`webctl reload` and `--prepare-only`):

1. `cmd/webctl/main.go:main` creates command loggers with `syslogx.NewForCommand` and calls `cli.ExecuteControl`.
2. `internal/cli/root.go:ExecuteControl` builds the Cobra root command, wires the `reload` subcommand, copies persistent flag values into `reload.Options`, and calls `internal/cli/reload.go:Run`.
3. `Run` requires root, resolves the runtime user with `lookupRunUser`, validates the runtime directory layout with `validateRunTLSDirs`, and creates/chowns `/run/webd` with `ensureRuntimeTLSDir`.
4. If `PrepareOnly` is false, `Run` locates live daemon PIDs with `findHTTPSDPIDs` and verifies that the configured HTTP/HTTPS listen ports are owned by those processes with `ensurePortsBoundByHTTPSD`.
5. `Run` stages all runtime artifacts through `stageTLSArtifacts`, or only local TLS cert/key artifacts through `stageOnlyLocalTLSArtifacts` when `--only-local-tls` is set.
6. `stageTLSArtifacts` first calls `stageConfigArtifact`, which loads the YAML source config with `internal/cli/config.go:Load`, converts it to runtime JSON with `buildRuntimeConfig`, and writes `/run/webd/config.json` atomically.
7. `buildRuntimeConfig` translates `allowed_ipv4` entries into numeric `start`/`end` IPv4 ranges for the runtime JSON, emits redirect routes directly, and for handler routes uses `buildRuntimeHandler` to resolve `ipv4_addresses` and stage `trusted_ca` runtime files when configured.
8. For handlers with `trusted_ca`, `stageTrustedCA` verifies the handler against the local CA file by calling `fetchVerifiedHandlerCACerts`; for `https`/`wss` handlers without `trusted_ca`, `stageAutoTrustedCA` verifies against the OS trust store via `fetchVerifiedHandlerOSCACerts` and stages the detected issuing/root CA chain. Both paths write `/run/webd/ca-<name>.crt` with `writeTrustedCAFile`.
9. After the runtime JSON is staged, `stageTLSArtifacts` validates the configured server certificate chain order with `validateTLSBundleOrder`, then copies the TLS certificate and key into `/run/webd/tls.crt` and `/run/webd/tls.key` with `copyFileAtomic` and fixes ownership.
10. If `PrepareOnly` is true, `Run` stops here after logging `prepare-only mode complete`; no process discovery or signal delivery happens.
11. If staged outputs are unchanged and `--force` is not set, `Run` logs a no-change result and exits without signaling.
12. Otherwise, `Run` sends `SIGHUP` to each discovered daemon PID with `syscall.Kill`, which triggers the in-process reload path in `internal/server/server.go:Run`.

Control-plane config check (`webctl check`):

1. `cmd/webctl/main.go:main` creates command loggers with `syslogx.NewForCommand` and calls `cli.ExecuteControl`.
2. `internal/cli/root.go:ExecuteControl` wires the `check` subcommand and calls `runCheck` with the shared `app.RunOptions` values from the persistent flags.
3. `internal/cli/check.go:runCheck` loads and validates the YAML config with `internal/cli/config.go:Load`, renders it with `PrettyYAML`, and prints it through `ColorizeYAML`.
4. `runCheck` performs port checks with `checkBindPort`, which resolves the configured port, inspects `/proc` listener ownership through `findPortOwners`, and reports either a free port or the owning processes.
5. `runCheck` performs handler checks with `checkHandlers`; each distinct handler URL is parsed, then either a plain TCP connection is attempted for `http` or a TLS handshake is attempted for `https`.
6. For HTTPS handlers with `trusted_ca`, `checkHandlers` loads the configured CA bundle with `loadTrustedCAPool` and uses it as `RootCAs`; otherwise it falls back to an insecure probe handshake that only checks reachability.
7. `runCheck` validates the local serving certificate and key with `checkTLSMaterials`, which reads both PEM files, verifies `tls.X509KeyPair`, parses the certificate chain with `parseCertificatesFromPEM`, checks ordering/signatures, and verifies that the leaf SAN matches one of the local host candidates from `hostCandidates`.
8. If any port, handler, or TLS check fails, `runCheck` returns a combined error summary; otherwise it prints `check OK`.

Control-plane host setup (`webctl setup`):

1. `cmd/webctl/main.go:main` creates command loggers with `syslogx.NewForCommand` and calls `cli.ExecuteControl`.
2. `internal/cli/root.go:ExecuteControl` wires the `setup` subcommand, binds the setup-specific flags, and calls `runSetup` with `app.SetupOptions`.
3. `internal/cli/setup.go:runSetup` requires root, then creates or validates the `webd` and `tlskey` groups with `ensureGroupExists` and the `webd` user with `ensureUserExists`.
4. `runSetup` ensures the `webd` user is a member of `tlskey` via `ensureUserInGroup`, then verifies the resulting account layout with `validateServiceIdentity` and `validateAccountDatabases`.
5. `runSetup` checks that the configured TLS key and certificate files exist, then provisions `/etc/webd` and the default config file via `ensureEtcConfig`.
6. `runSetup` stages the current binary into the versioned install tree with `ensureVersionedInstall`; that helper derives the versioned path from `app.Version` and `app.BuildTime` using `buildVersionDirName`, copies the executable into `/opt/webd/<version>/libexec/webd`, and refreshes `/opt/webd/current` to point at the newest installed version.
7. `runSetup` removes any file capabilities from the configured binary path with `ensureNoFileCapabilities`; low-port bind permission is then supplied only by systemd `AmbientCapabilities`.
8. `runSetup` writes or validates the systemd unit with `ensureSystemdUnit`; if the unit changed, it runs `daemonReload` to execute `systemctl daemon-reload`.
9. `runSetup` finishes by printing `setup complete` after the host account, config, binary install, capability, and systemd state all match the expected layout.

## Build From Source (xc)

This repository defines `xc` tasks under the `Tasks` heading below.

Examples:

```sh
xc -s -no-tty     # list task names
xc build          # alias for xc build-all
xc build-all      # build both binaries into ./bin/
xc build-server   # build ./bin/webd from ./cmd/webd
xc build-client   # build ./bin/webctl from ./cmd/webctl
xc test           # run all tests
xc check          # validate config.example.yaml
./bin/webd --version
```

## Tasks

### build-client

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webctl ./cmd/webctl
```

### build-server

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webd ./cmd/webd
```

### build-all

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webd ./cmd/webd

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webctl ./cmd/webctl
```

### build

Alias for `build-all`:

```sh
xc build-all
```

### test

```sh
go test ./...
```

### check

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webd ./cmd/webd
CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webctl ./cmd/webctl
./bin/webctl check --config ./config.example.yaml
```

### run

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webd ./cmd/webd
./bin/webd
```

### reload

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webd ./cmd/webd
CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webctl ./cmd/webctl
./bin/webctl reload
```

### setup

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webd ./cmd/webd
CGO_ENABLED=0 go build \
  -ldflags "-X 'webd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'webd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/webctl ./cmd/webctl
sudo ./bin/webctl setup
```
