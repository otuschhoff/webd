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

Manage an automated local TLS refresh timer (root required for add/modify/delete):

```sh
sudo ./bin/webctl reload-timer add --interval 1d
./bin/webctl reload-timer show
sudo ./bin/webctl reload-timer modify --interval 12h
sudo ./bin/webctl reload-timer delete
```

The timer name is `webd-local-tls-update.timer` and it runs `webctl reload --only-local-tls` as root on the configured interval.

Validate and pretty-print config:

```sh
./bin/webctl check --config /etc/webd/config.yaml
```

Host setup (root required):

```sh
sudo ./bin/webctl setup
```

Generate shell completion (hidden command; useful for package/integration scripts):

```sh
./bin/webctl completion bash
./bin/webctl completion tcsh
```

`webctl setup` also refreshes system shell completion files for `webctl` (bash, zsh, fish, tcsh) so the OS has the current command set.
It also installs root profile snippets so `/opt/webd/current/sbin` (the installed `webctl` subdir) is in root's `PATH`.

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
- Non-ACME HTTP requests are permanently redirected (`301`) to the equivalent `https://` URL.
- ACME challenge requests under `/.well-known/acme-challenge/` are served over HTTP without redirect.
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
- Most specific `path` wins (longest prefix match).

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

1. `cmd/webd/main.go:main` initializes logging, rejects flags/subcommands, checks runtime EUID range, and verifies required runtime files in `/run/webd`.
2. `main` builds `server.RunOptions` and calls `internal/server/server.go:Run`.
3. `Run` loads runtime JSON, validates config, builds route handlers with `buildRouteProxies`, and starts both HTTP and HTTPS listeners.
4. The request router in `internal/server/handler.go` serves ACME challenge requests first, then applies global HTTP→HTTPS redirects for non-ACME cleartext requests, then evaluates configured routes.
5. Proxy routes use `httputil.ReverseProxy` with forwarded-header enrichment (`handleProxyForwardedHeaders`) and transport dialing over staged IPv4 addresses (`handleProxyTransport`) to avoid request-time DNS lookups.
6. `Run` installs `SIGHUP` handling to atomically reload runtime config/routes and refresh serving cert/key without full process restart.

Control-plane reload (`webctl reload`):

1. `cmd/webctl/main.go:main` invokes `internal/cli/args.go:ExecuteControl`.
2. `reload` staging in `internal/cli/reload.go:Run` requires root, validates runtime destination layout, and prepares `/run/webd` ownership/permissions.
3. Default mode stages runtime config + trust artifacts + local TLS cert/key, then signals running `webd` only when staged outputs changed (unless `--force`).
4. `--only-local-tls` mode stages only local cert/key artifacts and signals only when those changed (unless `--force`).
5. `--prepare-only` stages artifacts but does not signal running processes.

Control-plane setup (`webctl setup`):

1. Requires root and validates/creates service identity (`webd` user/group and `tlskey` membership).
2. Verifies source TLS materials and provisions `/etc/webd/config.yaml` if absent.
3. Installs versioned binaries under `/opt/webd/<version>/` and updates `/opt/webd/current`.
4. Refreshes system shell completions and root PATH snippets for `webctl`.
5. Writes/updates `/etc/systemd/system/webd.service` and runs `systemctl daemon-reload` when needed.

## systemd webd.service details

`webctl setup` manages a hardened systemd unit at `/etc/systemd/system/webd.service`.

What the service does:

- Runs `webd` as user/group `webd` (non-root service user).
- Uses `RuntimeDirectory=webd` so runtime artifacts live under `/run/webd`.
- Executes `ExecStartPre=+/opt/webd/current/sbin/webctl reload --prepare-only` as root to stage `/run/webd/config.json`, `/run/webd/tls.crt`, `/run/webd/tls.key`, and staged trusted CA files before daemon start.
- Starts `webd` via `ExecStart=/opt/webd/current/libexec/webd`.
- Supports in-place reload via `ExecReload=+/opt/webd/current/sbin/webctl reload`, which stages runtime artifacts then sends `SIGHUP`.

Security and isolation model:

- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` and `AmbientCapabilities=CAP_NET_BIND_SERVICE` allow low-port binding without running as root.
- `RootDirectory=/run/webd` plus bind mounts expose only required binaries/log sockets and keeps runtime file scope minimal.
- Additional hardening includes `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateDevices=true`, restricted namespaces/address families, and syscall filters.

Operational behavior:

- `Restart=on-failure` automatically restarts on crash.
- Memory limits are enforced with `MemoryMax` and `GOMEMLIMIT` derived from defaults in `internal/cli/defaults.go`.
- Setup is idempotent: rerunning `webctl setup` updates the unit only when content differs.

Useful commands:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now webd.service
sudo systemctl status webd.service
sudo systemctl reload webd.service
journalctl -u webd.service -f
```

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
