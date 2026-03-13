# httpsd

## Objectives

- Provide a minimal Go HTTPS reverse proxy daemon for Linux hosts.
- Serve both HTTP (`:80`) and HTTPS (`:443`) with configured TLS material.
- Support zero-downtime reload of TLS cert/key and route config via `SIGHUP`.
- Split binaries by responsibility:
  - `httpsd` for the HTTP(S) data-plane server.
  - `httpsdctl` for control-plane operations (`reload`, `check`, `setup`).

## Usage

Build a local binary:

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsd ./cmd/httpsd

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsdctl ./cmd/httpsdctl
```

Run the proxy server:

```sh
./bin/httpsd
```

Reload config + TLS on a running process:

```sh
./bin/httpsdctl reload
```

Validate and pretty-print config:

```sh
./bin/httpsdctl check --config /etc/httpsd/config.yaml
```

Host setup (root required):

```sh
sudo ./bin/httpsdctl setup
```

## Configuration

Default config path: `/etc/httpsd/config.yaml`

Example (`config.example.yaml`):

```yaml
routes:
  - path_prefix: /api/
    upstream: http://127.0.0.1:8080/api/v1/
  - path_prefix: /internal/
    upstream: https://api.internal.example.com/v1/
    trusted_ca:
      name: internal-api
      cert_path: /etc/pki/ca-trust/source/anchors/internal-api.crt
  - path_prefix: /
    upstream: http://127.0.0.1:3000
```

Rules:

- `routes` must contain at least one entry.
- `path_prefix` must begin with `/` (empty is treated as `/`).
- `upstream` must be a valid absolute URL.
- `trusted_ca` is optional and supported only for `https` upstreams.
- `trusted_ca.name` may contain only letters, digits, `.`, `_`, and `-`.
- `trusted_ca.cert_path` must point to a PEM CA bundle that `httpsdctl reload` can read.
- Longest `path_prefix` wins.

TLS notes:

- `--tls-cert` should contain the server certificate chain PEM bundle.
- Bundle order should be leaf cert first, then intermediates.
- `--tls-key` is the private key PEM.

## Implementation

Project layout:

- `cmd/httpsd/main.go`: data-plane daemon entrypoint.
- `cmd/httpsdctl/main.go`: control-plane utility entrypoint.
- `internal/cli`: control-plane commands, config parsing, reload staging, setup.
- `internal/server`: runtime config model, proxy runtime, request logging, TLS/config SIGHUP reload.
- `internal/app`: defaults and shared option structs.

Runtime behavior highlights:

- Logging is sent to journal via syslog with separate categories:
  - `httpsd-error` for fatal/runtime errors
  - `httpsd-ops` for operational events (startup/load/reload/signal)
  - `httpsd-access` for per-request access entries
- TLS cert/key and routes are reloaded in-process on `SIGHUP`.
- `httpsdctl reload` resolves upstream hostnames and writes runtime config with decomposed upstream targets including `protocol`, `hostname`, `port`, `path`, and `ipv4_addresses`.
- `httpsdctl reload` verifies each HTTPS upstream against its configured local trusted CA bundle, extracts the validating intermediate/root certificates when possible, and stages them at `/run/httpsd/ca-<name>.crt`.
- `httpsd` loads only `/run/httpsd/config.json`, dials the staged IPv4 addresses directly, and does not perform DNS lookups for upstream routing.
- `httpsd` uses a staged trusted CA bundle to verify an HTTPS upstream when that upstream declares `trusted_ca`.
- Upstream requests include standard proxy headers such as `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP`, and `Forwarded`.
- `httpsd` accepts no flags/subcommands; control operations are in `httpsdctl`.
- `httpsd` requires effective UID in the 500-999 range.
- `httpsd` fails fast if any required runtime file is unreadable.

Implementation call flow:

Server startup (`httpsd`):

1. `cmd/httpsd/main.go:main` creates syslog loggers with `syslogx.New`, rejects flags/subcommands, validates the effective UID range, and verifies the required runtime files under `/run/httpsd`.
2. `main` builds `app.RunOptions` and calls `server.Run`.
3. `internal/server/server.go:Run` creates the daemon loggers, loads the runtime JSON with `LoadJSON`, and validates it through `internal/server/config.go:Validate`.
4. `Run` builds reverse proxies with `buildRouteProxies`; each route uses `upstreamURL`, `httputil.NewSingleHostReverseProxy`, a wrapped `Director` that calls `setForwardedHeaders`, and `newStaticUpstreamTransport`.
5. `newStaticUpstreamTransport` clones `http.DefaultTransport`, dials only the staged `ipv4_addresses`, and, for HTTPS upstreams, loads the staged CA bundle with `loadTrustedCertPool` and sets `TLSClientConfig.ServerName` to the upstream hostname.
6. `Run` wraps the router with `accessLogMiddleware`, creates the TLS reloader with `newCertReloader`, then starts the cleartext server with `http.Server.ListenAndServe` and the TLS server with `tls.Listen` plus `http.Server.Serve`.
7. `Run` also installs a `SIGHUP` handler that reloads the runtime config with `LoadJSON`, rebuilds routes with `buildRouteProxies`, swaps them atomically, and refreshes the serving certificate with `certReloader.Reload`.

HTTP request proxying:

1. The per-request handler created inside `internal/server/server.go:Run` reads the current route table from `atomic.Value` and picks the first prefix match, after `buildRouteProxies` sorted routes by descending prefix length.
2. The matched `routeProxy.proxy.ServeHTTP` executes the `httputil.ReverseProxy` created by `buildRouteProxies`.
3. The proxy `Director` first applies the standard upstream rewrite from `httputil.NewSingleHostReverseProxy`, then calls `setForwardedHeaders` to set `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, and `Forwarded`.
4. The proxy transport is the `http.RoundTripper` returned by `newStaticUpstreamTransport`; it uses a custom `DialContext` to try the staged IPv4 list in order and connects to `hostname:port` only for TLS verification and URL shaping, not for DNS resolution.
5. For HTTPS upstreams, the transport verifies the peer certificate against either the system pool or the staged `trusted_ca` bundle loaded by `loadTrustedCertPool`.
6. Proxy failures are handled by the custom `ErrorHandler` installed in `buildRouteProxies`, which returns `502 Bad Gateway` and logs the upstream/path/error.
7. The outer `accessLogMiddleware` records the final status, response size, duration, method, URI, and client IP after the proxied request completes.

Control-plane reload (`httpsdctl reload` and `--prepare-only`):

1. `cmd/httpsdctl/main.go:main` creates command loggers with `syslogx.NewForCommand` and calls `cli.ExecuteControl`.
2. `internal/cli/root.go:ExecuteControl` builds the Cobra root command, wires the `reload` subcommand, copies persistent flag values into `reload.Options`, and calls `internal/cli/reload.go:Run`.
3. `Run` requires root, resolves the runtime user with `lookupRunUser`, validates the runtime directory layout with `validateRunTLSDirs`, creates/chowns `/run/httpsd` with `ensureRuntimeTLSDir`, and bind-mounts `/dev/log` into the runtime tree with `ensureRuntimeDevLogBindMount`.
4. If `PrepareOnly` is false, `Run` locates live daemon PIDs with `findHTTPSDPIDs` and verifies that the configured HTTP/HTTPS listen ports are owned by those processes with `ensurePortsBoundByHTTPSD`.
5. `Run` stages all runtime artifacts through `stageTLSArtifacts`.
6. `stageTLSArtifacts` first calls `stageConfigArtifact`, which loads the YAML source config with `internal/cli/config.go:Load`, converts it to runtime JSON with `buildRuntimeConfig`, and writes `/run/httpsd/config.json` atomically.
7. `buildRuntimeConfig` processes each route with `buildRuntimeUpstream`, which parses the upstream URL, resolves `ipv4_addresses` with `lookupIPv4Addresses`, and, when `trusted_ca` is configured, stages a runtime CA file through `stageTrustedCA`.
8. `stageTrustedCA` verifies the upstream against the local CA file by calling `fetchVerifiedUpstreamCACerts`; that helper reads the configured PEM bundle, fetches the upstream-presented chain with `fetchUpstreamPeerCertificates`, verifies it with `x509.Certificate.Verify`, optionally extends it with `appendLocalParentChain`, and writes `/run/httpsd/ca-<name>.crt` with `writeTrustedCAFile`.
9. After the runtime JSON is staged, `stageTLSArtifacts` validates the configured server certificate chain order with `validateTLSBundleOrder`, then copies the TLS certificate and key into `/run/httpsd/tls.crt` and `/run/httpsd/tls.key` with `copyFileAtomic` and fixes ownership.
10. If `PrepareOnly` is true, `Run` stops here after logging `prepare-only mode complete`; no process discovery or signal delivery happens.
11. Otherwise, `Run` sends `SIGHUP` to each discovered daemon PID with `syscall.Kill`, which triggers the in-process reload path in `internal/server/server.go:Run`.

Control-plane config check (`httpsdctl check`):

1. `cmd/httpsdctl/main.go:main` creates command loggers with `syslogx.NewForCommand` and calls `cli.ExecuteControl`.
2. `internal/cli/root.go:ExecuteControl` wires the `check` subcommand and calls `runCheck` with the shared `app.RunOptions` values from the persistent flags.
3. `internal/cli/check.go:runCheck` loads and validates the YAML config with `internal/cli/config.go:Load`, renders it with `PrettyYAML`, and prints it through `ColorizeYAML`.
4. `runCheck` performs port checks with `checkBindPort`, which resolves the configured port, inspects `/proc` listener ownership through `findPortOwners`, and reports either a free port or the owning processes.
5. `runCheck` performs upstream checks with `checkUpstreams`; each distinct upstream URL is parsed, then either a plain TCP connection is attempted for `http` or a TLS handshake is attempted for `https`.
6. For HTTPS upstreams with `trusted_ca`, `checkUpstreams` loads the configured CA bundle with `loadTrustedCAPool` and uses it as `RootCAs`; otherwise it falls back to an insecure probe handshake that only checks reachability.
7. `runCheck` validates the local serving certificate and key with `checkTLSMaterials`, which reads both PEM files, verifies `tls.X509KeyPair`, parses the certificate chain with `parseCertificatesFromPEM`, checks ordering/signatures, and verifies that the leaf SAN matches one of the local host candidates from `hostCandidates`.
8. If any port, upstream, or TLS check fails, `runCheck` returns a combined error summary; otherwise it prints `check OK`.

Control-plane host setup (`httpsdctl setup`):

1. `cmd/httpsdctl/main.go:main` creates command loggers with `syslogx.NewForCommand` and calls `cli.ExecuteControl`.
2. `internal/cli/root.go:ExecuteControl` wires the `setup` subcommand, binds the setup-specific flags, and calls `runSetup` with `app.SetupOptions`.
3. `internal/cli/setup.go:runSetup` requires root, then creates or validates the `httpsd` and `tlskey` groups with `ensureGroupExists` and the `httpsd` user with `ensureUserExists`.
4. `runSetup` ensures the `httpsd` user is a member of `tlskey` via `ensureUserInGroup`, then verifies the resulting account layout with `validateServiceIdentity` and `validateAccountDatabases`.
5. `runSetup` checks that the configured TLS key and certificate files exist, then provisions `/etc/httpsd` and the default config file via `ensureEtcConfig`.
6. `runSetup` stages the current binary into the versioned install tree with `ensureVersionedInstall`; that helper derives the versioned path from `app.Version` and `app.BuildTime` using `buildVersionDirName`, copies the executable into `/opt/httpsd/<version>/sbin/httpsd`, and refreshes `/opt/httpsd/current` to point at the newest installed version.
7. `runSetup` grants `cap_net_bind_service` to the configured binary path with `ensureNetBindCapability` so `httpsd` can bind ports 80 and 443 without running as root.
8. `runSetup` writes or validates the systemd unit with `ensureSystemdUnit`; if the unit changed, it runs `daemonReload` to execute `systemctl daemon-reload`.
9. `runSetup` finishes by printing `setup complete` after the host account, config, binary install, capability, and systemd state all match the expected layout.

## Build From Source (xc)

This repository defines `xc` tasks under the `Tasks` heading below.

Examples:

```sh
xc -s -no-tty     # list task names
xc build          # alias for xc build-all
xc build-all      # build both binaries into ./bin/
xc build-server   # build ./bin/httpsd from ./cmd/httpsd
xc build-client   # build ./bin/httpsdctl from ./cmd/httpsdctl
xc test           # run all tests
xc check          # validate config.example.yaml
./bin/httpsd --version
```

## Tasks

### build-client

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsdctl ./cmd/httpsdctl
```

### build-server

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsd ./cmd/httpsd
```

### build-all

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsd ./cmd/httpsd

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsdctl ./cmd/httpsdctl
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
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsd ./cmd/httpsd
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsdctl ./cmd/httpsdctl
./bin/httpsdctl check --config ./config.example.yaml
```

### run

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsd ./cmd/httpsd
./bin/httpsd
```

### reload

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsd ./cmd/httpsd
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsdctl ./cmd/httpsdctl
./bin/httpsdctl reload
```

### setup

```sh
mkdir -p ./bin

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsd ./cmd/httpsd
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./bin/httpsdctl ./cmd/httpsdctl
sudo ./bin/httpsdctl setup
```
