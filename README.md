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
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd

CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsdctl ./cmd/httpsdctl
```

Run the proxy server:

```sh
./httpsd
```

Reload config + TLS on a running process:

```sh
./httpsdctl reload
```

Validate and pretty-print config:

```sh
./httpsdctl check --config /etc/httpsd/config.yaml
```

Host setup (root required):

```sh
sudo ./httpsdctl setup
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
- `httpsdctl reload` stages per-upstream trusted CA bundles at `/run/httpd/ca-<name>.crt` when configured.
- `httpsd` loads only `/run/httpsd/config.json`, dials the staged IPv4 addresses directly, and does not perform DNS lookups for upstream routing.
- `httpsd` uses a staged trusted CA bundle to verify an HTTPS upstream when that upstream declares `trusted_ca`.
- Upstream requests include standard proxy headers such as `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP`, and `Forwarded`.
- `httpsd` accepts no flags/subcommands; control operations are in `httpsdctl`.
- `httpsd` requires effective UID in the 500-999 range.
- `httpsd` fails fast if any required runtime file is unreadable.

## Build From Source (xc)

This repository defines `xc` tasks under the `Tasks` heading below.

Examples:

```sh
xc -s -no-tty     # list task names
xc build          # build ./httpsd from ./cmd/httpsd
xc test           # run all tests
xc check          # validate config.example.yaml
./httpsd --version
```

## Tasks

### build

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
```

### test

```sh
go test ./...
```

### check

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsdctl ./cmd/httpsdctl
./httpsdctl check --config ./config.example.yaml
```

### run

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
./httpsd
```

### reload

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsdctl ./cmd/httpsdctl
./httpsdctl reload
```

### setup

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsdctl ./cmd/httpsdctl
sudo ./httpsdctl setup
```
