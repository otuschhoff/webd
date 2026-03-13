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
  - path_prefix: /
    upstream: http://127.0.0.1:3000
```

Rules:

- `routes` must contain at least one entry.
- `path_prefix` must begin with `/` (empty is treated as `/`).
- `upstream` must be a valid absolute URL.
- Longest `path_prefix` wins.

TLS notes:

- `--tls-cert` should contain the server certificate chain PEM bundle.
- Bundle order should be leaf cert first, then intermediates.
- `--tls-key` is the private key PEM.

## Implementation

Project layout:

- `cmd/httpsd/main.go`: data-plane daemon entrypoint.
- `cmd/httpsdctl/main.go`: control-plane utility entrypoint.
- `internal/cli`: Cobra command wiring.
- `internal/server`: proxy runtime, request logging, TLS/config SIGHUP reload.
- `internal/proxycfg`: config model, load/validate, pretty/color output.
- `internal/reloadcmd`: process lookup + `SIGHUP` signaling.
- `internal/setup`: user/group/permissions/capabilities/systemd setup.
- `internal/app`: defaults and shared option structs.

Runtime behavior highlights:

- Access logs written to `/var/log/httpsd/access.log` with 1 MiB rotation.
- TLS cert/key and routes are reloaded in-process on `SIGHUP`.
- DNS upstream hostnames are refreshed ahead of TTL expiry; failed refreshes keep the last working IP set and retry with exponential backoff.
- Multi-IP DNS answers are probed and each request randomly picks one healthy upstream IP.
- Upstream requests include standard proxy headers such as `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP`, and `Forwarded`.
- `httpsd` accepts no flags/subcommands; control operations are in `httpsdctl`.
- `httpsd` requires effective UID in the 500-999 range.
- `httpsd` fails fast if any required file is unreadable: `/etc/httpsd/config.yaml`, `/run/httpsd/tls.crt`, `/run/httpsd/tls.key`, `/etc/resolv.conf`.

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
