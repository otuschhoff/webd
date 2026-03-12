# httpsd

## Objectives

- Provide a minimal Go HTTPS reverse proxy daemon for Linux hosts.
- Serve both HTTP (`:80`) and HTTPS (`:443`) with configured TLS material.
- Support zero-downtime reload of TLS cert/key and route config via `SIGHUP`.
- Keep operations simple with built-in CLI subcommands: `run`, `reload`, `check`, and `setup`.

## Usage

Build a local binary:

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
```

Run the proxy server:

```sh
./httpsd run --config /etc/httpsd/config.json
```

Reload config + TLS on a running process:

```sh
./httpsd reload
```

Validate and pretty-print config:

```sh
./httpsd check --config /etc/httpsd/config.json
```

Host setup (root required):

```sh
sudo ./httpsd setup
```

## Configuration

Default config path: `/etc/httpsd/config.json`

Example (`config.example.json`):

```json
{
  "routes": [
    {
      "path_prefix": "/api/",
      "upstream": "http://127.0.0.1:8080"
    },
    {
      "path_prefix": "/",
      "upstream": "http://127.0.0.1:3000"
    }
  ]
}
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

- `cmd/httpsd/main.go`: thin entrypoint.
- `internal/cli`: Cobra command wiring.
- `internal/server`: proxy runtime, request logging, TLS/config SIGHUP reload.
- `internal/proxycfg`: config model, load/validate, pretty/color output.
- `internal/reloadcmd`: process lookup + `SIGHUP` signaling.
- `internal/setup`: user/group/permissions/capabilities/systemd setup.
- `internal/app`: defaults and shared option structs.

Runtime behavior highlights:

- Access logs written to `/var/log/httpsd/access.log` with 1 MiB rotation.
- TLS cert/key and routes are reloaded in-process on `SIGHUP`.
- Root execution for `run` is blocked.
- Non-root run user is enforced unless `--force` is set.

## Build From Source (xc)

This repository defines `xc` tasks under the `Tasks` heading below.

Examples:

```sh
xc -s -no-tty     # list task names
xc build          # build ./httpsd from ./cmd/httpsd
xc test           # run all tests
xc check          # validate config.example.json
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
./httpsd check --config ./config.example.json
```

### run

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
./httpsd run --config "${CONFIG:-/etc/httpsd/config.json}"
```

### reload

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
./httpsd reload
```

### setup

```sh
CGO_ENABLED=0 go build \
  -ldflags "-X 'httpsd/internal/app.Version=v0.1.0' -X 'httpsd/internal/app.BuildTime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')' -X 'httpsd/internal/app.CommitSHA=$(git rev-parse --short=12 HEAD)'" \
  -o ./httpsd ./cmd/httpsd
sudo ./httpsd setup
```
