# Production Docker Packaging

This directory owns the production container image path. The Dockerfile is
separate from `contrib/demo-stack/`: demo-specific entrypoints, generated demo
TLS material, Compose topology and proof helpers stay in the demo stack. The
production image can be used by a demo or test environment later, but it is
built to run without that topology.

## Image Contract

- Build with Go 1.26 and `-mod=vendor`.
- Build `nauthilus-director` and `nauthilus-directorctl` from the root
  production module.
- Use reproducible build inputs: `-trimpath`, `-buildvcs=false` and an empty Go
  build id.
- Default to explicit build-helper base images and a `scratch` runtime image.
- Copy only the two binaries, CA trust roots, passwd/group metadata and empty
  runtime directories into the final image.
- Run as UID/GID `10001:10001` by default.
- Preserve outbound TLS verification through copied CA certificates.
- Carry OCI labels for version, revision, build date, source and license.

The runtime image contains no shell, package manager, Go toolchain, source
tree, vendor tree, `.git` directory, `temp/` material, archived implementation
files, demo TLS helpers or demo entrypoint.

## Build

Build the production image:

```sh
make docker-build
```

The target uses the following overridable variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `IMAGE_TAG` | `nauthilus-director:$(VERSION)` | Local image tag to build and smoke-test. |
| `VERSION` | `git describe --tags --always --dirty` or `dev` | Binary `--version` value and OCI version label. |
| `REVISION` | Short Git revision or `unknown` | OCI revision label. |
| `BUILD_DATE` | `unknown` | OCI created label; set an RFC 3339 timestamp when desired. |
| `IMAGE_SOURCE` | Repository URL | OCI source label. |
| `GO_IMAGE` | `golang:1.26-alpine3.23` | Go build-stage image. |
| `CERTS_IMAGE` | `alpine:3.23` | CA-certificate and passwd/group preparation image. |
| `RUNTIME_IMAGE` | `scratch` | Final runtime image. |
| `DOCKER_BUILD_FLAGS` | empty | Extra flags passed to `docker build`. |

Example with explicit metadata:

```sh
make docker-build \
  IMAGE_TAG=registry.example.org/nauthilus-director:v1.0.0 \
  VERSION=v1.0.0 \
  REVISION=0123456789ab \
  BUILD_DATE=2026-06-05T00:00:00Z
```

`make docker-build` skips with a stable message when the Docker CLI or daemon
is unavailable. It is intentionally not part of `make guardrails`.

## Smoke Test

Run the optional image smoke proof:

```sh
make docker-smoke
```

The smoke target builds the image, runs both binaries with `--version`, and
checks that a default config dump redacts protected values. It runs under
`--network=none`, `--read-only`, `/tmp` tmpfs and `/run/nauthilus-director`
tmpfs. It does not start protocol listeners and does not require production
secrets.

## Runtime Mounts

The default command starts the server with:

```text
nauthilus-director --config /etc/nauthilus-director/nauthilus-director.yml serve
```

Mount production configuration under `/etc/nauthilus-director/`. Secret-bearing
settings should reference files in that mount or in another read-only secret
mount, for example password files, bearer-token files, private keys and CA
bundles. The image does not bake secret values, default bearer tokens or
private keys.

Writable runtime paths:

| Path | Purpose | Recommended mount |
| --- | --- | --- |
| `/run/nauthilus-director` | Runtime sockets, pid-like state or future short-lived files | tmpfs owned by UID/GID `10001:10001` |
| `/tmp` | Optional temporary files required by Go/runtime libraries | tmpfs |

The image is compatible with read-only root filesystems when those writable
paths are provided as tmpfs mounts.

## Health Probes

The control listener is configured by
`runtime.servers.control.address`. The canonical default is
`127.0.0.1:9090`; container deployments usually bind an explicit container
address in their mounted config and publish only the intended host interface.

Use the unauthenticated liveness and readiness probes documented by the REST
contract:

```text
GET /healthz
GET /readyz
```

Operator status checks can use `nauthilus-directorctl status` when the control
API is reachable and authenticated according to the mounted runtime config.

## Static Validation

`make check-packaging` validates the Dockerfile without starting Docker. It
checks for Go 1.26, vendored builds, non-root runtime, `scratch` runtime
default, OCI labels, `.dockerignore` exclusions, stable optional targets and
the absence of demo-stack entrypoints or source-only copy paths.
