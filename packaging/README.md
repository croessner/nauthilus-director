# Production Packaging Inventory

This directory owns production delivery artifacts for `nauthilus-director`.
The M8.2 Docker slice added the production image path and optional Docker proof
targets. The M8.3 systemd slice adds the host service unit, non-secret
environment template and optional offline unit verification target.

Production packaging is separate from `contrib/demo-stack/`. The demo stack is
an interoperability and operator-proof environment with its own topology,
entrypoints, TLS helpers and smoke scripts. It may later consume production
artifacts, but it is not the production deployment guide and does not define
the production image or host-install layout.

## Release Target Conventions

- Build and packaging references use Go 1.26.4.
- Production binaries are `cmd/nauthilus-director` and
  `cmd/nauthilus-directorctl`.
- `make build` and `make build-check` remain the binary build validation path.
- `make install` remains the binary and manpage install path unless a later M8
  slice adds explicit systemd or package install targets.
- Generated OpenAPI artifacts stay reproducible through `make check-openapi`.
- Generated config reference docs stay reproducible through `make docs-check`.
- `make check-packaging` performs static inventory checks and is safe inside
  `make guardrails` because it does not call Docker, systemd or host install
  tools.

## Artifact Ownership

| Artifact class | Owner path | Validation path | Guardrail status | Notes |
| --- | --- | --- | --- | --- |
| Production binaries | `cmd/nauthilus-director/`, `cmd/nauthilus-directorctl/`, `Makefile` | `make build-check`; `make build` for concrete binary output | In `make guardrails` through `build-check` | Binaries must build from the root production module with Go 1.26.4. |
| Host binary and manpage install | `Makefile`, `docs/man/` | `make install DESTDIR=<staging-dir>` when install layout changes | Outside normal guardrails | Install validation writes to a chosen staging directory. |
| Production Docker image | `packaging/docker/Dockerfile`, `packaging/docker/README.md`, `.dockerignore`, `Makefile` | `make check-packaging`; optional `make docker-build`; optional `make docker-smoke` | Static checks only in guardrails | Docker daemon proof stays optional and separate. |
| systemd service | `packaging/systemd/nauthilus-director.service`, `packaging/systemd/nauthilus-director.env.example`, `packaging/systemd/README.md` | `make check-packaging`; optional `make systemd-verify` | Static checks only in guardrails | Host systemd must not be required for normal guardrails. |
| Production config examples | `docs/config/nauthilus-director.target.yml`, `docs/reference/config-defaults.yaml`, `docs/reference/config-paths.md` | `make docs-check` | In `make guardrails` | Examples use file paths and redacted placeholders, not secret values. |
| REST contract and generated boundaries | `docs/specs/openapi/`, `internal/rest/generated/`, `internal/client/generated/` | `make check-openapi`; focused Go tests when handlers or clients change | In `make guardrails` | Generated DTOs remain at the REST and client boundary. |
| Operator deployment docs | `docs/operations/` | `make docs-check`; `make check-packaging` for inventory presence | In `make guardrails` | Runbooks should link to manpages and config docs instead of duplicating secrets. |
| Deterministic E2E proof | `test/e2e/` | `make e2e` | In `make guardrails` | Uses real binaries or test processes and public sockets. |
| Docker interoperability proof | `test/e2e/interop/` | `make e2e-interop` | Outside normal guardrails | Requires Docker-capable environments and stable skips when unavailable. |
| Demo stack | `contrib/demo-stack/` | Demo scripts under `contrib/demo-stack/scripts/` | Outside normal guardrails | Demo-only topology, TLS generation, entrypoints and sample credentials stay there. |
| Local scratch and prompts | `temp/` | Not staged or validated as production output | Outside guardrails | Ignored local planning material must not become packaging input. |

## Guardrail Boundary

The default guardrail lane may run static packaging checks, but it must not
require a Docker daemon, a systemd host, root privileges or host install paths.
Docker image builds, image smoke tests, `systemd-analyze verify`, service
installation and demo-stack public proofs are optional or environment-specific
checks with their own target names.

`scripts/check-packaging.sh` owns this boundary. It validates the production
Dockerfile and systemd unit statically, provided the script remains
host-independent.

## Makefile Target Map

| Target | Scope | Production artifact owner | Guardrail status |
| --- | --- | --- | --- |
| `make build` | Build `nauthilus-director` and `nauthilus-directorctl` into `bin/` | `cmd/`, `Makefile` | Outside guardrails; used for concrete local binaries |
| `make build-check` | Compile all production Go modules | `cmd/`, `internal/`, `tools/` | In guardrails |
| `make install` | Install binaries and manpages into a chosen prefix | `Makefile`, `docs/man/` | Outside guardrails |
| `make docs-check` | Verify generated config documentation is current | `docs/config/`, `docs/reference/` | In guardrails |
| `make check-openapi` | Verify generated OpenAPI server/client artifacts are current | `docs/specs/openapi/`, `internal/rest/generated/`, `internal/client/generated/` | In guardrails |
| `make check-packaging` | Verify the production packaging inventory and host-independent guardrail boundary | `packaging/`, `docs/operations/`, `scripts/check-packaging.sh` | In guardrails |
| `make e2e` | Run deterministic public-boundary E2E proof | `test/e2e/` | In guardrails |
| `make e2e-interop` | Run Docker-backed real interoperability proof when available | `test/e2e/interop/` | Outside guardrails |
| `make docker-build` | Build the production image when Docker is available | `packaging/docker/Dockerfile`, `.dockerignore`, `Makefile` | Outside guardrails |
| `make docker-smoke` | Build the production image, run both binaries with `--version` and assert default config redaction | `packaging/docker/Dockerfile`, `Makefile` | Outside guardrails |
| `make systemd-verify` | Verify the service file offline when `systemd-analyze` exists | `packaging/systemd/nauthilus-director.service`, `Makefile` | Outside guardrails |
