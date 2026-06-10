# Production Deployment Inventory

This document identifies the production delivery artifacts for
`nauthilus-director`. It covers binaries, Docker, systemd and the validation
boundary. Security, OIDC, reload, failure and migration workflows live in the
focused operations runbooks linked below.

## Current Production Artifacts

| Artifact | Path | Validation | Notes |
| --- | --- | --- | --- |
| Server binary | `cmd/nauthilus-director/` | `make build-check`; `make build` | Built from the root production module with Go 1.26.4. |
| Operator CLI | `cmd/nauthilus-directorctl/` | `make build-check`; `make build` | Uses the generated OpenAPI client boundary for REST transport. |
| Manpages | `docs/man/` | `make docs-check`; install staging with `make install DESTDIR=<staging-dir>` | Operator command and config references. |
| Target configuration | `docs/config/nauthilus-director.target.yml` | `make docs-check` | Target YAML shape with secret paths and redacted references only. |
| Generated config defaults and path reference | `docs/reference/config-defaults.yaml`, `docs/reference/config-paths.md` | `make docs-check` | Generated from typed defaults and config metadata. |
| REST contract and generated code | `docs/specs/openapi/`, `internal/rest/generated/`, `internal/client/generated/` | `make check-openapi` | Public REST DTOs and generated clients stay at the API boundary. |
| Deterministic E2E lane | `test/e2e/` | `make e2e` | Public-socket and REST/CLI proof without Docker-only dependencies. |
| Real interoperability lane | `test/e2e/interop/` | `make e2e-interop` | Docker-capable proof lane, intentionally outside normal guardrails. |
| Production packaging inventory | `packaging/` | `make check-packaging` | Static ownership and guardrail-boundary checks. |
| Production Docker image | `packaging/docker/Dockerfile`, `.dockerignore`, `packaging/docker/README.md` | `make check-packaging`; optional `make docker-build`; optional `make docker-smoke` | Hardened image path outside the demo stack. |
| systemd service | `packaging/systemd/nauthilus-director.service`, `packaging/systemd/README.md` | `make check-packaging`; optional `make systemd-verify` | Hardened host service layout outside the demo stack. |

## Operations Runbooks

| Topic | Document |
| --- | --- |
| Control-plane auth, protected config and pprof risk | [`security.md`](security.md) |
| Nauthilus OIDC caller auth and migration from Basic Auth | [`oidc-nauthilus.md`](oidc-nauthilus.md) |
| Safe reload, graceful shutdown and upgrade flow | [`reload-upgrade.md`](reload-upgrade.md) |
| Concrete failure symptoms and safe diagnostics | [`failure-modes.md`](failure-modes.md) |
| Runtime-only migration workflows | [`migration-workflows.md`](migration-workflows.md) |

## Demo Boundary

`contrib/demo-stack/` is the demo and interoperability environment. It owns
Compose topology, demo service configuration, demo TLS generation, demo
entrypoints and public proof scripts. Those files are intentionally not moved
into production packaging.

Production deployments should start from the production binaries, config
reference, `packaging/` artifacts and operations docs. The demo stack can prove
real interop behavior and may later consume the production image, but it is not
the supported production host layout.

## Guardrail Boundary

`make guardrails` remains Docker-independent and host-systemd-independent. It
may run static checks such as `make check-packaging`, but it must not build
containers, install services, call host service managers or require elevated
privileges.

Environment-specific checks belong to separate targets:

- Docker image build and smoke proof: `make docker-build` and
  `make docker-smoke`.
- systemd unit verification: `make systemd-verify`, which skips when
  `systemd-analyze` is unavailable.
- Demo public proof: `contrib/demo-stack/scripts/` on a Docker-capable host.
- Real interop proof: `make e2e-interop` on a Docker-capable host.

## Binary Deployment And Preflight

Build production binaries from the root module with Go 1.26.4:

```sh
make build
```

Install them through the Makefile or through the host packaging policy:

```sh
make install DESTDIR=/tmp/nauthilus-director-staging PREFIX=/usr/local
```

Before starting or upgrading a host, run a secret-safe preflight from the same
config and control address the service will use:

```sh
nauthilus-director --version
nauthilus-director --config /etc/nauthilus-director/nauthilus-director.yml config dump -d --format yaml
nauthilus-director --config /etc/nauthilus-director/nauthilus-director.yml config dump -n --format yaml
nauthilus-directorctl --version
nauthilus-directorctl --address http://127.0.0.1:9090 runtime summary
nauthilus-directorctl --address http://127.0.0.1:9090 route lookup --protocol imap --user alice@example.org --backend-pool imap-default
```

Add the configured bearer-token-file, TLS or mTLS flags required by the control
listener. Use protected config output only through an explicit and authorized
`--protected` request.

## Container Deployment

The production image is built from `packaging/docker/Dockerfile` with Go 1.26.4,
vendored dependencies and a `scratch` runtime image. It includes only
`nauthilus-director`, `nauthilus-directorctl`, CA trust roots, passwd/group
metadata and empty runtime directories. It runs as UID/GID `10001:10001`.

Build and smoke-test locally:

```sh
make docker-build
make docker-smoke
```

Both targets skip with a stable message when the Docker CLI or daemon is not
available. The smoke target verifies both `--version` commands and default
config redaction. They are not part of `make guardrails`.

The default container command is:

```text
nauthilus-director --config /etc/nauthilus-director/nauthilus-director.yml serve
```

Mount the production YAML configuration under `/etc/nauthilus-director/`.
Credential-bearing config paths should point to mounted files rather than
literal values. Typical secret-bearing files include backend password files,
bearer-token files, TLS private keys, client certificates and CA bundles. The
image must not contain default bearer tokens, private keys or deployment
passwords.

Recommended read-only runtime shape:

```sh
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --tmpfs /run/nauthilus-director:rw,noexec,nosuid,size=16m,uid=10001,gid=10001 \
  --mount type=bind,src=/etc/nauthilus-director,dst=/etc/nauthilus-director,readonly \
  nauthilus-director:dev
```

Adjust the image tag, config source path and port publishing for the target
environment. The control listener comes from
`runtime.servers.control.address`; the canonical default is
`127.0.0.1:9090`. Container deployments that need host access should bind an
explicit container address in the mounted config and publish only the intended
host interface.

Use the liveness and readiness endpoints from the REST contract for container
health probes:

```text
GET /healthz
GET /readyz
```

For operator status, use `nauthilus-directorctl status` from a trusted context
with the control API address and authentication expected by the mounted config.
See [`security.md`](security.md) for control authentication and protected
endpoint requirements.

## systemd Host Deployment

The production unit lives at
`packaging/systemd/nauthilus-director.service`. It assumes binaries installed
under `/usr/local/bin`, configuration under `/etc/nauthilus-director/` and a
dedicated `nauthilus-director` user and group. It starts:

```text
/usr/local/bin/nauthilus-director --config /etc/nauthilus-director/nauthilus-director.yml serve
```

It reloads through the public control-plane CLI:

```text
/usr/local/bin/nauthilus-directorctl --address http://127.0.0.1:9090 --timeout 10s reload
```

The reload command reaches the configured control listener and, after the
control-auth boundary is enforced, must satisfy the configured control
authentication mode. Static bearer tokens, mTLS material or OIDC control
tokens must be supplied through host-managed files or CLI options, not as
literal unit-file values.

Recommended host setup:

```sh
install -d -o root -g nauthilus-director -m 0750 /etc/nauthilus-director
install -m 0640 -o root -g nauthilus-director nauthilus-director.yml /etc/nauthilus-director/nauthilus-director.yml
install -m 0640 -o root -g nauthilus-director control-token /etc/nauthilus-director/control-token
install -m 0640 -o root -g nauthilus-director redis-password /etc/nauthilus-director/redis-password
install -m 0644 packaging/systemd/nauthilus-director.service /etc/systemd/system/nauthilus-director.service
```

Create the `nauthilus-director` user and group through the local operating
system policy before enabling the service. The service user needs read access
to the YAML file and configured secret files. It should not own the binaries or
the YAML configuration. The unit keeps `/etc/nauthilus-director` read-only in
the service namespace so runtime operations cannot rewrite YAML.

Optional non-secret placeholder paths can be placed in
`/etc/default/nauthilus-director` by copying
`packaging/systemd/nauthilus-director.env.example`. Use this only for values
such as `NAUTHILUS_DIRECTOR_REDIS_PASSWORD_FILE=/etc/nauthilus-director/redis-password`.
The secret bytes stay in the named files.

Start and inspect the service:

```sh
systemctl daemon-reload
systemctl enable --now nauthilus-director.service
systemctl status nauthilus-director.service
journalctl -u nauthilus-director.service
```

The unit logs to journald through stdout and stderr. It does not configure a
file log sink and does not need a writable log directory by default.

## Host Reload, Restart and Upgrade

Use reload for changes accepted by the safe-reload service:

```sh
systemctl reload nauthilus-director.service
```

`ExecReload` runs `nauthilus-directorctl reload`; it is not `SIGHUP`, and it
does not patch YAML. When reload is rejected, the existing process keeps
serving with its old accepted config snapshot. Operators should read the
control response and journal entry, fix the config or choose a restart when the
change is restart-required.

Safe reload currently accepts only config changes that have a live owner in the
running process:

- listener additions and removals; existing listener socket, TLS, authority,
  protocol and backend-pool settings remain restart-required
- `director.backends.*` changes for new sessions
- `director.backend_pools.*` changes validated against the current listener
  inventory

Existing frontend sessions, active affinities, backend pins and placement holds
are not moved or cleared by reload. New sessions use the accepted snapshot after
reload; already connected sessions keep their established backend/proxy objects
until normal close or an explicit operator drain, kick or shutdown action.

Restart is required for process-owned or security-sensitive config roots:
`runtime.*`, `auth.*`, `storage.redis.*`, `observability.*`,
`director.routing`, `director.affinity`, `director.runtime_overrides`,
`director.health`, `director.maintenance`, `director.security` and in-place
changes to existing `director.listeners.*` entries. Profile enablement is also
restart-scoped; safe reload rejects `observability.profiles` changes so pprof
routes and Go runtime samplers cannot appear through a partial reload.

Use restart for binary upgrades, service-user changes, listener privilege
changes, systemd hardening changes, file-permission changes and any config
class that safe reload reports as restart-required:

```sh
make build
install -m 0755 bin/nauthilus-director /usr/local/bin/nauthilus-director
install -m 0755 bin/nauthilus-directorctl /usr/local/bin/nauthilus-directorctl
systemctl restart nauthilus-director.service
nauthilus-directorctl --address http://127.0.0.1:9090 status
```

For rolling upgrades, drain or move users with the documented runtime control
commands before restart when the target node has active sessions. Those runtime
operations modify Redis-backed runtime state only; they do not rewrite YAML.
See [`reload-upgrade.md`](reload-upgrade.md) and
[`migration-workflows.md`](migration-workflows.md) for the full operator
sequence.

## systemd Overrides

The default unit does not request privileged-port capabilities. If a host binds
IMAP, POP3, LMTP or ManageSieve directly on ports below `1024`, add a drop-in:

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

If the control listener is not `http://127.0.0.1:9090`, keep reload on the
public CLI path and override `ExecReload`:

```ini
[Service]
ExecReload=
ExecReload=/usr/local/bin/nauthilus-directorctl --address https://127.0.0.1:9090 --timeout 10s reload
```

If deployment-specific local state is added later, grant only the required
paths:

```ini
[Service]
ReadWritePaths=/run/nauthilus-director /var/lib/nauthilus-director
```

Avoid broad write access to `/etc`, `/usr`, `/var` or home directories.

## Protected Diagnostics

Runtime pprof diagnostics are absent by default. Leave
`observability.profiles.pprof.enabled: false` for normal production operation.
When disabled, `/debug/pprof/*` returns `404` and does not challenge with an
implementation-specific diagnostics page.

When an incident requires profiles, enable pprof on the mounted config and
restart the process during a controlled window. Profile enablement is
restart-scoped; safe reload rejects `observability.profiles` changes because
the HTTP route set and Go runtime samplers are process-wide behavior.

Profile routes are mounted only on the control listener. They use the same
control-plane authentication as `/api/v1/*` and `/metrics`, then require
protected authorization. Static bearer and mTLS authentication provide ordinary
control access only unless a future typed policy explicitly grants protected
diagnostics. OIDC callers need the configured ordinary control scope and a
protected scope such as `nauthilus-director.protected`.

Enable only the profile classes needed for the incident:

| Path | Default | Operational note |
| --- | --- | --- |
| `observability.profiles.goroutine.enabled` | `false` | Exposes goroutine stacks when pprof is enabled. |
| `observability.profiles.block.enabled` | `false` | Enables Go block profiling and process-wide sampling overhead. |
| `observability.profiles.mutex.enabled` | `false` | Enables Go mutex contention profiling and process-wide sampling overhead. |

Profile payloads can contain stack frames, command-line arguments, memory
allocation paths, timing and contention detail. Treat collected profiles as
sensitive artifacts. Store them outside long-lived logs, restrict access to the
incident team and delete or expire them after the investigation. Do not paste
profile bodies into tickets, chat systems or public bug reports without a
separate review.

Diagnostic access records a bounded audit event with the route class, result,
auth method and actor context. The audit path does not record profile bodies,
authorization headers, bearer tokens, private keys, protected config values or
raw certificates. Metrics labels remain low-cardinality and do not include
actor identities, request IDs, profile payload values or raw runtime
identifiers.

## Secret Handling

Production documentation should name credential-bearing file paths only, such
as files under `/etc/nauthilus-director/`. It must not include bearer token
values, passwords, private keys, session secrets or raw authorization headers.
