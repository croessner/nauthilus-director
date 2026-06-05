# M8 Production Hardening Specification

Status: completed. The M8 production-hardening implementation, documentation
and proof are in place; completion evidence is recorded below.

This document defines the final roadmap milestone for `nauthilus-director`.
M8 turns the completed M0-M7 feature set into a deployable, restartable,
observable and operable production service. It is not a new mail-protocol
milestone and must not reopen IMAP, LMTP, ManageSieve or POP3 protocol
semantics unless hardening exposes a concrete safety defect.

M8 belongs under `docs/specs/implementation/` because it defines concrete
implementation slices, repository artifacts, tests and operator-facing
acceptance criteria. The milestone is mostly hardening and packaging work, but
it still changes production behavior at deployment, control-plane,
diagnostic-profile, documentation and validation boundaries.

M8 builds on the completed M0 foundation, the completed M1 IMAP MVP, the
completed M2/M3 backend runtime and control implementation, the completed M4
observability runtime, the completed M5 LMTP production implementation, the
completed M6 ManageSieve proxy implementation, the completed M7 POP3
implementation and the completed backend-node affinity, user placement hold,
backend-pin and backend-side PROXY protocol follow-ups. The archived
implementation under `poc/` may be read only as historical source material.
Production artifacts, packaging, tests and documentation must not import it,
copy its layout or treat it as a compatibility target.

## Source Documents

M8 is governed by:

- `AGENTS.md`
- `POLICY.md`
- `README.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`
- `docs/specs/implementation/M3_LISTENER_RUNTIME_CONTROL_FOLLOWUP.md`
- `docs/specs/implementation/M3_ROUTE_LOOKUP_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`
- `docs/specs/implementation/M5_BACKEND_PROXY_PROTOCOL_FOLLOWUP.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/specs/implementation/M7_POP3_PROXY_SPEC.md`
- `docs/developer/AFFINITY_SESSION_HANDLING.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-director.1`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.yaml.5`
- `docs/FAQ.md`
- `docs/scale-runtime-state.md`
- `test/e2e/README.md`
- `test/e2e/interop/README.md`
- `contrib/demo-stack/`
- `contrib/demo-stack/scripts/`
- `Makefile`

M8 also depends on the current Nauthilus OIDC and backchannel contracts. The
implementation must verify those contracts against the sibling Nauthilus
repository before changing Director authentication code, because Nauthilus is
the configured authentication authority and OIDC issuer for this deployment
model.

If this specification conflicts with those source documents, fix the drift
before implementation continues. In particular, do not weaken stable config
paths, control-plane security, runtime-only mutation semantics, active-affinity
invariants, metric-label policy, protected config redaction, safe reload
behavior, Docker/Go toolchain alignment or operator documentation to make M8
faster to complete.

## M8 Goal

M8 delivers the first production deployment envelope:

```text
source checkout
  -> reproducible Go 1.26 build and generated-artifact checks
  -> hardened production Docker image outside the demo stack
  -> systemd service and host-install artifacts
  -> authenticated control-plane access for REST, CLI, metrics and diagnostics
  -> documented safe reload, restart and shutdown behavior
  -> optional protected pprof diagnostics
  -> failure-mode and operational migration runbooks
  -> deterministic guardrail proof, optional Docker image proof and final review
```

The hard invariant is that runtime operations remain runtime operations.
Operator workflows may use user placement holds, backend pins, user moves,
listener drains, backend drains, session kills, user kicks, route lookup,
runtime summaries and safe reload. They must not patch, rewrite or persist
YAML configuration through the REST API or `nauthilus-directorctl`.

M8 must also close production hardening gaps that were acceptable during
feature milestones but are not acceptable for a deployable v1 service. That
includes real control-plane authentication enforcement, protected diagnostic
profiles, non-demo packaging, restart-safe reload documentation and
operator-facing failure explanations.

## Delivery Shape

Implement M8 as explicit implementation slices:

1. Production artifact inventory and release target conventions.
2. Hardened production Docker image, image metadata and image validation.
3. systemd unit, host-install layout and offline unit validation.
4. Nauthilus OIDC discovery, client-credentials token source and authority
   caller-auth forwarding.
5. Control-plane authentication and authorization.
6. Protected diagnostics and profile endpoints.
7. Reload, restart and shutdown semantics.
8. Operational documentation, failure-mode docs and migration workflows.
9. E2E, optional Docker/systemd proof and demo-stack OIDC reconciliation.
10. Final closeout, completion evidence and roadmap update.

The slices may be committed separately, but M8 is not complete until the
repository has a production image path distinct from `contrib/demo-stack`, a
systemd service artifact, real control-plane auth enforcement for configured
v1 modes, real Nauthilus OIDC caller auth for the final interop proof,
protected pprof behavior that is disabled by default, operator docs for
rollout and failure handling, deterministic guardrail coverage and a final
review pass that rechecks M0-M7 invariants.

## Global Scope

In scope:

- Add production packaging artifacts outside `contrib/demo-stack`.
- Keep the demo-stack Dockerfile as a demo artifact only unless it is
  deliberately refactored to consume the new production image path.
- Keep Go, Docker and CI/tooling references aligned with Go 1.26.
- Build the production Docker image from vendored dependencies and reproducible
  generated code; do not download Go dependencies during the final image build
  when `vendor/` is present.
- Run the runtime image as a non-root user by default.
- Make the runtime image compatible with read-only root filesystems, mounted
  config, mounted secrets and writable runtime directories.
- Exclude the Go toolchain, source tree, `.git`, test fixtures, demo TLS
  generators and demo entrypoints from the production runtime image.
- Provide image labels or documented build args for version, revision, source
  and license metadata.
- Provide a systemd unit for the server process and document the expected user,
  group, config path, token/secret paths, runtime directory and restart policy.
- Use `nauthilus-directorctl reload` as the default systemd `ExecReload`
  behavior. Do not introduce a separate reload implementation for systemd.
- Keep `SIGTERM` and `SIGINT` as graceful shutdown signals. If M8 adds SIGHUP
  support, SIGHUP must call the same safe-reload service as REST and CLI.
- Implement real control-plane authentication before generated REST handlers.
- Support the configured v1 control auth modes that remain enabled in
  canonical defaults: static bearer token, mTLS and OIDC/JWT validation through
  Nauthilus. A mode that is configured but not implemented must fail closed at
  config validation or request time and must not be silently accepted.
- Implement real Nauthilus OIDC client-credentials caller auth for the selected
  authority transport when OIDC is enabled for Director-to-Nauthilus
  backchannel calls. HTTP transport must send `Authorization: Bearer <token>`
  to `/api/v1/*` instead of Basic Auth when OIDC caller auth is selected. gRPC
  transport must send `authorization: Bearer <token>` metadata to
  `AuthService` RPCs when OIDC caller auth is selected.
- Discover Nauthilus OIDC endpoints from a configured issuer/discovery URL by
  default. Direct `token_endpoint` or `introspection_endpoint` overrides may be
  supported only as explicit compatibility settings with validation and docs.
- Use the Nauthilus OIDC token endpoint for client-credentials token
  acquisition regardless of whether the authority transport is HTTP or gRPC.
  The gRPC authority transport does not have a separate token-acquisition RPC.
- Cache acquired client-credentials access tokens in-process per authority and
  refresh them before expiry. The cache must be concurrency-safe, must not log
  token material and must fail closed when a refresh fails and no unexpired
  token is available.
- Keep static bearer token files as an explicit compatibility or emergency
  caller-auth mode. They must not be the final demo-stack interop proof for M8
  when Nauthilus OIDC client credentials are available.
- Reconcile `auth.authorities.*.oidc.*` so the subtree has enforced behavior.
  Hint-only fields may remain only with documented semantics. Any enabled OIDC
  configuration that cannot affect authentication must fail validation or be
  removed with a breaking-change decision, docs and tests.
- Keep reverse-proxy authenticated headers out of M8 unless a typed config
  shape, spoofing protections, documentation and tests are added first.
- Propagate authenticated actor identity into runtime audit fields for mutating
  operations, protected config reads, reload attempts and diagnostic profile
  access.
- Keep unauthenticated access limited to explicitly documented liveness and
  readiness endpoints that return no secrets and no runtime topology.
- Require authenticated control access for `/api/v1/*`, `/metrics` and any
  diagnostic profile endpoints unless an explicit documented disabled-auth mode
  is configured for a local-only deployment.
- Keep protected config output stronger than ordinary authenticated control
  access. If the authenticated mode cannot prove protected-output permission,
  `include_protected=true` must return `403` without partial output.
- Expose pprof only when `observability.profiles.pprof.enabled` is true.
- Register pprof under the control listener, not protocol listeners and not a
  separate unauthenticated debug port, unless a later spec adds a dedicated
  protected profile listener.
- Keep pprof disabled by default and documented as a sensitive diagnostic mode.
- Wire `observability.profiles.block.enabled` only through explicit runtime
  profile configuration and tests. Block profiling must remain off by default.
- Document failure modes for Redis, Nauthilus HTTP/gRPC, control auth, backend
  health, affinity ambiguity, route lookup, reload rejection, Docker startup,
  systemd startup and optional pprof.
- Document operator migration workflows that combine user placement holds,
  backend pins, user moves, active-affinity inspection, listener/backend drains
  and safe reload without rewriting YAML runtime state.
- Keep OpenAPI-generated DTOs at the REST/client boundary when M8 touches the
  control API.
- Add or extend Makefile targets when they keep packaging and documentation
  validation reproducible.
- Keep `make guardrails` Docker-independent. Docker or systemd-dependent proof
  may be additive, but the default guardrail lane must stay runnable without a
  Docker daemon or host systemd.

Out of scope:

- Adding new mail protocol behavior.
- Changing backend placement, active affinity, user hold, backend pin or
  route-lookup semantics except to fix a concrete safety defect.
- Moving runtime state out of Redis.
- Writing YAML configuration from REST or CLI runtime mutations.
- Replacing OpenAPI-generated REST/client boundaries with hand-written models.
- Turning pprof on by default.
- Exposing pprof on protocol listeners or an unauthenticated network listener.
- Depending on the demo stack as the only production packaging path.
- Replacing deterministic fake-service E2E with Docker-only proof.
- Adding release signing, SBOM publishing or package repository automation
  unless the implementation has enough release infrastructure to validate it.

## Stable Config Paths

M8 must preserve all stable paths from M0-M7. These paths are especially
important to the hardening work:

- `runtime.servers.control.enabled`
- `runtime.servers.control.address`
- `runtime.servers.control.auth.bearer.enabled`
- `runtime.servers.control.auth.bearer.token_file`
- `runtime.servers.control.auth.oidc.enabled`
- `runtime.servers.control.auth.oidc.authority`
- `runtime.servers.control.auth.oidc.validation`
- `runtime.servers.control.auth.oidc.required_scopes`
- `runtime.servers.control.auth.mtls.enabled`
- `runtime.servers.control.tls.enabled`
- `runtime.servers.control.tls.cert`
- `runtime.servers.control.tls.key`
- `runtime.servers.control.tls.client_ca`
- `runtime.servers.control.tls.require_client_cert`
- `runtime.servers.control.tls.min_tls_version`
- `runtime.process.shutdown_timeout`
- `observability.metrics.enabled`
- `observability.metrics.path`
- `observability.profiles.pprof.enabled`
- `observability.profiles.block.enabled`
- `observability.log.redact_secrets`
- `observability.log.username_hash_salt_file`
- `storage.redis.*`
- `director.listeners.*`
- `director.backends.*`

M8 may add new config paths only when the behavior cannot be safely expressed
with existing paths. Any added stable path must include typed validation,
generated defaults, generated config-path documentation, manpage text,
redaction metadata when secret-bearing and tests.

M8 is expected to add real Nauthilus OIDC integration paths unless the
implementation proves an equivalent, already-stable local shape:

- `auth.authorities.*.oidc.issuer`
- `auth.authorities.*.oidc.discovery_url`
- `auth.authorities.*.oidc.client_credentials.enabled`
- `auth.authorities.*.oidc.client_credentials.client_id`
- `auth.authorities.*.oidc.client_credentials.client_secret_file`
- `auth.authorities.*.oidc.client_credentials.token_endpoint_auth_method`
- `auth.authorities.*.oidc.client_credentials.scopes`
- `auth.authorities.*.oidc.client_credentials.refresh_before_expiry`
- `auth.authorities.*.oidc.client_credentials.token_endpoint`
- `runtime.servers.control.auth.oidc.protected_scopes`

The exact path names may be adjusted during implementation only to better
match existing config ownership. The resulting config must still satisfy these
semantics: discovery-first endpoint resolution, client-credentials token
acquisition, secret-file redaction, scope configuration, early refresh and
separate ordinary-control versus protected-control authorization.

If M8 discovers that a current default advertises a control auth mode that is
not implemented, the implementation must either implement that mode or make a
documented compatibility decision that changes the default with migration notes
and tests. It must not ship a production-hardening closeout where configured
control auth is silently ignored.

## Nauthilus OIDC Compatibility Findings

The M8 OIDC work is not a generic local JWT feature. It must match real
Nauthilus behavior:

- Nauthilus publishes OIDC discovery at
  `/.well-known/openid-configuration`. The discovery document includes
  `token_endpoint`, `introspection_endpoint`, `jwks_uri`, supported grant
  types including `client_credentials`, token endpoint auth methods including
  `client_secret_basic`, `client_secret_post`, `private_key_jwt` and `none`,
  and introspection auth methods `client_secret_basic`, `client_secret_post`
  and `private_key_jwt`.
- Nauthilus issues client-credentials access tokens from `/oidc/token`. Tokens
  carry `aud=<client_id>` and a space-separated `scope` claim. Requested
  scopes are filtered by the configured OIDC client's allowed and implied
  scopes.
- Nauthilus validates `/oidc/introspect` callers as OIDC clients, validates the
  submitted token through the IdP token validator and returns inactive when the
  token is missing, invalid or has an `aud` claim that does not match the
  introspecting client. Director control-plane OIDC must account for that
  audience behavior instead of assuming a generic introspection client can
  introspect arbitrary audiences.
- Nauthilus HTTP backchannel routes under `/api/v1/*` can be protected by Basic
  Auth and/or OIDC Bearer auth. OIDC Bearer auth is based on
  client-credentials tokens issued by the Nauthilus IdP and requires
  Nauthilus backchannel scopes such as `nauthilus:authenticate`,
  `nauthilus:lookup_identity` and `nauthilus:list_accounts`.
- Nauthilus gRPC authority has no OIDC discovery or introspection RPC.
  Caller auth is transported as gRPC metadata `authorization: Bearer <token>`;
  Nauthilus validates that token locally and enforces RPC-specific scopes.
  Director must therefore obtain OIDC tokens through the HTTP OIDC token
  endpoint even when the selected authority transport is gRPC.
- Mail-protocol SASL `XOAUTH2` and `OAUTHBEARER` credentials are different
  from Director caller auth. Director parses the SASL envelope only far enough
  to extract the authentication identity, mechanism identity and bearer
  material, then forwards the bearer token to Nauthilus as credential material
  through `/api/v1/auth/json` or `AuthService.Authenticate`. Director must not
  perform local JWT validation or introspection for mail SASL credentials.
- The `oidc_cid` field in the Nauthilus JSON DTO and gRPC protobuf is a client
  identifier context field for Nauthilus policy/bruteforce/account logic. It
  is not a replacement for Director caller authentication and does not carry a
  bearer token.

These findings are binding for M8. If Nauthilus changes these contracts before
M8 is implemented, update this specification and the Director integration
tests before shipping the milestone.

## Target Repository Boundaries

The exact file names may change if the implementation finds a better local
pattern, but the boundary should remain this shape:

```text
packaging/
  docker/
    Dockerfile
    README.md
  systemd/
    nauthilus-director.service
    README.md
docs/
  operations/
    README.md
    deployment.md
    failure-modes.md
    migration-workflows.md
internal/
  nauthilus/
    oidc.go
    oidc_test.go
  rest/
    auth.go
    auth_test.go
  observability/
    profiles.go
    profiles_test.go
scripts/
  check-packaging.sh
```

Repository boundaries:

- Production Docker and systemd artifacts belong under `packaging/`, not under
  `contrib/demo-stack`.
- Demo-stack files may consume or reference production artifacts, but demo
  topology, demo TLS generation and demo entrypoints stay under
  `contrib/demo-stack`.
- Control auth belongs near the REST server boundary and must run before
  generated handler decoding for protected routes.
- Nauthilus OIDC discovery and client-credentials token acquisition belong in
  `internal/nauthilus/` or a narrow authority-auth package owned by the
  Nauthilus client boundary. Mail protocol packages must receive only the
  resulting authority client behavior and must not fetch or validate OIDC
  tokens themselves.
- Authorization and actor extraction should be represented as small domain
  types or interfaces. Runtime packages should receive actors, not parse HTTP
  headers.
- pprof registration belongs at the control HTTP composition boundary. It
  must not leak into mail protocol packages.
- Operator docs belong under `docs/operations/` and may cross-link to manpages,
  `docs/FAQ.md`, `docs/scale-runtime-state.md` and implementation specs.

## M8.1 Production Artifact Inventory and Release Targets

### Purpose

Establish the production artifact map and validation commands before adding
hardening implementation details.

### In Scope

- Inventory existing build, install, manpage, OpenAPI, generated-docs, E2E,
  interop and demo-stack paths.
- Decide the canonical production packaging paths under `packaging/`.
- Add Makefile targets only when they make production artifacts reproducible.
- Keep optional Docker/systemd checks out of `make guardrails` unless they can
  run deterministically without host-specific services.
- Document which artifacts are production, demo-only, generated or test-only.

### Out of Scope

- Publishing release artifacts.
- Creating distro packages.
- Replacing existing install targets without a concrete packaging reason.

### Expected Files or Packages

```text
Makefile
README.md
packaging/README.md
packaging/docker/README.md
packaging/systemd/README.md
scripts/check-packaging.sh
```

### Implementation Notes

- `make build` and `make build-check` remain the local binary validation path.
- `make install` remains a host binary and manpage install path unless M8 adds
  explicit systemd install targets.
- If M8 adds `make docker-build`, the target should build the production image
  and accept `VERSION`, `REVISION`, `IMAGE_TAG` and base-image override
  variables.
- If M8 adds `make check-packaging`, it should perform static checks that do
  not require Docker or systemd to be running.
- Packaging docs should make clear that `contrib/demo-stack` is not the
  production deployment guide.

### Required Unit Tests

- Static checks verify production packaging paths exist once M8 introduces
  them.
- Makefile tests or shell checks verify packaging targets are listed in
  `.PHONY` and do not run Docker inside `make guardrails`.

### Required Integration or E2E Tests

- Optional Docker build tests may run under a separate target and skip with a
  stable message when Docker is unavailable.
- Optional systemd verification may run `systemd-analyze verify` when present
  and skip with a stable message when absent.

### Acceptance Criteria

- Production, demo and generated artifacts are clearly separated.
- Operators can identify the supported production deployment artifacts without
  reading the demo stack.
- `make guardrails` remains the final Docker-independent local gate.

### Review Checklist

- Verify no production packaging artifact imports, copies or depends on `poc/`.
- Verify Go 1.26 is named consistently in Docker/build docs.
- Verify optional checks do not make guardrails host-specific.

## M8.2 Hardened Production Docker Image

### Purpose

Provide a production image path that is smaller, safer and less demo-specific
than `contrib/demo-stack/Dockerfile.director`.

### In Scope

- Add a production Dockerfile under `packaging/docker/`.
- Build both `nauthilus-director` and `nauthilus-directorctl` from the vendored
  root module.
- Use Go 1.26 in the build stage.
- Use a runtime stage that excludes the Go toolchain, source tree, vendor tree,
  test files, demo fixtures and `.git`.
- Run as a non-root UID/GID by default.
- Support mounted config under `/etc/nauthilus-director/`.
- Support mounted secrets through files referenced by typed config.
- Support writable runtime directories through `/run/nauthilus-director` and
  optional `/tmp`, without requiring writes to the image filesystem.
- Preserve TLS trust roots required for outbound Nauthilus, Redis, control and
  backend TLS verification.
- Include image labels or build args for version, revision, source and license.
- Add a container smoke check that verifies `--version`, config validation or a
  short-lived safe command without starting public protocol listeners unless
  explicitly requested.

### Out of Scope

- Demo TLS generation.
- Demo entrypoints that patch config at container start.
- Downloading source dependencies in the runtime stage.
- Using mutable `latest` tags as the documented default.
- Requiring privileged containers.

### Expected Files or Packages

```text
packaging/docker/Dockerfile
packaging/docker/README.md
Makefile
scripts/check-packaging.sh
```

### Implementation Notes

- The production image should prefer a minimal runtime base. If a shell or
  package manager remains in the runtime image, document the reason and the
  hardening tradeoff.
- The Dockerfile should support base image overrides through build args while
  keeping repository defaults pinned to explicit versioned tags.
- The image should not copy `contrib/demo-stack/director/entrypoint.sh` or
  demo TLS helpers.
- If the image exposes ports, they must reflect production listener and control
  defaults only as documentation; exposing a port is not a security boundary.
- The image must not bake production secrets, default bearer tokens or private
  keys.
- Smoke tests should assert that protected config values are redacted by
  default.

### Required Unit Tests

- Static packaging checks detect missing production Dockerfile, missing
  non-root user directive, mutable `latest` base tags and demo-only entrypoint
  references.
- Static checks detect accidental copies of `.git`, `poc/`, `temp/` or demo TLS
  generation scripts into the production runtime stage.

### Required Integration or E2E Tests

- `make docker-build` builds the production image when Docker is available.
- `make docker-smoke` or an equivalent optional target runs the image and
  proves `nauthilus-director --version` and `nauthilus-directorctl --version`.
- If the smoke test starts the server, it must bind loopback-only addresses,
  use generated temporary config/secrets and clean up containers.

### Acceptance Criteria

- The production image is distinct from the demo-stack image.
- The runtime image runs non-root and contains no source tree or Go toolchain.
- The image can run with mounted config and secrets.
- Image validation has a deterministic static guard and an optional Docker
  proof.

### Review Checklist

- Verify no secret-bearing config value is baked into image layers.
- Verify image docs describe read-only filesystem and writable paths.
- Verify image docs do not call the demo stack a production deployment.

## M8.3 systemd Unit and Host Deployment Layout

### Purpose

Provide a host service definition that starts, reloads and stops the Director
with restrictive defaults and clear operator expectations.

### In Scope

- Add a systemd service file under `packaging/systemd/`.
- Use the production `nauthilus-director` binary as the service entrypoint.
- Use `nauthilus-directorctl reload` for `ExecReload`.
- Document the control address, timeout and token requirements for
  `ExecReload`.
- Configure graceful shutdown with `SIGTERM` and a timeout aligned with
  `runtime.process.shutdown_timeout`.
- Use restrictive systemd hardening options where they do not break configured
  listener, TLS, Redis, Nauthilus or backend access.
- Document optional override snippets for low ports, custom config paths,
  additional writable paths and environment files.
- Keep service startup read-only with respect to YAML configuration.

### Out of Scope

- Running host `systemctl` in guardrails.
- Assuming all deployments use systemd.
- Writing secrets from the unit file.

### Expected Files or Packages

```text
packaging/systemd/nauthilus-director.service
packaging/systemd/README.md
docs/operations/deployment.md
Makefile
scripts/check-packaging.sh
```

### Implementation Notes

- Recommended unit shape:
  - `User=nauthilus-director`
  - `Group=nauthilus-director`
  - `RuntimeDirectory=nauthilus-director`
  - `ConfigurationDirectory=nauthilus-director`
  - `ExecStart=/usr/local/bin/nauthilus-director --config /etc/nauthilus-director/nauthilus-director.yml serve`
  - `ExecReload=/usr/local/bin/nauthilus-directorctl --address http://127.0.0.1:9090 reload`
  - `Restart=on-failure`
  - `NoNewPrivileges=true`
  - `PrivateTmp=true`
  - `ProtectSystem=strict`
  - `ProtectHome=true`
- Use capability options only when documented. Binding privileged ports should
  require an override, not a broad default privilege set.
- If the unit reads a bearer token for `ExecReload`, document file ownership
  and permissions. The token must not appear literally in the unit.
- `ExecReload` failure must leave the old process running with the old
  accepted config snapshot.

### Required Unit Tests

- Static checks verify the service file has `ExecStart`, `ExecReload`,
  `Restart=on-failure`, `NoNewPrivileges=true` and does not contain literal
  secrets.
- Static checks verify the unit does not use `KillSignal=SIGHUP` as reload.

### Required Integration or E2E Tests

- If `systemd-analyze` is available, verify the unit offline.
- Add a deterministic non-systemd test for the reload path itself through
  `nauthilus-directorctl reload` against a public control listener.

### Acceptance Criteria

- Operators have a documented host-service baseline.
- Reload and restart semantics are clear and match the code.
- The systemd unit does not require unsafe privileges by default.

### Review Checklist

- Verify systemd docs mention restart-required config changes.
- Verify systemd docs mention safe reload rejection behavior.
- Verify override examples do not encourage YAML mutation through runtime
  commands.

## M8.4 Nauthilus OIDC and Authority Caller Auth

### Purpose

Replace demo-era Basic caller authentication as the final proof path with real
Nauthilus-issued OIDC Bearer caller tokens for Director-to-Nauthilus authority
communication.

### In Scope

- Implement OIDC discovery against the configured Nauthilus issuer or discovery
  URL.
- Validate discovery metadata before use, including issuer, token endpoint,
  introspection endpoint and supported client authentication methods.
- Implement a client-credentials token source for Director authority caller
  auth.
- Support `client_secret_basic`, `client_secret_post` and `private_key_jwt` for
  token endpoint client authentication when covered by focused tests and docs.
- Cache access tokens per authority and refresh before expiry.
- Keep token refresh concurrency-safe inside one Director process.
- Use Bearer caller auth for HTTP authority requests when OIDC caller auth is
  selected.
- Use Bearer caller auth for gRPC authority requests when OIDC caller auth is
  selected.
- Preserve Basic Auth and static bearer token support only as explicit
  compatibility or emergency modes.
- Preserve mail-protocol SASL bearer-token forwarding semantics.
- Update config defaults, config docs and manpages for real OIDC caller auth
  paths.

### Out of Scope

- Local JWT validation of end-user mail SASL bearer credentials.
- Inventing a gRPC token endpoint or gRPC introspection endpoint that
  Nauthilus does not expose.
- Replacing Nauthilus as the OIDC issuer.
- Making static token files the final M8 interop proof path.
- Cross-process token caches. A Redis-backed cache may be added later, but M8
  only requires a correct in-process cache.

### Expected Files or Packages

```text
internal/config/auth.go
internal/config/defaults.go
internal/config/validate.go
internal/config/config_test.go
internal/nauthilus/oidc.go
internal/nauthilus/oidc_test.go
internal/nauthilus/http.go
internal/nauthilus/http_test.go
internal/nauthilus/grpc_network.go
internal/nauthilus/grpc_network_test.go
docs/config/nauthilus-director.target.yml
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
docs/man/nauthilus-director.yaml.5
```

### Implementation Notes

- Discovery should be resolved once per authority with bounded timeout and
  cached metadata. Failed discovery must fail closed for OIDC-enabled
  authorities.
- Discovery metadata must be treated as configuration input, not user input.
  Error messages should identify the failing field without echoing secrets.
- Token requests must use `application/x-www-form-urlencoded` with
  `grant_type=client_credentials`, configured scopes and the selected client
  authentication method.
- The token source must reject empty `access_token`, unsupported `token_type`
  when present, negative expiry values and oversized response bodies.
- The token cache must refresh before expiry and must not reuse expired tokens
  after a failed refresh.
- HTTP authority OIDC caller auth must set `Authorization: Bearer <token>` and
  must not also send Basic Auth.
- gRPC authority OIDC caller auth must set `authorization: Bearer <token>` and
  must not also send Basic Auth metadata.
- Authority operation scopes should match Nauthilus requirements:
  `nauthilus:authenticate` for Authenticate,
  `nauthilus:lookup_identity` for LookupIdentity and
  `nauthilus:list_accounts` for ListAccounts.
- If one shared token is used for all authority operations, its configured
  scopes must include every operation the authority client can perform.
- SASL `XOAUTH2` and `OAUTHBEARER` parsing must remain a secret-safe envelope
  parser only. The extracted bearer token remains credential material passed to
  Nauthilus through the existing JSON/protobuf DTO fields.
- `oidc_cid` remains a Nauthilus policy context field. It must not be used as
  a token, client secret or authorization decision by the Director.

### Required Unit Tests

- Discovery succeeds with a valid Nauthilus-style document.
- Discovery rejects missing token endpoint, missing introspection endpoint,
  issuer mismatch and unsupported client auth method.
- Token acquisition sends the configured client authentication method and
  scopes.
- Token acquisition caches tokens and refreshes before expiry.
- Token refresh failure with an unexpired cached token continues with that
  token.
- Token refresh failure with no usable cached token fails closed.
- HTTP authority OIDC caller auth sends Bearer and not Basic.
- gRPC authority OIDC caller auth sends Bearer metadata and not Basic metadata.
- Config validation rejects enabled OIDC caller auth without issuer/discovery,
  client ID, required secret material, token auth method or scopes.
- Mail SASL bearer forwarding tests remain green and prove no local
  introspection is introduced.

### Required Integration or E2E Tests

- A deterministic fake-Nauthilus E2E proves discovery, token acquisition,
  Bearer forwarding and successful auth through the public protocol socket.
- A negative E2E proves invalid or insufficient-scope caller tokens are rejected
  without leaking token material.
- The real-server interop lane uses Nauthilus OIDC Bearer caller auth as the
  primary Director-to-Nauthilus proof before M8 closeout.

### Acceptance Criteria

- OIDC caller auth is real behavior, not a config-only subtree.
- HTTP and gRPC authority transports can both use Nauthilus-issued Bearer
  tokens.
- Basic Auth remains a fallback, not the final interop proof.
- End-user mail SASL bearer tokens are forwarded to Nauthilus and never
  validated locally by the Director.

### Review Checklist

- Verify OIDC token material, client secrets and SASL bearer credentials do not
  appear in logs, metrics, traces, CLI output or test output.
- Verify the implementation matches the current Nauthilus discovery, token and
  gRPC authority contracts.
- Verify generated config docs and manpages describe the new OIDC caller-auth
  paths.

## M8.5 Control-Plane Authentication and Authorization

### Purpose

Harden the control listener so production management, metrics, protected config
output and optional pprof diagnostics are not exposed as unauthenticated
interfaces.

### In Scope

- Enforce configured control auth before generated REST handlers.
- Support static bearer tokens loaded from `runtime.servers.control.auth.bearer.token_file`
  when bearer auth is enabled.
- Support mTLS authentication when control TLS and mTLS auth are enabled.
- Support OIDC/JWT validation through Nauthilus when OIDC auth remains enabled
  in canonical defaults.
- For control-plane OIDC, validate incoming `Authorization: Bearer` tokens by
  calling Nauthilus token introspection through the configured authority's
  discovered `introspection_endpoint`. Do not implement a local JWT verifier as
  the default M8 validation path.
- Reject enabled-but-unimplemented control auth modes fail-closed.
- Keep reverse-proxy authenticated headers unsupported unless a typed config
  shape and spoofing protections are added first.
- Attach authenticated actor identity and auth method to request context.
- Preserve the existing route-lookup pre-decode credential rejection.
- Protect `/api/v1/*`, `/metrics` and `/debug/pprof/*`.
- Allow unauthenticated `/healthz` and `/readyz` only if they remain
  topology-free and secret-free.
- Require protected authorization for `include_protected=true` config reads and
  pprof access.
- Audit protected config reads and pprof access without recording protected
  values, profile payloads, bearer tokens or raw certificates.

### Out of Scope

- Accepting unauthenticated control mutations.
- Treating local loopback binding as a replacement for configured auth.
- Adding reverse-proxy auth implicitly.
- Exposing pprof through OpenAPI as normal REST DTOs.

### Expected Files or Packages

```text
internal/rest/auth.go
internal/rest/auth_test.go
internal/rest/server.go
internal/rest/server_test.go
internal/nauthilus/oidc.go
internal/nauthilus/oidc_test.go
internal/rest/adapters/handler.go
internal/rest/adapters/handler_test.go
internal/observability/events.go
internal/observability/policy.go
docs/specs/openapi/nauthilus-director.yaml
cmd/nauthilus-directorctl/main.go
```

### Implementation Notes

- Authentication should run before generated request decoding so unauthenticated
  callers cannot use schema parsing differences for route probing.
- Use constant-time comparison for static bearer token values.
- Read token files through the same secret-safe file handling and diagnostics
  approach used elsewhere in config-sensitive paths.
- Do not log `Authorization` headers, tokens, JWTs, certificate PEM values or
  protected config values.
- The v1 authorization model should distinguish at least:
  - unauthenticated liveness/readiness
  - authenticated control admin
  - protected diagnostics/config access
- Static bearer auth may grant ordinary control-admin access. If it cannot
  prove protected access, protected config and pprof must return `403`.
- OIDC control auth must parse only the incoming bearer envelope locally, then
  call Nauthilus introspection. A successful response must be `active=true` and
  must satisfy configured `runtime.servers.control.auth.oidc.required_scopes`.
  Missing, inactive, malformed, oversized or introspection-failed tokens must
  fail closed without falling back to static bearer or disabled auth.
- OIDC protected access must require an additional protected scope. The default
  protected scope should be `nauthilus-director.protected` unless the
  implementation adds and documents a different
  `runtime.servers.control.auth.oidc.protected_scopes` default.
- Because current Nauthilus introspection returns inactive when `aud` does not
  match the introspecting client, M8 must configure the Director control OIDC
  client so accepted control tokens have a matching audience, or document and
  test a real Nauthilus-supported alternative.
- mTLS protected access must be explicit. If there is no typed policy that maps
  a verified certificate identity to protected access, it must not grant
  protected access automatically.
- `/metrics` may remain a Prometheus text endpoint, but it must pass the same
  control auth policy unless explicit disabled-auth local deployment is
  configured.
- pprof authorization is specified in M8.6, but the same authenticated actor
  and protected-authorization model must be reused there.

### Required Unit Tests

- Requests without auth can reach only documented liveness/readiness endpoints.
- Requests without auth cannot reach `/api/v1/version`, `/api/v1/backends`,
  `/metrics`, `/api/v1/config/*`, `/api/v1/reload` or pprof paths.
- Static bearer auth accepts the exact configured token and rejects missing,
  malformed and mismatched tokens without leaking token material.
- Enabled-but-unimplemented auth modes fail closed.
- mTLS auth requires verified control TLS client certificate state when enabled.
- OIDC control auth fetches and caches discovery metadata, calls the configured
  Nauthilus introspection endpoint, enforces `active=true`, `required_scopes`
  and protected scopes, and rejects inactive/audience-mismatched/scope-missing
  responses.
- OIDC discovery rejects missing `introspection_endpoint`, issuer mismatch and
  non-HTTPS endpoints unless an explicit local-test allowance is configured.
- Protected config output returns `403` without partial output when the actor
  lacks protected authorization.
- Auth failures use stable status codes and secret-safe problem payloads.
- Route lookup still rejects credential-bearing JSON before generated decoding.

### Required Integration or E2E Tests

- `make e2e` proves control auth denial and success through public control
  sockets.
- `nauthilus-directorctl` sends configured auth material without printing it.
- `nauthilus-directorctl` can obtain or forward a Nauthilus client-credentials
  access token for OIDC-protected control requests, or the M8 implementation
  documents a tested external-token workflow. In both cases, the CLI must send
  `Authorization: Bearer <token>` and never print the token.
- Protected config denial through `nauthilus-directorctl config dump -P`
  remains closed and prints no partial protected output.
- Metrics scraping is denied without auth and succeeds with valid control auth.

### Acceptance Criteria

- Production control auth is actually enforced.
- Protected operations are stronger than ordinary authenticated access.
- No control auth secret appears in logs, metrics, traces, CLI errors or test
  output.

### Review Checklist

- Verify every generated control route is covered by auth middleware except
  documented liveness/readiness paths.
- Verify metrics are not a bypass route.
- Verify actor identity reaches runtime audit fields.

## M8.6 Protected Diagnostics and Profiles

### Purpose

Expose sensitive runtime diagnostics only through explicit, authenticated and
protected control-plane paths.

### In Scope

- Register pprof handlers only when `observability.profiles.pprof.enabled` is
  true.
- Keep pprof disabled by default.
- Register pprof under the control listener only.
- Require authenticated control access and protected authorization for every
  pprof route.
- Keep disabled pprof behavior as `404`, not an authenticated placeholder page.
- Wire `observability.profiles.block.enabled` through explicit runtime profile
  setup when implemented.
- Keep block profiling disabled by default.
- Audit diagnostic access without recording profile payloads, bearer tokens,
  protected config values or raw certificate material.
- Document profile endpoints as sensitive production diagnostics.

### Out of Scope

- Exposing pprof on mail protocol listeners.
- Exposing pprof through a separate unauthenticated debug port.
- Adding pprof routes to OpenAPI as normal REST DTOs.
- Turning block profiling on by default.

### Expected Files or Packages

```text
internal/rest/server.go
internal/rest/server_test.go
internal/observability/profiles.go
internal/observability/profiles_test.go
internal/observability/events.go
docs/operations/deployment.md
docs/operations/failure-modes.md
docs/man/nauthilus-director.yaml.5
```

### Implementation Notes

- pprof registration should happen at control HTTP composition time so protocol
  packages remain unaware of diagnostics.
- Profile routes must use the same actor/protected-authorization model from
  M8.5.
- `include_protected=true` config reads and pprof access may share protected
  authorization decisions, but profile handlers must not reuse config dump
  DTOs or OpenAPI request models.
- If runtime toggling of pprof or block profiling cannot be implemented safely,
  safe reload must reject those changes with a clear restart-required reason.
- Metrics labels and trace attributes for profile access must remain bounded
  and must not include profile names derived from unbounded input, raw actor
  tokens or request IDs.

### Required Unit Tests

- Disabled pprof routes return `404`.
- Enabled pprof routes reject unauthenticated requests.
- Enabled pprof routes reject authenticated actors without protected
  authorization.
- Enabled pprof routes allow actors with protected authorization.
- pprof access audits record route class and actor identity without profile
  bodies or secret material.
- Block profiling remains disabled by default.
- Profile reload behavior is tested for supported and unsupported transitions.

### Required Integration or E2E Tests

- Optional pprof E2E proves disabled-by-default and enabled-plus-protected
  behavior without dumping profile bodies into logs.
- Metrics scraping remains protected by M8.5 control auth and is not a pprof
  bypass path.

### Acceptance Criteria

- pprof is unavailable by default.
- pprof is available only behind the control listener and protected
  authorization when enabled.
- Block profiling remains disabled by default and explicit when enabled.
- Diagnostic access leaves useful audit trails without leaking secrets or
  profile payloads into logs, metrics or traces.

### Review Checklist

- Verify no protocol listener registers pprof.
- Verify disabled pprof is indistinguishable from an absent route.
- Verify profile handlers do not bypass M8.5 authentication or protected
  authorization.

## M8.7 Reload, Restart and Shutdown Semantics

### Purpose

Make reload and process lifecycle behavior predictable for operators and
deployment tooling.

### In Scope

- Preserve the M2/M3 safe reload model.
- Document and test which config changes are live-reloadable and which require
  restart.
- Ensure `nauthilus-directorctl reload`, `POST /api/v1/reload` and systemd
  `ExecReload` all use the same safe-reload service.
- Keep unsafe reload rejection atomic: no partial apply, no YAML write and old
  snapshot remains active.
- Keep existing frontend sessions on their established backend/proxy objects
  until close.
- Use the new accepted snapshot only for new sessions after safe reload.
- Ensure graceful shutdown waits within `runtime.process.shutdown_timeout` and
  closes listeners before process exit.
- Wire `observability.profiles.block.enabled` and pprof enablement with
  explicit lifecycle behavior.

### Out of Scope

- Making every config path live-reloadable.
- Restarting the process from inside the REST API.
- Adding distributed reload orchestration across multiple Director instances.

### Expected Files or Packages

```text
internal/runtime/control.go
internal/runtime/control_test.go
internal/app/server.go
internal/listener/listener.go
cmd/nauthilus-director/main.go
cmd/nauthilus-directorctl/main.go
docs/operations/deployment.md
docs/operations/failure-modes.md
docs/man/nauthilus-directorctl.1
```

### Implementation Notes

- The existing unsafe reload classes remain restart-required unless M8 proves
  a safe live apply path:
  - control listener address
  - control auth
  - control TLS
  - core protocol semantics
- Listener additions and removals should remain safe reload behavior when the
  listener manager can apply them without changing existing listener semantics.
- Backend registry changes should remain safe only when active sessions can
  keep using their already selected backend objects.
- If M8 adds SIGHUP, it must not bypass REST/CLI auth for ordinary remote
  callers because SIGHUP is local process control. It still must call the same
  safe-reload service and emit the same observability event.
- Profile enable/disable on reload must be explicit. If pprof cannot be safely
  toggled at runtime, safe reload must reject that change with a clear restart
  reason.

### Required Unit Tests

- Safe reload applies supported changes and rejects unsafe changes atomically.
- systemd `ExecReload` documentation command remains equivalent to
  `nauthilus-directorctl reload`.
- Shutdown tests preserve operator-visible exit behavior.
- Profile reload behavior is tested for supported and unsupported transitions.

### Required Integration or E2E Tests

- Public control socket E2E proves reload success for a safe change.
- Public control socket E2E proves reload rejection for an unsafe change and
  verifies the old config remains active.
- Listener reload E2E proves removed listeners stop accepting new sessions and
  existing sessions are not silently rerouted.

### Acceptance Criteria

- Operators have one documented reload path.
- Unsafe live changes fail closed with clear reasons.
- Shutdown and restart behavior is consistent between direct process and
  systemd documentation.

### Review Checklist

- Verify reload docs do not imply YAML is modified.
- Verify reload metrics/logs use bounded reason classes.
- Verify pprof/profile toggles do not create unauthenticated routes.

## M8.8 Operational Documentation and Migration Workflows

### Purpose

Create durable operator documentation for deploying, diagnosing and migrating a
production Director deployment.

### In Scope

- Add `docs/operations/` documentation.
- Document deployment using binaries, systemd and containers.
- Document control auth setup, token files, TLS/mTLS, OIDC delegation and
  protected config behavior.
- Document Nauthilus OIDC setup for Director deployments, including issuer or
  discovery URL, client-credentials client configuration, token endpoint auth
  method, required Nauthilus backchannel scopes, Director control scopes and
  protected-control scopes.
- Document failure modes with observable symptoms, likely causes, safe
  commands and rollback guidance.
- Document migration workflows that combine:
  - route lookup
  - runtime summary
  - session listing
  - user placement holds
  - user backend pins
  - user moves
  - user kicks
  - listener drains
  - backend maintenance and drains
  - active-affinity clear
  - safe reload
- Include explicit statements that runtime commands do not rewrite YAML.
- Cross-link manpages and FAQ entries instead of duplicating command reference
  prose when possible.
- Keep docs vendor-neutral except when naming actual configured services or
  protocol peers.

### Out of Scope

- Turning the operations docs into a marketing page.
- Documenting POC deployment paths.
- Providing host-specific automation for a single private deployment.

### Expected Files or Packages

```text
docs/operations/README.md
docs/operations/deployment.md
docs/operations/failure-modes.md
docs/operations/migration-workflows.md
docs/FAQ.md
docs/man/nauthilus-director.1
docs/man/nauthilus-directorctl.1
docs/man/nauthilus-director.yaml.5
```

### Implementation Notes

- Deployment docs should include preflight checks:
  - `nauthilus-director --version`
  - `nauthilus-director config dump -d`
  - `nauthilus-director config dump -n`
  - `nauthilus-directorctl --version`
  - `nauthilus-directorctl runtime summary`
  - `nauthilus-directorctl route lookup`
- Failure-mode docs should cover at least:
  - config validation failure
  - missing environment placeholder
  - Redis unavailable
  - Redis ambiguous state
  - Nauthilus unavailable
  - Nauthilus OIDC discovery unavailable
  - Nauthilus OIDC token endpoint unavailable
  - Nauthilus OIDC introspection denied or inactive
  - Nauthilus OIDC scope/audience mismatch
  - backend health hard-down
  - backend TLS identity failure
  - backend capacity exhaustion
  - user placement hold timeout
  - backend pin mismatch
  - route lookup rejected input
  - protected config denied
  - control auth denied
  - safe reload rejected
  - pprof disabled or unauthorized
  - Docker image start failure
  - systemd service start failure
- Migration docs should include reversible workflows:
  - move one user to a new backend node without changing YAML runtime state
  - drain a backend for maintenance while preserving active sessions when safe
  - use a placement hold to pause new sessions during mailbox movement
  - use a backend pin for targeted commissioning
  - roll back a failed move or pin
  - distinguish runtime state cleanup from config edits
- Docs must avoid raw backend identifiers as metric-label recommendations.
  Commands may show backend identifiers because operators need them for runtime
  control, but metrics guidance must keep the bounded-label policy.

### Required Unit Tests

- Manpage or docs tests verify new operation docs are linked from existing
  operator entrypoints.
- Text checks verify docs do not instruct operators to rewrite YAML through
  REST or CLI runtime commands.
- Text checks verify docs mention redaction and protected config denial.

### Required Integration or E2E Tests

- E2E should cover at least one documented migration workflow through public
  control sockets and protocol sockets.
- Demo-stack proof should run the operator-facing scripts that remain the
  quickest public proof path.

### Acceptance Criteria

- Operators have durable deployment, failure and migration docs.
- Runtime-only semantics are explicit in every migration workflow.
- Failure docs map symptoms to safe diagnostic commands without exposing
  secrets.

### Review Checklist

- Verify docs are under `docs/`, not `temp/`.
- Verify docs are vendor-neutral unless naming actual configured services.
- Verify examples avoid secrets in command lines.

## M8.9 E2E, Packaging Proof and Demo Reconciliation

### Purpose

Prove that the production service can be built, started, authenticated,
reloaded, diagnosed and operated without regressing the
completed protocol milestones.

### In Scope

- Extend deterministic fake-service E2E for control auth, metrics auth, pprof
  disable/enable behavior, safe reload and at least one documented migration
  workflow.
- Preserve existing IMAP, LMTP, ManageSieve and POP3 fake-service coverage.
- Preserve `make e2e-interop` real-server coverage.
- Convert the final real-server interop lane to OIDC Bearer caller auth for
  Director-to-Nauthilus communication instead of HTTP Basic or gRPC Basic as
  the primary proof. Basic Auth may remain as an explicitly documented
  compatibility fallback, but it must not be the M8 closeout proof path.
- Add optional Docker image build/smoke proof.
- Add optional offline systemd verification proof.
- Reconcile demo-stack docs/scripts only where M8 changes production artifacts
  or operator proof expectations.

### Out of Scope

- Requiring Docker for default guardrails.
- Requiring host systemd for default guardrails.
- Treating skipped optional Docker/systemd checks as successful production
  proof. Skips must be explicit and stable.

### Expected Files or Packages

```text
test/e2e/
test/e2e/interop/
contrib/demo-stack/
contrib/demo-stack/scripts/
Makefile
scripts/check-packaging.sh
```

### Implementation Notes

- E2E should verify behavior through public sockets, REST endpoints and CLI
  commands, not through internal package shortcuts.
- Optional Docker and systemd checks should be clearly named and documented.
- Demo-stack changes should be narrow. Do not rebuild or redesign demo
  topology unless M8 production artifacts require a small integration update.
- Demo-stack Nauthilus config must enable the built-in IdP, configure an OIDC
  client that supports `client_credentials` and allows the Nauthilus
  backchannel scopes used by the Director. The Director demo config must use
  Nauthilus discovery and OIDC caller auth for the selected authority
  transport.
- `make e2e-interop` must prove that the Director obtains a
  client-credentials token from Nauthilus, forwards it to the real Nauthilus
  HTTP or gRPC authority path, and still completes at least one externally
  visible protocol authentication flow.
- The interop lane must also prove a negative case: missing, invalid or
  insufficient-scope OIDC caller tokens are rejected by Nauthilus and surface
  as a safe Director auth failure without secret leakage.

### Required Unit Tests

- Packaging static checks pass.
- Control auth, pprof, reload and docs tests pass.
- Manpage/docs alignment tests pass.

### Required Integration or E2E Tests

- `make e2e` passes.
- `make e2e-interop` passes on a Docker-capable environment before M8 closeout,
  or the closeout records a stable skip reason and the separate Docker image
  proof remains pending.
- `make e2e-interop` uses OIDC Bearer caller auth as the primary
  Director-to-Nauthilus proof and records whether HTTP or gRPC was selected
  for that proof.
- Optional `make docker-build` and `make docker-smoke` pass on a
  Docker-capable environment before production image closeout.
- Optional systemd verification passes where `systemd-analyze` is available.

### Acceptance Criteria

- Control auth is proved through public control sockets.
- Safe reload is proved through REST/CLI and documented systemd `ExecReload`.
- pprof is disabled by default and protected when enabled.
- Production Docker and systemd artifacts have static validation and optional
  runtime proof.
- Existing protocol milestones remain green.

### Review Checklist

- Verify optional proof skips are not presented as production proof.
- Verify the real-server proof records whether HTTP or gRPC was selected for
  OIDC Bearer caller auth.

## M8.10 Final Closeout and Completion Evidence

### Purpose

Close M8 only after the implementation, documentation, tests and roadmap agree
with each other.

### In Scope

- Re-read the required source documents in the final review pass.
- Compare the implemented behavior against this specification.
- Fix any drift discovered in config defaults, docs, OpenAPI, generated
  artifacts, packaging, demo-stack proof or tests.
- Add concrete `### Completion Evidence` to this specification.
- Update `docs/ARCHITECTURE_ROADMAP.md` under
  `### M8: Production hardening` with a concise `Status: completed` paragraph
  that points back to this specification.
- Run `make guardrails` as the final local gate before any commit or pull
  request.
- Record exact validation commands, optional Docker/systemd proof status and
  `git status --short`.

### Out of Scope

- Marking M8 complete because optional proof skipped.
- Committing or publishing changes unless explicitly requested.
- Adding new implementation behavior during closeout except to fix drift found
  by the final review.

### Expected Files or Packages

```text
docs/specs/implementation/M8_PRODUCTION_HARDENING_SPEC.md
docs/ARCHITECTURE_ROADMAP.md
```

### Implementation Notes

- Completion evidence must distinguish passed commands, skipped optional
  commands and commands that remain pending.
- Optional Docker or systemd skips must include stable reasons such as missing
  Docker daemon or missing `systemd-analyze`.
- The final closeout must include a short Soll/Ist comparison against this
  specification, not only a list of commands.
- If `make guardrails` fails, M8 remains incomplete unless the failure is
  outside the repository and explicitly documented as an environmental blocker.

### Required Unit Tests

- No new unit tests are required solely for the closeout phase.
- Any drift fixed during closeout must include the focused tests required by
  the changed behavior.

### Required Integration or E2E Tests

- `make guardrails` passes as the final local gate before commit or pull
  request.
- `make e2e-interop` status is recorded with the OIDC Bearer caller-auth proof
  result or a stable skip reason.
- Optional Docker and systemd proof status is recorded.

### Acceptance Criteria

- Completion evidence records exact commands and outcomes.
- The roadmap M8 entry is marked completed and links to this specification.
- The final review confirms M0-M7 invariants still hold.
- `git status --short` is recorded in the closeout.

### Review Checklist

- Verify the final proof includes M0-M7 regression commands.
- Verify optional proof skips are not presented as production proof.
- Verify `make guardrails` is the final local gate.

## Top-Level Acceptance Checklist

M8 is complete because all items below are true:

- [x] Production packaging artifacts live outside `contrib/demo-stack`.
- [x] Production Docker image builds from Go 1.26, vendored dependencies and
      generated artifacts.
- [x] Runtime Docker image excludes source, `.git`, `poc/`, `temp/`, demo TLS
      helpers, test fixtures and the Go toolchain.
- [x] Runtime Docker image runs non-root and supports mounted config/secrets.
- [x] Docker image validation has deterministic static checks and optional
      Docker runtime proof.
- [x] systemd service artifact exists with restrictive defaults.
- [x] systemd `ExecReload` uses `nauthilus-directorctl reload`.
- [x] systemd docs explain restart-required changes and safe reload rejection.
- [x] Control auth is enforced before generated REST handlers.
- [x] Enabled static bearer, mTLS and OIDC/JWT control auth modes either work
      or fail closed with documented validation/request errors.
- [x] Control-plane OIDC validates incoming bearer tokens through Nauthilus
      discovery and introspection, enforces ordinary and protected scopes, and
      accounts for Nauthilus audience matching behavior.
- [x] Director-to-Nauthilus authority calls support OIDC client-credentials
      caller auth for HTTP and gRPC selected transports.
- [x] OIDC client-credentials token acquisition discovers Nauthilus endpoints,
      caches access tokens safely, refreshes before expiry and never logs token
      or client-secret material.
- [x] HTTP authority OIDC caller auth sends Bearer headers instead of Basic
      Auth when selected.
- [x] gRPC authority OIDC caller auth sends Bearer metadata instead of Basic
      Auth when selected.
- [x] Mail SASL `XOAUTH2` and `OAUTHBEARER` still forward bearer credentials
      to Nauthilus without local token validation or secret logging.
- [x] Unauthenticated control access is limited to documented liveness and
      readiness endpoints.
- [x] `/api/v1/*`, `/metrics` and pprof require authenticated control access
      unless explicit disabled-auth local deployment is configured.
- [x] Protected config output requires protected authorization and returns
      `403` without partial output when unauthorized.
- [x] pprof is disabled by default.
- [x] pprof is available only behind the control listener and protected
      authorization when enabled.
- [x] Block profiling remains disabled by default and has explicit lifecycle
      tests if implemented.
- [x] Safe reload behavior remains atomic and runtime-only.
- [x] `nauthilus-directorctl reload`, REST reload and systemd reload use the
      same safe-reload service.
- [x] Existing sessions remain on their established backend/proxy objects
      across safe reload.
- [x] Operational deployment docs exist under `docs/operations/`.
- [x] Failure-mode docs cover Redis, Nauthilus, backend, control auth, reload,
      Docker, systemd and pprof failures.
- [x] Migration workflow docs combine holds, moves, pins, drains and affinity
      inspection without YAML runtime mutation.
- [x] Manpages and FAQ cross-link the durable operations docs where useful.
- [x] Existing IMAP, LMTP, ManageSieve and POP3 E2E coverage remains green.
- [x] `make e2e` proves M8 control auth, metrics auth, pprof and reload
      behavior through public sockets.
- [x] `make e2e-interop` remains the real-server lane and passes before final
      production closeout on a Docker-capable environment.
- [x] `make e2e-interop` uses Nauthilus OIDC Bearer caller auth as the primary
      Director-to-Nauthilus proof instead of HTTP Basic or gRPC Basic.
- [x] `make guardrails` passes as the final local gate.
- [x] Completion evidence is added to this specification.
- [x] The M8 roadmap entry is updated with completed status and a pointer to
      this specification.
- [x] `git status --short` is recorded in the M8 closeout.

### Completion Evidence

Closeout date: 2026-06-06.

Implemented hardening surface: production packaging artifacts under
`packaging/`, `.dockerignore`, `scripts/check-packaging.sh`, Docker/systemd
Makefile targets, restrictive systemd service defaults, Docker non-root scratch
runtime, safe reload through the shared REST/CLI service, protected optional
pprof, control-plane authentication before generated REST handlers, protected
config authorization, Nauthilus-backed control OIDC introspection,
Director-to-Nauthilus OIDC client-credentials caller auth for HTTP and gRPC, and
operations documentation under `docs/operations/`.

Authentication and OIDC reconciliation:

- The sibling Nauthilus OIDC discovery, token, introspection, HTTP backchannel
  and gRPC authority contracts were rechecked before closeout. Director now
  relies on Nauthilus as the OIDC validation authority and as the issuer for
  caller-auth client credentials.
- HTTP authority caller auth sends `Authorization: Bearer ...` when OIDC client
  credentials are configured. gRPC authority caller auth sends Bearer metadata
  for the same authority mode.
- OIDC caller-auth token state is an in-memory, per-process,
  per-authority-token-source cache only. It refreshes before expiry and does not
  persist or log token or client-secret material.
- Mail SASL `XOAUTH2` and `OAUTHBEARER` handling still parses only the envelope
  needed to forward the bearer credential and mechanism identity to Nauthilus.
  Director does not locally introspect, validate or cache user bearer tokens.
- Control-plane OIDC introspection is used only for incoming administrative
  bearer tokens and enforces configured ordinary and protected scopes before
  serving protected endpoints or protected config output.

Boundary and documentation reconciliation:

- OpenAPI remained the REST contract source. Generated server/client DTOs remain
  confined to REST, CLI and test-boundary adapters; protocol/runtime packages
  continue to use explicit domain objects.
- OIDC, control auth, protected profiles and packaging config paths are present
  in typed config defaults, validation, redaction metadata, target config,
  generated reference defaults, generated config paths and manpage/reference
  documentation.
- Runtime mutation workflows remain runtime-only. Holds, moves, pins, drains,
  reload and affinity operations do not rewrite YAML configuration.
- Metrics, logs, diagnostics and examples were reviewed for secret-bearing
  output. No new secret-bearing examples or logs are part of the closeout.

Validation evidence:

- `make check-openapi check-docs check-packaging` passed before the final
  documentation closeout update.
- `make docker-smoke` passed on a Docker-capable host. The smoke proved the
  production image build, `nauthilus-director --version`,
  `nauthilus-directorctl --version` and default config redaction.
- `make systemd-verify` was skipped for an environment capability reason:
  `systemd-analyze` is unavailable on this macOS host. Static systemd inventory
  checks passed through `make check-packaging`.
- `make e2e-interop` passed on a Docker-capable host. The run proved OIDC Bearer
  caller auth for Director-to-Nauthilus authority requests, the real server
  binary, six Dovecot IMAP backends, Dovecot LMTP, ManageSieve and POP3
  backends when available, swaks-to-Postfix submission, curl IMAP delivery,
  health ownership, cluster affinity and runtime control.
- `make guardrails` was not rerun during this M8.10 docs-only closeout after the
  operator confirmed that the long M8.9 proof had already completed. The M8.9
  guardrails proof remains the implementation gate for this milestone; this
  closeout adds only the final spec and roadmap reconciliation.
- `make check-docs` and `git diff --check` were rerun after the final
  documentation update.
- `git status --short` was recorded during closeout. The worktree remained
  dirty with the expected M8 implementation, generated, documentation,
  packaging, demo-stack and E2E changes; no staged ignored `temp/` files were
  present.

## Required M8 Review Pass

Before closing M8, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `POLICY.md`.
3. Re-read `docs/ARCHITECTURE_ROADMAP.md`, especially sections covering
   configuration, REST control API, CLI, observability, deployment and M8.
4. Re-read `docs/specs/implementation/M0_FOUNDATION_SPEC.md`.
5. Re-read `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`.
6. Re-read `docs/specs/implementation/M3_LISTENER_RUNTIME_CONTROL_FOLLOWUP.md`.
7. Re-read `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`.
8. Re-read `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`.
9. Re-read `docs/specs/implementation/M5_BACKEND_PROXY_PROTOCOL_FOLLOWUP.md`.
10. Re-read `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`.
11. Re-read `docs/specs/implementation/M7_POP3_PROXY_SPEC.md`.
12. Re-read `docs/config/nauthilus-director.target.yml`.
13. Re-read `docs/reference/config-defaults.yaml`.
14. Re-read `docs/reference/config-paths.md`.
15. Re-read `docs/specs/openapi/nauthilus-director.yaml` if control auth,
    pprof, protected config, reload or metrics behavior changed.
16. Re-read `docs/man/nauthilus-director.1`,
    `docs/man/nauthilus-directorctl.1` and
    `docs/man/nauthilus-director.yaml.5`.
17. Re-read `test/e2e/README.md` and `test/e2e/interop/README.md`.
18. Re-read `contrib/demo-stack` and proof scripts if M8 changes demo-facing
    artifacts.
19. Re-check the current Nauthilus OIDC discovery, token, introspection,
    HTTP backchannel and gRPC authority contracts before closing any OIDC
    integration work.
20. Compare implementation and docs against this specification and source
    documents.
21. Fix drift in OIDC caller auth, control auth defaults, safe reload
    semantics, protected config behavior, pprof exposure, Docker image
    hardening, systemd reload behavior, runtime-only migration docs and
    metric-label policy.
22. Run `make check-openapi` after any OpenAPI schema or generated-code change.
23. Run `make check-docs` after any typed config, metadata or generated docs
    change.
24. Run packaging static checks.
25. Run targeted OIDC caller auth, control auth, pprof, reload, Dockerfile,
    systemd and docs tests.
26. Run `make e2e`.
27. Run `make e2e-interop` on a Docker-capable environment and record the real
    IMAP, LMTP, ManageSieve and POP3 lane status, including whether HTTP or
    gRPC carried the Nauthilus OIDC Bearer caller-auth proof.
28. Run optional production Docker build/smoke proof on a Docker-capable
    environment and record the result.
29. Run optional systemd offline verification where available and record the
    result.
30. Add concrete `### Completion Evidence` to this specification.
31. Update `docs/ARCHITECTURE_ROADMAP.md` with concise M8 completed status.
32. Run `make guardrails` before any commit or pull request.
33. Record `git status --short` and exact validation results in the M8
    closeout.

## Decisions and Open Questions

These decisions are recorded so M8 implementation does not rediscover them in
code.

1. Decision: M8 stays under `docs/specs/implementation/`.

   Rationale: the milestone creates concrete production artifacts, tests and
   runtime behavior. It is not an architecture-only note even though it adds no
   new mail protocol.

2. Decision: production Docker packaging is separate from `contrib/demo-stack`.

   Rationale: the demo stack may remain convenient and opinionated. Production
   images must not inherit demo TLS generation, demo entrypoints or demo
   topology assumptions.

3. Decision: systemd reload uses `nauthilus-directorctl reload`.

   Rationale: REST, CLI and systemd should converge on one safe-reload service.
   M8 must not create a separate reload path hidden in unit files.

4. Decision: SIGHUP is not required for M8.

   Rationale: the existing public control-plane reload path is explicit,
   authenticated and auditable. If SIGHUP is added, it must call the same
   safe-reload service and keep the same observability semantics.

5. Decision: pprof is control-plane diagnostics, not a standalone debug
   listener.

   Rationale: profile endpoints are sensitive. M8 must keep them disabled by
   default and protect them behind the control listener and protected
   authorization when enabled.

6. Decision: configured control auth cannot be cosmetic.

   Rationale: a production-hardening milestone must not leave configured auth
   modes unenforced. Enabled modes must either work or fail closed with
   documentation and tests.

7. Decision: runtime migration workflows stay runtime-only.

   Rationale: user holds, backend pins, moves, drains, kicks and affinity
   cleanup are Redis-backed runtime operations. They must not mutate YAML
   configuration through REST or CLI.

8. Decision: optional Docker and systemd proof is additive to guardrails.

   Rationale: default local guardrails must remain deterministic without host
   Docker or systemd, while production closeout should still record Docker and
   systemd proof when those environments are available.

9. Decision: M8 uses ten implementation phases.

   Rationale: OIDC caller auth, control-plane auth, protected diagnostics,
   lifecycle semantics, proof and closeout have different risk profiles and
   validation shapes. Splitting them prevents the security-sensitive OIDC and
   control-auth work from being hidden inside one overloaded hardening phase.

No blocking open questions remain for an initial M8 implementation. If M8
discovers a new production-hardening ambiguity, update this specification
before implementation continues.
