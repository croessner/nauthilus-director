# M0 Foundation Specification

Status: implementation-ready M0 specification

This document defines the first production implementation phase for
`nauthilus-director`. M0 establishes the root production Go module, typed
configuration, Nauthilus authentication boundary, routing fact resolver,
OpenAPI control API workflow, Redis state interfaces, observability baseline
and test harness needed before the IMAP MVP expands in M1.

M0 is not a proof-of-concept migration. The archived implementation under
`poc/` may be read only as historical source material, and production code must
not import it, preserve its package layout, or use it as a compatibility target.

## Source Documents

M0 is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/specs/README.md`
- `.gitignore`

If this specification conflicts with those source documents, fix the drift
before implementation continues.

## M0 Goal

M0 prepares the codebase for the IMAP MVP without implementing the IMAP protocol
flow itself. It creates the production foundation that later protocol slices use
without re-deciding architecture, config paths, auth boundaries, routing
semantics, REST generation, Redis state ownership or local quality gates.

## Global Scope

In scope:

- Create the root Go 1.26 production module outside `poc/`.
- Establish the initial root package layout and narrow package boundaries.
- Pin the approved foundation dependencies and OpenAPI generator.
- Add Makefile targets for generation, stale-output checks and normal gates.
- Define and implement the typed config loader, defaults, validation,
  placeholder expansion and redaction model.
- Define the Nauthilus auth transport boundary and shared internal auth result.
- Define the director-owned routing resolver interface with `auth_attribute`
  and deterministic hash fallback.
- Establish the OpenAPI-first REST contract workflow and generated server/client
  boundaries.
- Establish Redis state interfaces, key-shape helpers and Lua script loading
  conventions needed by active affinity and runtime overrides.
- Establish structured logging, trace boundaries and metric label policy.
- Add the first E2E harness entrypoint and fake service scaffolding so M1 can
  prove behavior through public sockets and commands, and document the separate
  future Docker interoperability smoke lane.

Out of scope:

- Implementing IMAP, POP3, LMTP or ManageSieve protocol flows.
- Implementing transparent protocol proxying.
- Implementing full backend health checks, maintenance execution or selector
  policies beyond minimal interfaces and deterministic foundations.
- Implementing all Redis Lua scripts for open, heartbeat, close, reap, move,
  kick, clear and administrative pins.
- Adding generated artifacts as part of this specification writing task.
- Writing runtime mutations back into YAML configuration.
- Adding feature-specific Redis configuration subtrees.

## Stable M0/M1 Config Paths

The following config paths are stable for M0/M1 and must not be renamed,
removed or inverted without an explicit breaking-change decision plus docs,
examples, migration notes and tests:

- `runtime.process`
- `runtime.servers.control`
- `runtime.timeouts`
- `runtime.clients`
- `observability`
- `storage.redis`
- `auth.authorities`
- `director.security`
- common listener fields: `protocol`, `service_name`, `network`, `address`,
  `authority`, `backend_pool`, `proxy_protocol` and `tls`
- `director.listeners.imap`
- `director.listeners.imaps`
- `director.routing`
- `director.affinity`
- `director.health`
- `director.maintenance`
- `director.runtime_overrides`
- `director.backend_pools`
- `director.backends`

LMTP, ManageSieve and POP3 listener/backend details remain draft until their
later milestones.

## Target Package Boundaries

M0 establishes these production packages. A package may contain minimal domain
interfaces or placeholders when later phases own the full implementation, but it
must keep ownership boundaries clear.

```text
cmd/nauthilus-director/
cmd/nauthilus-directorctl/

internal/app/
internal/config/
internal/nauthilus/
internal/routing/
internal/backend/
internal/state/
internal/rest/
internal/rest/generated/
internal/rest/adapters/
internal/client/generated/
internal/observability/
```

Boundary rules:

- `internal/app` owns process assembly, Fx modules, lifecycle, reload entrypoints
  and runtime snapshot wiring.
- `internal/config` owns typed config models, defaults, loading, expansion,
  validation, redaction and config dump formatting.
- `internal/nauthilus` owns director-to-Nauthilus auth clients, request/response
  mapping, transport selection and secret-safe auth errors.
- `internal/routing` owns logical routing fact resolution only.
- `internal/backend` owns backend registry, backend domain objects, selector
  interfaces, health state and maintenance state.
- `internal/state` owns Redis-backed affinity/session/runtime state interfaces,
  key builders, script loading and Redis failure semantics.
- `internal/rest` owns the control server boundary, REST auth, generated server
  adapters and domain-to-DTO conversion.
- `internal/client/generated` contains only generated OpenAPI client code for
  `nauthilus-directorctl`.
- `internal/observability` owns logging, metrics, tracing and redaction-safe
  field helpers.

Protocol packages are intentionally not part of M0. M1 and later phases add
`internal/protocol/...` packages without moving auth, routing, backend, REST or
observability responsibilities into protocol handlers.

## M0 Security and Observability Baseline

M0 implementation must start with the security and observability rules that later
protocol work will inherit:

- Use structured logs with secret-safe fields only.
- Never log authentication material, session secrets, tokens, passwords, SASL
  blobs or private keys.
- Prepare OpenTelemetry span boundaries for Nauthilus auth, routing resolution,
  backend selection, REST requests and later protocol sessions.
- Register Prometheus metrics only through helpers that enforce the documented
  low-cardinality label allowlist.
- Do not add username, user hash, recipient, session ID, trace ID, request ID,
  client IP, raw backend identifier, raw error text or secret-bearing values as
  metric labels.
- Fail closed on ambiguous auth, routing, Redis or backend-selection state.
- Keep TLS, listener exposure, backend authentication, control APIs and
  operational overrides on the safest usable defaults.

## M0.1 Repository and Module Foundation

### Purpose

Create the production Go 1.26 root module and repository structure that all
later implementation slices use.

### In Scope

- Add root `go.mod` with Go 1.26.
- Use `github.com/croessner/nauthilus-director` as the root module path.
- Keep `go.mod`, Docker builds, CI, vendor tree, Makefile targets and
  operator-facing docs aligned with Go 1.26.
- Add root `go.sum` and `vendor/` after dependency changes.
- Add approved foundation dependencies:
  - `go.uber.org/fx`
  - `github.com/spf13/viper`
  - `github.com/go-playground/validator/v10`
  - `github.com/redis/go-redis/v9` pinned to `v9.19.0`
  - `github.com/json-iterator/go` only where intentionally chosen over
    `encoding/json`
  - `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen` pinned to
    `v2.7.0` as a tool
- Pin OpenAPI generation to schema version `openapi: 3.0.3` unless a later
  explicit architecture decision changes it.
- Add the minimal server and CLI command roots with `--version` support.
- Add package directories listed in Target Package Boundaries.
- Add `tools/tools.go` or an equivalent root module tool pin so OpenAPI
  generation is reproducible from the vendored module tree.
- Add Makefile targets or update existing targets so `make test`, `make race`,
  `make lint`, `make e2e`, `make build-check` and `make guardrails` are the
  main validation path.
- Add `make generate-openapi` and `make check-openapi` once the OpenAPI contract
  exists.

### Out of Scope

- Implementing mail protocol listeners.
- Importing, moving or adapting packages from `poc/`.
- Adding generated OpenAPI files before the generation workflow and stale check
  are defined.
- Adding convenience dependencies without documented need.

### Expected Files or Packages

```text
go.mod
go.sum
vendor/
tools/tools.go
cmd/nauthilus-director/main.go
cmd/nauthilus-directorctl/main.go
internal/app/
internal/config/
internal/nauthilus/
internal/routing/
internal/backend/
internal/state/
internal/rest/
internal/observability/
scripts/generate-openapi.sh
scripts/check-openapi.sh
Makefile
```

### Implementation Notes

- The root module is the only production Go module in M0. The `poc/` module
  remains archived and must stay excluded from production module discovery.
- The same root module contains both production binaries:
  `cmd/nauthilus-director` for the server and `cmd/nauthilus-directorctl` for
  the CLI client.
- `go mod tidy` and `go mod vendor` are mandatory after dependency or tool pin
  changes.
- Makefile targets must use the root production module and continue to ignore
  `poc/` except for explicit `poc-*` targets.
- `nauthilus-director --version` and `nauthilus-directorctl --version` must work
  before deeper behavior exists.
- If Docker or CI files are introduced or updated in M0, they must explicitly
  use Go 1.26 and the same Makefile targets as local validation.
- Generated artifacts must be reproducible from checked-in source specs,
  generator config and pinned tool versions.

### Required Unit Tests

- Version command tests for both binaries.
- Root package import tests that fail if production packages import paths under
  `/poc/`.
- Makefile or script test coverage for module discovery excluding `poc/` where
  practical.

### Required Integration or E2E Tests

- `make e2e` must have a stable entrypoint. It may initially skip protocol
  scenarios with a clear message until M1 starts, but it must be executable and
  ready for public-socket tests.
- Build-check validation must build the root module once it exists.

### Acceptance Criteria

- Root production `go.mod` exists and uses Go 1.26.
- Root production `go.mod` uses module path
  `github.com/croessner/nauthilus-director`.
- `poc/` remains an archive and is not imported by production code.
- Approved dependencies and tool pins are present.
- Additional dependencies, if any, have explicit justification in the commit or
  implementation notes.
- `go mod tidy` and `go mod vendor` have been run after dependency changes.
- Makefile targets are the main validation path and `make guardrails` remains
  the final local gate.

### Review Checklist

- Verify `git grep -n 'poc/' -- '*.go'` does not show production imports or
  package coupling.
- Verify `go.mod` uses module path
  `github.com/croessner/nauthilus-director`, says Go 1.26 and includes the
  approved foundation versions.
- Verify `vendor/modules.txt` reflects the pinned dependencies.
- Verify both binaries expose `--version`.
- Verify broad implementation did not start protocol flow work prematurely.

## M0.2 Typed Configuration, Defaults, Expansion, and Redaction

### Purpose

Implement the production config foundation from
`docs/config/nauthilus-director.target.yml` with typed validation, stable M0/M1
paths, fail-closed placeholder expansion and deterministic redaction.

### In Scope

- YAML as the default config and dump format.
- Viper-based loading with support for common Viper formats where practical.
- Typed config structs in `internal/config`.
- Mapstructure decode from the merged config tree into typed structs.
- Mandatory `go-playground/validator/v10` validation after decode.
- Unknown field rejection where the selected parser/decoder path can support
  strictness.
- Nauthilus-compatible config includes and patches as part of the M0 loader,
  resolved before placeholder expansion and typed validation.
- Canonical defaults for all stable M0/M1 paths.
- Config value expansion for scalar values:
  - `${NAME}` expands environment variables.
  - Ordinary `$` remains literal.
  - `$${NAME}` escapes a placeholder.
  - Map keys are never expanded.
  - Missing variables fail closed.
  - Missing-variable errors name the config path and variable name without
    leaking raw or partially expanded values.
- Explicit secret metadata so expanded secret values remain redacted by default.
- Config dump commands:
  - `nauthilus-director config dump -d --format yaml`
  - `nauthilus-director config dump -n --format yaml`
  - `nauthilus-director config dump -n -P --format yaml`
- Redaction policy:
  - `-d` prints canonical defaults only.
  - `-n` prints non-default effective config, redacted by default.
  - `-n -P` includes protected credential values explicitly.
  - `-P` affects only config output and never logs, metrics, traces or REST
    responses.
- Redis config remains centralized under `storage.redis`.
- Runtime REST and CLI mutations never rewrite YAML config.

### Out of Scope

- Building a dynamic config schema service.
- Rewriting config files after REST or CLI runtime mutations.
- Adding feature-specific Redis config under affinity, sessions or runtime
  overrides.
- Treating `docs/config/nauthilus-director.target.yml` as an exact generated
  file. It remains the target draft that typed config must align with.

### Expected Files or Packages

```text
internal/config/config.go
internal/config/defaults.go
internal/config/load.go
internal/config/include.go
internal/config/patch.go
internal/config/expand.go
internal/config/validate.go
internal/config/redact.go
internal/config/dump.go
internal/config/secret.go
internal/config/*_test.go
cmd/nauthilus-director/main.go
```

### Implementation Notes

- The config loader must work through a cohesive `Loader` type rather than
  package-level mutable state.
- Loading order is:
  1. Start from canonical defaults.
  2. Read the main config file.
  3. Resolve `includes` recursively.
  4. Merge included settings and main settings into a raw tree.
  5. Collect and apply `patch` operations.
  6. Strip loader-only keys.
  7. Expand scalar placeholders in values only.
  8. Apply Viper environment bindings or overrides according to documented
     precedence.
  9. Decode into typed structs with mapstructure.
  10. Validate typed structs with `validator/v10`.
  11. Build an immutable config snapshot for app wiring.
- Include and patch semantics must match the production Nauthilus config loader:
  - Loader directives are root-level keys named `includes`, `env` and `patch`.
  - `includes` supports `required`, `optional` and environment-specific groups
    under `env.<name>.required` and `env.<name>.optional`.
  - The active include environment is the root `env` string when set; otherwise
    it comes from the Viper environment key `env`, which maps to
    `NAUTHILUS_DIRECTOR_ENV` in this project.
  - Include paths are resolved relative to the file that declares them unless
    the include path is absolute.
  - Includes are recursive and must detect include cycles using cleaned file
    paths.
  - Missing required includes fail config loading. Missing optional includes are
    ignored. Other read or decode errors fail config loading.
  - Includes are merged before the declaring file, and later files override
    earlier files. Nested maps merge recursively. Non-map values, including
    slices, replace the previous value.
  - `patch` is a list of operations with `op`, `path` and `value`.
  - Supported patch operations are `add`, `replace` and `remove`.
  - Patch paths use dot-separated map keys, not JSON Pointer or RFC 6902 paths.
  - Patches from included files are collected before patches from the including
    file. All collected patches are applied after the raw tree is merged and
    before placeholder expansion.
  - `add` appends to an existing list, shallow-merges into an existing map, or
    creates a new list containing the value when the target key does not exist.
  - `replace` sets the addressed value, creating missing parent maps as needed.
  - `remove` requires the addressed value to exist. For lists it removes entries
    equal to `value`; for maps it deletes a single string key or a list of string
    keys.
  - Unsupported operations, empty paths, empty path segments, type mismatches
    and invalid non-string map-removal keys fail config loading.
  - `includes`, `env` and `patch` are loader-only keys and must not appear in
    the final typed runtime config snapshot or config dump output.
- Unknown fields should be rejected through mapstructure unused-field metadata
  or equivalent strict decode support. If a Viper format cannot support
  unknown-field rejection, document and test the limitation for that format.
- Secret-bearing values must use typed wrappers or explicit struct metadata,
  not substring-based path guesses.
- The redactor must operate on typed config metadata so destination secret
  metadata survives placeholder expansion.
- `storage.redis.enabled`, topology mode, auth, TLS, pool, retry, health,
  key-prefix and namespace validation belongs to the central Redis config type.
- Include and patch support belongs to `internal/config`; it must not be
  implemented through ad hoc string manipulation after typed decode and must not
  introduce a director-specific dialect that drifts from Nauthilus.
- `runtime.servers.control` must default to a safe local management listener.
- TLS settings default to verification on; `insecure_skip_verify` defaults
  false and must be explicit when allowed.
- Config dumps must not include Redis runtime overrides unless a separate
  runtime-state command asks for them.

### Required Unit Tests

- Defaults produce a valid typed config for stable M0/M1 paths.
- YAML load and typed validation succeed for
  `docs/config/nauthilus-director.target.yml` after test-safe file path
  handling.
- Unknown fields are rejected for strict decode paths.
- Includes and patches are merged before placeholder expansion and typed
  validation.
- `includes.required`, `includes.optional` and `includes.env.<name>` are
  resolved in Nauthilus-compatible order.
- Relative includes are resolved from the declaring file directory.
- Recursive includes detect cycles.
- Missing required includes fail; missing optional includes are ignored.
- Loader-only keys `includes`, `env` and `patch` are stripped from the final
  settings tree.
- Patch operations `add`, `replace` and `remove` follow the Nauthilus
  dot-path semantics for maps and lists.
- Invalid patch operations, empty paths, type mismatches and invalid remove
  values fail closed.
- Missing required fields fail validation with path-specific errors.
- `${NAME}` expands scalar values.
- Ordinary `$` remains literal.
- `$${NAME}` produces a literal `${NAME}` value.
- Map keys are not expanded.
- Missing environment variables fail closed and errors include the config path
  and variable name only.
- Expanded password, token and key fields remain redacted in default output.
- `-P` includes protected values only in config dump output.
- `-P` has no effect on log, metric, trace or REST redaction helpers.
- `-d`, `-n` and `-n -P` produce deterministic YAML output.
- Redis config validates standalone, Sentinel and Cluster modes with TLS/auth
  requirements.

### Required Integration or E2E Tests

- Run the `nauthilus-director config dump` subcommands through the binary, not
  internal helpers, and assert redaction and deterministic output.
- Validate that a config containing a missing placeholder exits non-zero without
  logging the raw value.

### Acceptance Criteria

- Typed config loader behavior is implemented and covered by tests.
- Include and patch behavior is implemented and covered by tests.
- Placeholder expansion and redaction behavior are implemented and covered by
  tests.
- Stable M0/M1 config paths are represented in typed structs and documented.
- Redis remains centralized under `storage.redis`.
- Runtime state mutation paths cannot write YAML config.

### Review Checklist

- Compare typed config structs against
  `docs/config/nauthilus-director.target.yml`.
- Verify `validator/v10` runs after decode, not before.
- Verify include and patch merging happens before placeholder expansion and
  typed validation.
- Verify secret metadata is destination-based and survives expansion.
- Verify missing-variable errors are secret-safe.
- Verify no feature-specific Redis subtree was added.

## M0.3 Nauthilus Auth Contract Boundary

### Purpose

Create the director-owned auth abstraction that talks to Nauthilus as an
authentication authority only and maps HTTP and gRPC responses into one internal
result shape.

### In Scope

- `internal/nauthilus` package with narrow auth client interfaces.
- Configurable authority transport: HTTP or gRPC.
- Shared internal result:

```go
type AuthResult struct {
    Decision      string
    Account       string
    SessionID     string
    StatusMessage string
    Attributes    map[string][]string
}
```

- HTTP transport to `/api/v1/auth/json` using the real structured Nauthilus
  auth DTO.
- gRPC transport boundary for `nauthilus.auth.v1.AuthService` mapping into the
  same `AuthResult`.
- Identity lookup and list-accounts method boundaries.
- Secret-safe request, response and error types.
- Mapping tests that prove the director does not send director-owned routing or
  backend fields to Nauthilus.

### Out of Scope

- Asking Nauthilus for concrete director backend identifiers.
- Implementing director routing inside the Nauthilus client.
- Implementing local OIDC bearer-token validation.
- Logging passwords, tokens, SASL blobs, session secrets or private keys.
- Sending unknown HTTP JSON fields such as `service`, nested `tls`, nested
  `proxy`, `listener`, `session_id`, `backend_identifier` or `routing_hint`.

### Expected Files or Packages

```text
internal/nauthilus/client.go
internal/nauthilus/http.go
internal/nauthilus/grpc.go
internal/nauthilus/request.go
internal/nauthilus/response.go
internal/nauthilus/errors.go
internal/nauthilus/*_test.go
internal/config/auth.go
```

### Implementation Notes

- Nauthilus authenticates only. Backend selection stays in routing, state and
  backend packages.
- The protocol identity belongs in `protocol`, not in a top-level `service`
  body field.
- HTTP JSON encoding must be strict and based on the real Nauthilus structured
  auth DTO. Golden tests must assert the outbound body field set.
- The director may parse SASL `PLAIN`, `LOGIN`, `XOAUTH2` and `OAUTHBEARER`
  envelopes only enough to preserve mechanism identity and pass credential
  material to Nauthilus.
- OIDC-backed bearer-token validation belongs to Nauthilus. The director
  preserves the bearer material as a secret and sends it over the configured
  authority transport.
- Both transports must classify outcomes as authenticated, rejected or tempfail
  without leaking credential material.
- Transport errors and malformed authority responses fail closed.
- Authentication attributes are inputs to routing only after a successful auth
  or lookup result.

### Required Unit Tests

- HTTP request body includes `protocol` and omits forbidden director fields.
- HTTP request uses `/api/v1/auth/json` with `application/json`.
- HTTP `mode=no-auth` lookup maps into `AuthResult`.
- HTTP `mode=list-accounts` boundary is represented without inventing backend
  decisions.
- gRPC auth, lookup and list-accounts responses map into the same `AuthResult`
  shape as HTTP.
- Rejected, tempfail, malformed and transport-error outcomes are classified
  consistently.
- Passwords, tokens, SASL blobs and private keys are redacted from errors and
  log fields.
- Unknown JSON fields in internal outbound DTO tests fail the golden assertion.

### Required Integration or E2E Tests

- Fake Nauthilus HTTP authority returns account and routing attributes.
- Fake Nauthilus gRPC authority returns equivalent account and routing
  attributes.
- Binary-level auth client smoke tests must prove the selected transport is
  driven by `auth.authorities.<name>.transport`.

### Acceptance Criteria

- Nauthilus HTTP/gRPC auth boundary is defined and covered by tests.
- Nauthilus remains authentication-only in code and docs.
- HTTP outbound DTO does not contain forbidden director fields.
- gRPC maps to the same `AuthResult` as HTTP.
- Secret-bearing auth material is never logged or exposed in metrics.

### Review Checklist

- Verify no Nauthilus client API returns a concrete backend identifier for
  normal director routing.
- Verify `service` is absent from HTTP auth bodies and `protocol` is present.
- Verify malformed or ambiguous auth state fails closed.
- Verify all auth observability uses secret-safe fields.

## M0.4 Routing Resolver Foundation

### Purpose

Define the director-owned routing fact layer used after authentication and
before backend selection.

### In Scope

- `internal/routing` package.
- `RoutingResolver` interface.
- Request model consuming auth attributes, listener context, normalized account,
  tenant, protocol, service name and client context as needed.
- Result model returning account key, tenant, shard tag, routing source,
  generation where relevant, stickiness behavior, TTL where relevant and safe
  attributes.
- `auth_attribute` resolver.
- Deterministic hash fallback resolver.
- Chain behavior that uses `auth_attribute` first and falls back to hash when
  configured and safe.
- Fail-closed behavior on ambiguous routing facts.
- Explicit guarantee that normal user-stateful routing results do not return a
  concrete backend identifier.

### Out of Scope

- Selecting concrete backends.
- Creating or refreshing active sessions.
- Mutating Redis.
- Calling Nauthilus.
- Calling external HTTP or gRPC routing services.
- Implementing complete backend maintenance or health logic.

### Expected Files or Packages

```text
internal/routing/resolver.go
internal/routing/request.go
internal/routing/result.go
internal/routing/auth_attribute.go
internal/routing/hash.go
internal/routing/chain.go
internal/routing/errors.go
internal/routing/*_test.go
internal/backend/registry.go
internal/backend/selector.go
internal/state/affinity.go
```

### Implementation Notes

- The resolver returns logical routing facts only.
- `shard_tag + protocol + backend_pool` later maps to concrete backend
  identifiers in `internal/backend`.
- Active affinity pins logical `shard_tag` first, then resolves
  protocol-specific backend entries.
- `auth_attribute` reads configured attribute names for account key, shard tag
  and tenant from `AuthResult.Attributes`.
- Multiple values for a field that must be singular are ambiguous and must fail
  closed unless an explicit ordered-selection rule exists in config.
- Deterministic hash fallback must be stable for the same normalized account,
  tenant and configured shard set.
- The resolver may expose safe attributes for explanation and route lookup, but
  must filter secrets and high-cardinality values according to observability
  policy.
- Backend selector interfaces may exist in M0 so the REST route lookup contract
  can compile later, but full selector behavior belongs to M1/M2.

### Required Unit Tests

- `auth_attribute` resolves account key, tenant and shard tag from configured
  auth attributes.
- Missing shard attribute falls back to deterministic hash when configured.
- Missing shard attribute fails closed when no fallback exists.
- Multiple shard values fail closed unless explicitly configured otherwise.
- Hash fallback is deterministic and changes only when the configured shard set
  changes.
- Result never contains a concrete backend identifier for normal user-stateful
  routing.
- Safe attributes exclude credential and forbidden metric-label material.
- Route lookup uses routing facts without calling Nauthilus or mutating state.

### Required Integration or E2E Tests

- Fake Nauthilus attributes drive `auth_attribute` routing through a public
  binary or test-process boundary when M1 protocol entrypoints exist.
- M0 may provide a route lookup smoke test through the REST scaffold once the
  generated server boundary exists.

### Acceptance Criteria

- Routing resolver foundation is defined and covered by tests.
- `auth_attribute` and deterministic hash fallback are implemented or precisely
  scaffolded for immediate M1 use.
- Resolver output stays logical and does not select concrete backends.
- Backend selector and state interfaces are separated from resolver code.

### Review Checklist

- Verify `internal/routing` imports neither REST handlers nor Nauthilus
  transport implementations.
- Verify active affinity is modeled as shard-tag-first, backend-second.
- Verify route lookup remains director-only and side-effect-free.
- Verify errors are explainable without leaking raw account or credential
  material.

## M0.5 OpenAPI Control API Foundation

### Purpose

Establish the OpenAPI-first REST control API workflow, generated server/client
boundaries and CLI client transport rules before REST implementation expands.

### In Scope

- Source REST contract at `docs/specs/openapi/nauthilus-director.yaml`.
- Create the initial OpenAPI file during M0 and include the full v1 endpoint
  group set listed below.
- OpenAPI schema version pinned to `3.0.3`.
- Generator pinned to
  `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.0`.
- Generated REST server boundary, DTOs and generated client-with-responses SDK.
- `internal/rest` adapters from generated DTOs into explicit domain objects.
- `internal/client/generated` OpenAPI client SDK for `nauthilus-directorctl`.
- `nauthilus-directorctl` command structure using generated client transport.
- Makefile targets:
  - `make generate-openapi`
  - `make check-openapi`
- Stale-output check that fails when generated files differ from the source
  OpenAPI contract and generator config.
- Initial endpoint groups from the architecture roadmap specified in OpenAPI.
- Route lookup specified as director-only and side-effect-free.

### Out of Scope

- Letting OpenAPI generated code own mail protocol state machines.
- Letting OpenAPI generated code own routing resolver implementation.
- Letting OpenAPI generated code own backend registry, selector or health
  model.
- Letting OpenAPI generated code own Nauthilus transport implementation.
- Duplicating REST DTOs in hand-written CLI code.
- Persisting runtime mutations into YAML configuration.

### Expected Files or Packages

```text
docs/specs/openapi/nauthilus-director.yaml
docs/specs/openapi/oapi-codegen.server.yml
docs/specs/openapi/oapi-codegen.client.yml
internal/rest/server.go
internal/rest/auth.go
internal/rest/adapters/
internal/rest/generated/
internal/client/generated/
cmd/nauthilus-directorctl/
scripts/generate-openapi.sh
scripts/check-openapi.sh
Makefile
```

### Implementation Notes

- The OpenAPI document is the source of truth for public REST DTOs.
- The initial M0 OpenAPI document should be broad enough to cover the planned
  v1 control surface, even when some operations are backed by explicit
  not-yet-implemented handlers. Later contract refinements are allowed, but
  they must be treated as normal public REST contract changes.
- Register the planned v1 routes in M0. Operations whose domain behavior is not
  implemented yet must return explicit `501 Not Implemented` responses through
  the generated REST boundary instead of being absent from the server.
- Generated code stays at the REST boundary. Hand-written adapters convert DTOs
  into config, routing, backend and state domain objects.
- `nauthilus-directorctl` may own nested subcommands, local config, output
  formatting and operator-friendly errors, but it must use generated OpenAPI
  client types for API transport.
- The REST control API runs in the main `nauthilus-director` process on
  `runtime.servers.control`.
- The v1 REST API is separate from the mail data path and must default to a
  local or protected management listener.
- Supported control auth modes in the contract are disabled, static bearer
  token, mTLS, reverse-proxy authenticated headers and OIDC/JWT via Nauthilus.
- Route lookup must not authenticate credentials, call Nauthilus, create
  sessions, refresh leases or mutate Redis. It may read configured resolver
  inputs, Redis-backed affinity, runtime overrides, health and maintenance state
  when those subsystems exist.
- Mutating REST endpoints manage Redis-backed runtime state only.

### Initial Endpoint Groups

The OpenAPI contract must reserve or define:

```text
GET  /healthz
GET  /readyz
GET  /api/v1/version
GET  /api/v1/config/effective
GET  /api/v1/config/defaults
GET  /api/v1/config/non-default
POST /api/v1/reload
GET  /api/v1/backends
GET  /api/v1/backends/{identifier}
POST /api/v1/backends/{identifier}/maintenance
DELETE /api/v1/backends/{identifier}/maintenance
POST /api/v1/backends/{identifier}/runtime/in
POST /api/v1/backends/{identifier}/runtime/out
POST /api/v1/backends/{identifier}/runtime/drain
DELETE /api/v1/backends/{identifier}/runtime
GET  /api/v1/sessions
GET  /api/v1/sessions/{session_id}
DELETE /api/v1/sessions/{session_id}
GET  /api/v1/users
GET  /api/v1/users/{user_key}
GET  /api/v1/users/{user_key}/sessions
GET  /api/v1/users/{user_key}/affinity
PUT  /api/v1/users/{user_key}/affinity
DELETE /api/v1/users/{user_key}/affinity
POST /api/v1/users/{user_key}/move
POST /api/v1/users/{user_key}/kick
POST /api/v1/route/lookup
GET  /metrics
```

M0 must stub domain-incomplete handlers behind explicit `501 Not Implemented`
or equivalent generated-boundary domain errors. The OpenAPI paths, generated
types, adapters and route lookup side-effect rules must be established before
M1/M3.

### Required Unit Tests

- OpenAPI generation command writes only expected generated paths.
- Stale-output check fails on intentionally modified generated output.
- REST adapters do not expose generated DTOs outside REST/client boundaries.
- CLI packages do not define duplicate request/response DTOs.
- Route lookup handler or adapter rejects credential-bearing inputs.
- Route lookup implementation path does not call Nauthilus or mutate state.

### Required Integration or E2E Tests

- Start the control listener and call `/healthz`, `/readyz` and
  `/api/v1/version` over HTTP.
- Call at least one planned-but-not-implemented route and assert a structured
  `501 Not Implemented` response.
- Run `nauthilus-directorctl --version`.
- Run at least one `nauthilus-directorctl` read-only command through the
  generated client once the control server exists.
- Run `make check-openapi` as part of guardrails once generated files exist.

### Acceptance Criteria

- OpenAPI generator and stale-output workflow are defined and covered by
  tests/checks.
- Initial OpenAPI source file exists and includes the planned v1 endpoint group
  set.
- Planned v1 routes are registered in M0, and domain-incomplete operations
  return structured `501 Not Implemented` responses.
- `nauthilus-directorctl` client-boundary requirements are defined and enforced.
- Generated code remains at REST/client boundaries.
- Route lookup is specified and tested as director-only and side-effect-free.

### Review Checklist

- Verify OpenAPI source lives under `docs/specs/openapi/`.
- Verify generated files are reproducible from pinned generator config.
- Verify CLI code imports generated client types instead of duplicating DTOs.
- Verify REST mutations cannot rewrite YAML config.

## M0.6 Test, E2E Harness, and Guardrails Foundation

### Purpose

Create the validation framework that keeps M0 safe and lets M1 prove externally
visible protocol behavior without internal package shortcuts.

### In Scope

- Keep `make guardrails` as the final local gate.
- Ensure `make guardrails` runs:
  - `make fix`
  - `make vet`
  - `make lint`
  - `make test`
  - `make race`
  - `make e2e`
  - `make build-check`
- Add an E2E runner at `test/e2e/run.sh`.
- Add fake service scaffolding for:
  - Nauthilus HTTP authority
  - Nauthilus gRPC authority
  - IMAP backend
  - LMTP backend
  - ManageSieve backend
  - POP3 backend
- Document the future Docker interoperability smoke lane as separate from the
  deterministic fake-service guardrail lane.
- Use real Redis or a Redis-compatible test service for active affinity and
  runtime overrides.
- Ensure E2E tests start real binaries or test processes and talk to public
  sockets, REST endpoints and CLI commands where applicable.
- Add test logging helpers that redact credentials and SASL bearer material.
- Add targeted unit tests for config, auth, routing, OpenAPI adapters, state
  key building and observability policies.

### Out of Scope

- Proving full IMAP login and proxy flow before M1.
- Replacing unit tests with internal-only E2E shortcuts.
- Printing credentials, SASL blobs or bearer tokens in test logs.
- Making Redis optional for production active affinity semantics.
- Requiring Postfix or Dovecot Docker interoperability runs before the
  corresponding production protocol entrypoints exist.

### Expected Files or Packages

```text
test/e2e/run.sh
test/e2e/README.md
test/e2e/fakes/nauthilus_http/
test/e2e/fakes/nauthilus_grpc/
test/e2e/fakes/imap_backend/
test/e2e/fakes/lmtp_backend/
test/e2e/fakes/managesieve_backend/
test/e2e/fakes/pop3_backend/
test/e2e/interop/README.md
internal/state/keys.go
internal/state/scripts/
internal/observability/policy.go
```

### Implementation Notes

- E2E tests are allowed to skip scenarios whose production entrypoints do not
  exist yet, but the runner itself must be executable and documented.
- M0 must create the E2E runner and fake-service scaffold directories. A textual
  specification without those files is not sufficient for M0 acceptance.
- Fake services should expose observable counters or request logs that omit
  credentials.
- E2E must use two clearly documented lanes:
  - the default guardrail lane runs through `make e2e`, uses deterministic fake
    Nauthilus and fake protocol backends, and remains suitable for local
    guardrails;
  - the future Docker interoperability lane may use a target such as
    `make e2e-interop` or `make e2e-docker`, uses pinned container images or
    digests, and skips explicitly when Docker or production protocol entrypoints
    are unavailable.
- The Docker interoperability lane should use `chrroessner/postfix` when
  Postfix behavior is part of the externally visible scenario, and
  Dovecot project-provided Docker assets for IMAP, POP3, LMTP and ManageSieve
  backend interoperability once those protocol entrypoints exist.
- Docker interoperability tests validate real server behavior, packaging
  assumptions, listener exposure and TLS/backend-auth settings. They do not
  replace fake-service tests for forced edge cases, deterministic routing and
  secret-safe observability assertions.
- Redis test setup must exercise the same key builder and script loader used by
  production code.
- Redis key groups use Cluster hash tags derived from the normalized affinity
  key:

```text
<prefix>:v<schema>:{aff:<affinity_hash>}:state
<prefix>:v<schema>:{aff:<affinity_hash>}:sessions
<prefix>:v<schema>:{aff:<affinity_hash>}:session:<session_id>
<prefix>:v<schema>:{aff:<affinity_hash>}:override
<prefix>:v<schema>:runtime:backend:<backend_id>
<prefix>:v<schema>:idx:sessions
<prefix>:v<schema>:idx:backends
```

- Normal routing must eventually use atomic Lua scripts for open, heartbeat,
  close, reap, move, kick, clear and administrative pin changes. M0 must
  establish script loading, SHA tracking, `EVALSHA` fallback behavior, server
  time usage and fail-closed error classification even if only minimal scripts
  exist.
- Session liveness is lease-based. A crashed director must not leave permanent
  active sessions.
- Observability tests must enforce the low-cardinality metric label allowlist.

Allowed metric labels:

```text
protocol
service
listener
operation
result
reason_class
transport
mechanism
backend_pool
shard_tag
maintenance_mode
direction
method
route
status_class
tls_mode
redis_mode
```

Forbidden metric labels:

```text
username
user_hash
recipient
session_id
trace_id
request_id
client_ip
remote_addr
backend_identifier
token
password
sasl_blob
raw_error
```

### Required Unit Tests

- State key builder creates Cluster-hash-tagged per-affinity key groups.
- Raw usernames are not required in Redis keys.
- Script loader registers scripts, tracks SHA values and classifies missing
  scripts without best-effort success.
- Redis ambiguous state errors fail closed.
- Metric label registration rejects forbidden labels.
- Structured log fields redact secrets.
- Trace span names are prepared for auth, routing, backend selection, REST and
  later protocol sessions.
- E2E runner exits successfully when no runnable scenarios exist yet and says
  what was skipped, including deferred Docker interoperability scenarios.

### Required Integration or E2E Tests

- Start fake Nauthilus HTTP and gRPC authorities on public test sockets.
- Start fake protocol backend test processes on public test sockets.
- Start real Redis or a Redis-compatible service and verify connectivity through
  production config.
- Call public REST endpoints and CLI commands when the control server exists.
- Assert fake service logs do not contain credentials or bearer material.
- Document the Docker interoperability smoke lane; M0 does not need to start
  Postfix or Dovecot containers until matching production protocol entrypoints
  exist.

### Acceptance Criteria

- E2E harness entrypoint exists and is executable.
- Fake service scaffolding exists for Nauthilus HTTP/gRPC and future protocol
  backends.
- Redis test service expectations are documented and wired into the harness.
- `make guardrails` remains the final local gate.

### Review Checklist

- Verify E2E tests use public sockets, REST endpoints and CLI commands.
- Verify tests do not prove behavior through internal package shortcuts.
- Verify credentials and SASL bearer material are absent from test logs.
- Verify state tests cover Cluster hash tags and fail-closed Redis semantics.

## Top-Level Acceptance Checklist

M0 is complete only when all items below are true:

- [ ] Root production module exists and does not import `poc/`.
- [ ] Root production module path is
      `github.com/croessner/nauthilus-director`.
- [ ] Root module, Docker builds, CI, vendor tree, Makefile targets and
      operator-facing docs are aligned with Go 1.26.
- [ ] Approved dependencies and tool pins are present.
- [ ] Additional dependencies, if any, are explicitly justified.
- [ ] `go mod tidy` and `go mod vendor` expectations are documented and have
      been followed after dependency updates.
- [ ] `make test`, `make race`, `make lint`, `make e2e`,
      `make build-check` and `make guardrails` are the main validation path.
- [ ] Generated artifacts are reproducible and have stale-output checks.
- [ ] Typed config loader behavior is defined and covered by tests.
- [ ] Config include and patch behavior is defined and covered by tests.
- [ ] Unknown field rejection is implemented where the selected decode path can
      support it.
- [ ] Env placeholder expansion behavior is defined and covered by tests.
- [ ] Redaction and `-P` config dump behavior are defined and covered by tests.
- [ ] Config dump output excludes Redis runtime overrides unless a separate
      runtime-state command asks for them.
- [ ] Redis settings live centrally under `storage.redis`.
- [ ] Active affinity uses Redis implicitly without feature-specific Redis
      config subtrees.
- [ ] Nauthilus HTTP/gRPC auth boundary is defined and covered by tests.
- [ ] HTTP auth sends `protocol` and does not send `service`, nested `tls`,
      nested `proxy`, `listener`, `session_id`, `backend_identifier` or
      `routing_hint`.
- [ ] gRPC auth maps to the same internal `AuthResult` shape as HTTP.
- [ ] Passwords, tokens, SASL blobs, session secrets and private keys are never
      logged.
- [ ] Routing resolver foundation is defined and covered by tests.
- [ ] Routing resolver returns logical facts and does not return a concrete
      backend identifier for normal user-stateful routing.
- [ ] `auth_attribute` and deterministic hash fallback behavior are covered.
- [ ] Redis state interfaces, key builders, script-loading approach and
      fail-closed semantics are established.
- [ ] OpenAPI source contract lives under
      `docs/specs/openapi/nauthilus-director.yaml`.
- [ ] Initial OpenAPI source contract includes the planned v1 endpoint group
      set, even when handlers are still explicit stubs.
- [ ] Planned v1 routes are registered, and domain-incomplete operations return
      structured `501 Not Implemented` responses.
- [ ] OpenAPI generator version and schema version are pinned.
- [ ] OpenAPI stale-output workflow is defined and covered by tests/checks.
- [ ] Generated REST server, DTO and client SDK code stay at REST/client
      boundaries.
- [ ] `nauthilus-directorctl` uses the generated OpenAPI REST client SDK for API
      transport.
- [ ] Hand-written CLI code does not duplicate REST DTOs or maintain a parallel
      client model.
- [ ] Route lookup is director-only, side-effect-free and covered by tests.
- [ ] Structured logs use secret-safe fields.
- [ ] OpenTelemetry span boundaries are prepared for auth, routing, backend
      selection, REST and later protocol sessions.
- [ ] Prometheus labels use only the documented low-cardinality allowlist.
- [ ] E2E harness entrypoint exists and is executable.
- [ ] Fake Nauthilus HTTP/gRPC authorities and fake IMAP, LMTP, ManageSieve and
      POP3 backend test scaffolds exist.
- [ ] Docker interoperability smoke lane is documented separately from the
      deterministic fake-service guardrail lane.
- [ ] E2E tests use public sockets, REST endpoints and CLI commands where
      applicable.
- [ ] E2E tests keep credentials and SASL bearer material out of logs.
- [ ] `make guardrails` is the final local gate before commit or pull request.

## Required M0 Review Pass

Before closing M0, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `docs/ARCHITECTURE_ROADMAP.md`.
3. Re-read `docs/config/nauthilus-director.target.yml`.
4. Compare implementation and docs against this specification and the source
   documents.
5. Fix drift, missing constraints, accidental POC coupling and vague acceptance
   criteria.
6. Run targeted docs/spec review and `git status --short`.
7. Run `make guardrails` before any commit or pull request that contains M0
   implementation work.
