# nauthilus-director Development Guidelines

This repository is a Go 1.26 project. Keep `go.mod`, Docker builds, CI, and
operator-facing documentation aligned with Go 1.26 whenever toolchain details
change.

The previous implementation lives under `poc/`. Treat that directory as a
historical proof-of-concept archive and source of ideas only. This repository is
now the production implementation. Production code must be implemented from the
repository root layout and must not import packages from `poc/` or preserve the
POC package structure as a compatibility constraint.

## Required Workflow

- Use the Makefile targets instead of ad hoc command variants whenever possible.
- Run `make guardrails` before every commit or pull request.
- Design and implement security-by-design and security-by-default. Prefer
  restrictive defaults, fail closed on ambiguous auth or transport state, and
  require explicit configuration for weaker or compatibility-oriented behavior.
- Design the production code with strict object-oriented boundaries in Go:
  encapsulate state in cohesive types, expose behavior through methods and
  narrow interfaces, and prefer composition over package-level mutable state.
- Apply DRY intentionally. Shared protocol, backend, auth, config, and
  observability behavior should live in one clear abstraction instead of being
  duplicated across packages.
- Keep external dependencies intentional. Prefer the Go standard library or a
  small local implementation when the behavior is simple, security-sensitive,
  and easy to maintain; add vendor packages only when they clearly reduce risk,
  complexity, or long-term maintenance cost.
- Treat the approved foundation dependencies as intentional architecture
  choices: Uber Fx (`go.uber.org/fx`) for application composition, Viper for
  configuration loading, go-playground/validator
  (`github.com/go-playground/validator/v10`) for mandatory typed config
  validation after Viper/mapstructure decoding,
  `github.com/redis/go-redis/v9@v9.19.0` for central production state and
  runtime coordination, and jsoniter for JSON paths where we intentionally
  choose it over `encoding/json`.
- Support Nauthilus-style environment-variable placeholders in scalar config
  values from the first production config loader. Expansion must happen before
  typed validation, must never expand map keys, must fail closed on missing
  variables, and must keep secret metadata and redaction intact.
- Stabilize configuration paths by implementation phase. Once a config path is
  stable for a phase, do not rename, remove or invert it without an explicit
  breaking-change decision plus docs, examples, migration notes and tests.
- Use OpenAPI from hour zero for the REST control API. The REST contract,
  server boundary, REST DTOs, and generated clients should originate from the
  OpenAPI spec instead of being retrofitted later. Keep generated artifacts
  reproducible: use
  `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.0`, pin the
  generator and schema version, provide a Makefile target, and add a
  stale-output check before relying on generated code.
- `nauthilus-directorctl` must use the generated OpenAPI REST client SDK for
  API transport. Hand-written CLI code may wrap the SDK for subcommands, output
  formatting and operator errors, but must not duplicate REST DTOs or maintain a
  parallel hand-written client model.
- Run Go tests through the Makefile targets so `make test`, `make race`, and
  `make guardrails` stay aligned.
- Add and run E2E tests for externally visible behavior. E2E tests must start
  real binaries or test processes, talk to public sockets, REST endpoints and
  CLI commands, and avoid internal package shortcuts as proof of behavior.
- Run lint through `make lint`; `make guardrails` includes `golangci-lint`.
- Keep the vendored module tree in sync. After dependency updates, run
  `go mod tidy` and `go mod vendor`.
- Prefer unit-test-driven development for core and domain behavior: write or
  adjust focused unit tests before production code when the behavior can be
  exercised cleanly at unit level.
- For bugs and regressions, create a failing reproducer test before changing
  production code whenever a stable reproducer is practical. If the reproducer
  fits the project and is not brittle or environment-only, keep it as regression
  coverage.
- When a unit test fails, first determine whether the failure exposes a defect
  in the core production code. Fix production code when it is wrong. Change the
  test only when the test logic, fixture, or assertion is demonstrably wrong.
- Write code comments and technical documentation in English.
- Maintain project documentation under `docs/`. Formal specs belong under
  `docs/specs/`; manpages belong under `docs/man/`.
- Keep local planning, prompt, scratch, and handoff artifacts under `temp/`.
  The root `temp/` directory is ignored and must never be staged, committed, or
  re-included through ignore exceptions. If a temporary artifact becomes
  durable project documentation, rewrite or move it under `docs/` first.
- Keep product and architecture documentation vendor-neutral. Do not frame
  target behavior by naming other mail-server or director projects unless the
  named project is an actual dependency, protocol peer, or configured service.
- Keep production validation focused on the new root codebase. Use `poc-*`
  Makefile targets only when intentionally checking the archived POC.

## Architecture Boundaries

- Nauthilus is the authentication authority only.
- Nauthilus must not make director routing or backend-selection decisions.
- `nauthilus-director` owns backend selection, health handling, affinity, and
  proxy lifecycle decisions.
- The director-to-Nauthilus authentication transport must be configurable:
  deployments use either HTTP or gRPC.
- OIDC-backed bearer-token validation belongs to Nauthilus. Protocol handlers
  may parse SASL `XOAUTH2` and `OAUTHBEARER` envelopes only far enough to pass
  mechanism identity and bearer material to Nauthilus without logging secrets.
- User-stateful protocols require active session stickiness. While a user has
  open frontend sessions, new sessions for the same affinity key must route to
  the same backend shard. Redis is the production source of truth for active
  affinity and session coordination; local caches are accelerators only.
- Active affinity and session coordination use per-affinity Redis key groups
  with Cluster hash tags and atomic Lua scripts for open, heartbeat, close,
  reap, move, kick and clear operations. Session liveness is lease-based; normal
  routing must not rely on distributed locks.
- Redis connection, security, authentication, Cluster and Sentinel settings
  belong centrally under `storage.redis`. Active affinity uses Redis implicitly;
  do not add feature-specific Redis sub-trees unless the code introduces a real
  multi-backend abstraction.
- REST and CLI mutation commands manage runtime state only. They may move or
  kick users, adjust backend runtime weight, mark backends in/out, and drain
  hosts through Redis-backed runtime state, but must never rewrite YAML config.
- Route lookup is a director-only, side-effect-free routing diagnostic. It must
  not call Nauthilus, authenticate credentials, create sessions, refresh leases
  or mutate Redis state.
- Soft maintenance excludes a backend from new initial placements while
  preserving existing sessions and active pins by default. Hard maintenance
  excludes all new sessions and may terminate existing sessions after explicit
  grace. Maintenance and drain operations must be auditable.
- The REST control API runs in the main `nauthilus-director` process on its own
  `runtime.servers.control` listener for v1. Do not introduce a separate
  management process unless a later architecture decision explicitly adds it.
- `nauthilus-directorctl` must use clean nested subcommands for operator
  workflows instead of growing a flat flag soup.
- Protocol handling should stay separated from backend selection, Nauthilus
  client code, REST management, and observability.
- Domain objects should own their invariants. Avoid procedural helper sprawl
  that lets unrelated packages mutate session, listener, backend, or auth state
  directly.
- Duplication is acceptable only when it preserves clear protocol-specific
  behavior and avoids premature abstraction; repeated business rules,
  validation logic, security checks, and transport semantics must be shared.
- New dependencies must be justified by a concrete need. Do not vendor a
  package for small helpers, trivial parsers, wrappers, or convenience code that
  can be implemented clearly and safely in-repo.
- OpenAPI must describe the public REST contract before implementation expands
  the control API. Code generation should provide the REST server boundary,
  DTOs, clients, and adapters from the beginning, but generated code must not
  blur the mail-protocol runtime boundaries or replace explicit domain objects.
- Configuration handling must keep canonical defaults inspectable with `-d`,
  non-default effective config inspectable with `-n`, and credential-bearing
  output available only through explicit `-P`. Redaction is the default.
- Config value expansion uses `${NAME}` placeholders, keeps ordinary `$`
  characters literal, supports `$${NAME}` escaping, reports missing variables
  without leaking raw or partially expanded values, and runs before
  mapstructure/validator processing.
- YAML is the project default config and dump format, but the Viper loader must
  support the common Viper formats where practical. Both server and client
  binaries must support `--version`.
- Authentication material, session secrets, tokens, passwords, and private keys
  must not be logged. Diagnostics should preserve traceability without exposing
  credentials.
- Metrics labels must use the documented low-cardinality allowlist. Do not add
  username, user hash, recipient, session ID, trace ID, request ID, client IP,
  raw backend identifier, raw error text or secret-bearing values as metric
  labels.
- TLS, listener exposure, backend authentication, control APIs, and operational
  overrides should default to the safest usable behavior.

## Commit Log Format

Use structured commit messages with a fixed, capitalized prefix and a concise
headline:

```text
Prefix: Summarize the main change

- Detail the most relevant implementation work
- Mention tests, guardrails, or generated files when relevant
- Call out operator-facing behavior, config, packaging, or dependency changes
```

Allowed prefixes:

- `Add`: new functionality, files, or supported behavior
- `Change`: behavior changes that are not primarily bug fixes
- `Fix`: bug fixes and regressions
- `Remove`: deleted behavior, files, or obsolete paths
- `Refactor`: internal restructuring without intended behavior changes
- `Test`: test-only changes
- `Docs`: documentation-only changes
- `Build`: Makefile, Docker, packaging, release, or toolchain changes
- `Ci`: GitHub Actions, GitLab CI, or automation changes
- `Vendor`: dependency and vendored module updates
- `Security`: hardening or vulnerability-related changes
- `Chore`: repository maintenance that does not fit the other prefixes

The subject line should state what was fundamentally done. The body should be a
short bullet list that refines the headline with the essential work completed.
Split unrelated work into separate commits when no single prefix and headline
describe the change cleanly.

## Quality Gates

`make guardrails` runs the local quality gate:

- `make fix`
- `make vet`
- `make lint`
- `make test`
- `make race`
- `make e2e`
- `make build-check`

Until the new production Go module is created, module-specific targets skip the
root code checks after validating the shared tooling configuration.
