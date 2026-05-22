# Engineering Policy

These rules are mandatory for coding changes in this repository.

## Must Rules

- MUST: Keep the project on Go 1.26 across module metadata, CI, Docker builds,
  and documentation.
- MUST: Apply security-by-design and security-by-default. Defaults must be
  restrictive, ambiguous authentication or transport state must fail closed, and
  weaker or compatibility-oriented behavior must require explicit configuration.
- MUST: Use strict object-oriented boundaries in Go. State must be encapsulated
  in cohesive types, behavior must be exposed through methods and narrow
  interfaces, and composition is preferred over package-level mutable state.
- MUST: Apply DRY intentionally. Shared protocol, backend, auth, config, and
  observability behavior must live in one clear abstraction instead of being
  duplicated across packages.
- MUST: Keep external dependencies intentional. Prefer the Go standard library
  or a small local implementation when the behavior is simple,
  security-sensitive, and easy to maintain.
- MUST: Add vendor packages only when they clearly reduce risk, complexity, or
  long-term maintenance cost.
- MUST: Treat the approved foundation dependencies as intentional architecture
  choices: Uber Fx (`go.uber.org/fx`), Viper,
  `github.com/go-playground/validator/v10` for mandatory typed config
  validation after Viper/mapstructure decoding,
  `github.com/redis/go-redis/v9@v9.19.0` for central production state, and
  jsoniter.
- MUST: Support Nauthilus-style environment-variable placeholders in scalar
  config values from the initial config implementation. Expansion must use
  `${NAME}` syntax, keep ordinary `$` literals intact, support `$${NAME}`
  escaping, run before mapstructure/validator processing, never expand map
  keys, and fail closed on missing variables without leaking raw or partially
  expanded values.
- MUST: Stabilize configuration paths by declared stability window. Once a
  config path is declared stable, it must not be renamed, removed or semantically
  inverted without an explicit breaking-change decision and matching docs,
  examples, migration notes and tests.
- MUST: Use OpenAPI from hour zero for the REST control API. The REST contract,
  server boundary, REST DTOs, and generated clients must originate from the
  OpenAPI spec instead of being retrofitted later.
- MUST: Build `nauthilus-directorctl` on the generated OpenAPI REST client SDK.
  CLI code may wrap generated calls for command UX and output formatting, but
  must not duplicate REST DTOs or keep a parallel hand-written API client
  model.
- MUST: Keep OpenAPI-generated artifacts reproducible by documenting the
  generator, pinning `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen`
  to `v2.7.0`, providing a Makefile target, and checking for stale generated
  output in local guardrails.
- MUST: Treat this repository as the production implementation, not as a new
  POC. `poc/` is an archived proof-of-concept only. Production code must not
  import from it or depend on its package structure.
- MUST: Keep Nauthilus as the authentication authority only. It must not make
  director routing or backend-selection decisions.
- MUST: Keep backend selection, health handling, affinity, and proxy lifecycle
  decisions inside `nauthilus-director`.
- MUST: Preserve active user stickiness for user-stateful protocols. While a
  user has open frontend sessions, new sessions for the same affinity key must
  route to the same backend shard unless hard-down, hard-maintenance, explicit
  administrative drain/kill, or fail-closed behavior applies.
- MUST: Use Redis as the production source of truth for active affinity and
  session coordination. Local in-process state may cache Redis state, but must
  not be the authoritative production store.
- MUST: Model active affinity and session coordination as per-affinity Redis
  key groups with Cluster hash tags, lease-based sessions, atomic Lua scripts,
  generation checks for administrative mutations, and fail-closed behavior when
  required Redis state is unavailable or ambiguous.
- MUST: Keep Redis connection, security, authentication, Cluster and Sentinel
  configuration centralized under `storage.redis`. Active affinity uses Redis
  implicitly; feature-specific Redis sub-trees are allowed only if a real
  multi-backend abstraction exists in code.
- MUST: Keep the director-to-Nauthilus authentication transport configurable so
  a deployment can use either HTTP or gRPC.
- MUST: Delegate OIDC-backed bearer-token validation to Nauthilus by default.
  SASL `XOAUTH2` and `OAUTHBEARER` handlers may parse envelopes only far enough
  to pass mechanism identity and bearer material to Nauthilus without logging
  secrets.
- MUST: Keep REST and CLI mutations runtime-only. They may move or kick users,
  adjust backend runtime weight, mark backends in/out, and drain hosts through
  Redis-backed runtime state, but must never rewrite YAML configuration.
- MUST: Keep route lookup as a director-only, side-effect-free routing
  diagnostic. It must not call Nauthilus, authenticate credentials, create
  sessions, refresh leases or mutate Redis state.
- MUST: Keep soft and hard maintenance semantics distinct. Soft maintenance
  excludes new initial placements while preserving existing sessions and active
  pins by default; hard maintenance excludes all new sessions and may terminate
  existing sessions after explicit grace. Maintenance and drain operations must
  be auditable.
- MUST: Run the v1 REST control API in the main `nauthilus-director` process on
  a dedicated `runtime.servers.control` listener. A separate management process
  is out of scope unless a later architecture decision explicitly adds it.
- MUST: Never log authentication material, session secrets, tokens, passwords,
  or private keys. Diagnostics must preserve traceability without exposing
  credentials.
- MUST: Keep metrics labels on a strict low-cardinality allowlist. Usernames,
  user hashes, recipients, session IDs, trace IDs, request IDs, client IPs, raw
  backend identifiers, raw error text and secret-bearing values must not be
  metric labels.
- MUST: Keep TLS, listener exposure, backend authentication, control APIs, and
  operational overrides on the safest usable default.
- MUST: Keep domain invariants owned by domain objects. Unrelated packages must
  not mutate session, listener, backend, or auth state directly.
- MUST: Avoid duplicated business rules, validation logic, security checks, and
  transport semantics.
- MUST: Justify new dependencies by a concrete need. Small helpers, trivial
  parsers, wrappers, and convenience code should be implemented clearly and
  safely in-repo instead of pulled in as vendor packages.
- MUST: Keep generated OpenAPI server boundaries, DTOs, clients, and adapters
  at REST boundaries. Generated code must not replace explicit mail-protocol
  domain objects or backend-selection domain logic.
- MUST: Provide config inspection with canonical defaults via `-d`,
  non-default effective config via `-n`, and protected credential output only
  through explicit `-P`. Redaction is the default.
- MUST: Treat env-expanded secret values exactly like literal or file-provided
  secrets for redaction, logs, metrics, REST config output, and explicit `-P`
  config inspection.
- MUST: Default project config and config-dump output to YAML while supporting
  common Viper config formats where practical.
- MUST: Provide `--version` on both the server binary and
  `nauthilus-directorctl`.
- MUST: Run `make guardrails` before committing or opening a pull request.
- MUST: Keep `.golangci.yml` aligned with the repository guardrail policy and
  run `golangci-lint` through `make lint` or `make guardrails`.
- MUST: Keep lint checks strict enough to report unused variables, constants,
  functions, and types.
- MUST: Keep `vendor/` synchronized after dependency changes.
- MUST: Run Go tests through the Makefile targets so local validation stays
  consistent with CI and release builds.
- MUST: Provide E2E tests for externally visible behavior. E2E tests must prove
  behavior from outside the process by using real binaries or test processes,
  public protocol sockets, REST endpoints and CLI commands; internal package
  calls are not sufficient proof.
- MUST: Prefer unit-test-driven development for core and domain behavior. Write
  or adjust focused unit tests before production code when the behavior can be
  exercised cleanly at unit level.
- MUST: For bugs and regressions, create a failing reproducer test before
  changing production code whenever a stable reproducer is practical. If the
  reproducer fits the project and is not brittle or environment-only, keep it as
  regression coverage.
- MUST: Treat failing unit tests as root-cause evidence. First determine
  whether the failure exposes a defect in core production code; if it does, fix
  production code. Change the unit test only when the test logic, fixture, or
  assertion is demonstrably wrong.
- MUST: Write code comments and technical documentation in English. All
  hand-written named functions and receiver methods must have concise English doc
  comments, including unexported functions and unexported receiver methods.
  Comments must explain intent, invariants, security assumptions, side effects,
  or protocol behavior instead of merely restating the identifier.
- MUST: Add the project copyright and license header to hand-written source
  files: `Copyright (C) 2026 Christian Rößner` and
  `SPDX-License-Identifier: AGPL-3.0-only`. Generated Go files are exempt only
  when they use the standard `Code generated ... DO NOT EDIT.` marker.
- MUST: Name production code after domain behavior, not implementation
  artifacts. Function names, receiver names, identifiers, comments and paths
  must not refer to planning-only documents, phases, specs, milestones, prompt
  IDs, task IDs, rollout labels or similar transient implementation references.
- MUST: Maintain project documentation under `docs/`. Formal specs must live
  under `docs/specs/`; manpages must live under `docs/man/`.
- MUST: Keep product and architecture documentation vendor-neutral. Do not
  frame target behavior by naming other mail-server or director projects unless
  the named project is an actual dependency, protocol peer, or configured
  service.
- MUST: Write commit messages as `Prefix: Concise headline`, using only the
  approved prefixes `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`,
  `Docs`, `Build`, `Ci`, `Vendor`, `Security`, and `Chore`.
- MUST: Use the commit subject as a headline for what was fundamentally done,
  then use the body as a short bullet list of the essential implementation,
  validation, operator-facing, packaging, or dependency details.
- MUST: Split unrelated work into separate commits when no single approved
  prefix and headline describes the change cleanly.
- MUST: Keep `nauthilus-directorctl` organized around clean nested subcommands
  for operator workflows.

## Definition Of Done

- [ ] Dependency changes were followed by `go mod tidy` and `go mod vendor`.
- [ ] `make guardrails` passes locally.
- [ ] `golangci-lint` findings are fixed or intentionally documented.
- [ ] New or changed code has focused test coverage where appropriate.
- [ ] Externally visible behavior has E2E coverage through public protocols,
      REST endpoints or CLI commands where practical.
- [ ] Core and domain behavior was preferably developed unit-test-first where
      clean unit coverage is practical.
- [ ] Config changes cover env placeholder expansion, missing-variable
      diagnostics, map-key behavior, escaping, typed validation order, and
      secret redaction where relevant.
- [ ] Changes to stable config paths are either backward-compatible or backed by
      an explicit breaking-change decision, docs, examples, migration notes and
      tests.
- [ ] Bugs and regressions have a failing reproducer test first, and stable
      project-fitting reproducers remain as regression coverage.
- [ ] Failing unit tests were checked against core production behavior before
      test code was changed.
- [ ] Comments and technical docs introduced by the change are English-only.
- [ ] Hand-written named functions and receiver methods introduced or changed by
      the change have concise English doc comments, including unexported
      functions and unexported receiver methods.
- [ ] Hand-written source files introduced or changed by the change carry the
      project copyright and `SPDX-License-Identifier: AGPL-3.0-only` header;
      generated Go files are exempt only with the standard generated-code marker.
- [ ] Production code names, comments and paths introduced or changed by the
      change describe domain behavior and do not refer to planning-only docs,
      phases, specs, milestones, prompt IDs, task IDs or rollout labels.
- [ ] Project docs live under `docs/`, specs under `docs/specs/`, and manpages
      under `docs/man/`.
- [ ] Product and architecture docs stay vendor-neutral unless naming an actual
      dependency, protocol peer, or configured service.
- [ ] Production code does not depend on `poc/`.
- [ ] Nauthilus integration keeps authentication separate from director backend
      selection.
- [ ] User-stateful protocol routing preserves active Redis-backed affinity
      while matching frontend sessions are open.
- [ ] Redis-backed affinity/session changes preserve per-affinity atomicity,
      lease cleanup, generation checks and fail-closed behavior.
- [ ] REST and CLI mutations update Redis-backed runtime state only and do not
      modify configuration files.
- [ ] Route lookup changes remain director-only and side-effect-free, with no
      Nauthilus calls, credential checks, session creation or Redis mutations.
- [ ] Maintenance changes preserve the documented soft/hard distinction, active
      pin behavior, explicit grace handling and audit metadata.
- [ ] Security-sensitive changes preserve restrictive defaults, fail-closed
      behavior, and secret-safe logging.
- [ ] Metrics changes use only allowed low-cardinality labels, and any new
      label is documented and tested for secrecy and cardinality risk.
- [ ] Domain state is encapsulated behind cohesive types, methods, and narrow
      interfaces.
- [ ] Shared business rules, validation, security checks, and transport
      semantics are not duplicated.
- [ ] New dependencies are justified, minimal, and preferable to a clear local
      implementation.
- [ ] OpenAPI specs, generated artifacts, generator version, Makefile target,
      and stale-output checks are updated together when REST contracts change.
- [ ] CLI REST calls use the generated OpenAPI client SDK rather than a
      parallel hand-written API client.
- [ ] Config defaults, non-default dumps, redaction, protected output, and
      selectable output format behavior are covered when config handling
      changes.
- [ ] Server and CLI version output remains available.
- [ ] Commit messages use the approved prefix, headline, and bullet-list body
      format.
