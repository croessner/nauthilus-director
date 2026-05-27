# M4 Observability Specification

Status: implementation-ready M4 specification

This document defines the observability polish milestone for
`nauthilus-director`. M4 turns the existing secret-safe event vocabulary,
metric-label policy and prepared trace boundaries into real operator-facing
observability: structured logs, Prometheus metrics, OpenTelemetry traces,
runtime correlation and deterministic tests.

M4 builds on the completed M0 foundation, the completed M1 IMAP MVP and the
completed M2/M3 backend runtime and control implementation. It is not a
proof-of-concept migration. The archived implementation under `poc/` may be
read only as historical source material, and production code must not import
it, preserve its package layout or use it as a compatibility target.

## Source Documents

M4 is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-paths.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-director.1`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.yaml.5`
- `docs/specs/README.md`
- `.gitignore`

If this specification conflicts with those source documents, fix the drift
before implementation continues.

## M4 Goal

M4 implements the first production-grade observability loop:

```text
runtime operation
  -> cohesive domain method
  -> secret-safe observability event
  -> structured log record
  -> bounded Prometheus metric observation
  -> OpenTelemetry span and attributes
  -> externally verifiable operator output
```

The final result is not just a `/metrics` placeholder and not just span names in
constants. It is one shared observability service used by listener lifecycle,
IMAP sessions, Nauthilus auth, routing, Redis state, backend selection, backend
health, proxy lifetime, REST handlers, CLI-visible runtime operations, safe
reload and Fx lifecycle logging.

M4 must preserve the architecture boundary that observability records behavior
without owning behavior. Metrics, logs and traces must not become a second
runtime model, a selector implementation, a Redis state source or a place where
protocol handlers smuggle state across package boundaries.

## Delivery Shape

Implement M4 as explicit implementation slices:

1. Observability runtime service, sink lifecycle and Fx wiring.
2. OpenTelemetry trace provider, OTLP exporter and context propagation.
3. Prometheus registry, instruments and generated `/metrics` provider.
4. Structured logging, correlation and redaction policy separation.
5. Runtime instrumentation coverage for existing M0 through M3 behavior.
6. E2E collector/scrape proof, documentation updates and final review.

The slices may be committed separately, but M4 is not complete until the
production `nauthilus-director` process emits useful logs, metrics and traces
through configured sinks and the deterministic guardrail lane proves those
outputs through public process boundaries.

## Global Scope

In scope:

- Replace the no-op/default recorder path with a production observability
  service that fans normalized events into logs, metrics and traces.
- Wire observability through Fx so lifecycle ordering is explicit and shutdown
  flushes exporters within the configured process shutdown timeout.
- Implement OpenTelemetry tracing for prepared boundaries:
  - accepted frontend session
  - IMAP pre-auth handling
  - Nauthilus authentication
  - routing fact resolution
  - backend selection
  - backend connect and backend auth
  - proxy pipe lifetime
  - REST request handling
  - reload and runtime control operations
  - backend health checks
- Implement the OTLP trace exporter for the existing
  `observability.tracing.*` config surface.
- Implement Prometheus metrics through a process-local registry and the
  generated `/metrics` REST boundary.
- Keep metric labels restricted to the documented low-cardinality allowlist.
- Split log-field, trace-attribute and metric-label policies so logs and traces
  may carry operator diagnostics that are still forbidden as metric labels.
- Preserve secret-safe defaults for credentials, SASL blobs, bearer tokens,
  private keys and protected config values.
- Add duration and byte observations for protocol, backend, REST, Redis and
  proxy work where the existing event hooks do not already carry them.
- Add deterministic unit tests for metric registration, trace export, log
  redaction, correlation and exporter lifecycle.
- Add E2E proof that starts the production `nauthilus-director` binary, scrapes
  `/metrics`, exercises a representative IMAP/control flow and verifies
  secret-safe observable output.
- Update operator-facing documentation when behavior, supported config values
  or generated config docs change.

Out of scope:

- POP3, LMTP or ManageSieve protocol entrypoints.
- LMTP recipient metrics from real LMTP traffic before M5.
- A second management process for metrics or tracing.
- Runtime mutations to YAML configuration.
- User, recipient, client IP, session ID, request ID, trace ID, raw backend
  identifier or raw error text as Prometheus labels.
- Logging authentication material, passwords, bearer tokens, SASL blobs,
  private keys or protected config values, even when debug logging is enabled.
- Authenticated remote OTLP header maps or secret-bearing exporter credentials
  unless a typed protected config shape, docs, generated references and tests
  are added in the same implementation slice.
- pprof and block-profile HTTP exposure. The existing profile config remains
  typed config, but optional diagnostic profile endpoints belong to M8 unless a
  later architecture decision moves them forward.
- Replacing deterministic fake-service E2E with Docker interoperability tests.

## Stable Config Paths

M4 uses the existing stable observability config paths:

- `observability.log.level`
- `observability.log.json`
- `observability.log.add_source`
- `observability.log.redact_secrets`
- `observability.log.username_hash_salt_file`
- `observability.metrics.enabled`
- `observability.metrics.path`
- `observability.metrics.runtime_metrics`
- `observability.tracing.enabled`
- `observability.tracing.service_name`
- `observability.tracing.exporter`
- `observability.tracing.endpoint`
- `observability.tracing.sample_ratio`
- `observability.profiles.pprof.enabled`
- `observability.profiles.block.enabled`

M4 must not rename, remove or invert these paths without an explicit
breaking-change decision plus docs, examples, migration notes and tests. It may
validate currently defined values more strictly when the stricter behavior
follows the architecture and avoids silently advertising unsupported behavior.

M4 keeps the generated OpenAPI `GET /metrics` path as the v1 control-plane
metrics contract. Because arbitrary metrics paths cannot be represented by the
current generated route without changing the OpenAPI contract, M4 must reject
non-`/metrics` values for `observability.metrics.path` or first update the
OpenAPI contract and generated artifacts. It must not silently ignore the
configured path.

## Target Package Boundaries

M4 expands existing production packages:

```text
internal/observability/
internal/app/
internal/listener/
internal/protocol/imap/
internal/nauthilus/
internal/routing/
internal/backend/
internal/state/
internal/runtime/
internal/proxy/
internal/rest/
internal/rest/adapters/
test/e2e/
docs/
```

Boundary rules:

- `internal/observability` owns recorder construction, structured logging,
  metric instruments, trace providers, exporter lifecycle, redaction policy and
  policy tests.
- `internal/app` owns Fx wiring, startup ordering and shutdown flushing for
  observability dependencies.
- `internal/listener` records listener/session lifecycle observations but must
  not own metric instruments or trace exporters.
- `internal/protocol/imap` records protocol observations and span boundaries but
  must not export telemetry directly.
- `internal/nauthilus` records auth transport observations without leaking
  credentials, request bodies, bearer material or protected caller secrets.
- `internal/routing` records logical routing duration and outcome without
  exposing unsafe auth attributes.
- `internal/backend` records selector, health and backend-connect observations
  while keeping backend state ownership inside the backend package.
- `internal/state` records Redis operation observations and failure classes
  without exposing raw keys that contain affinity hashes, session IDs or user
  material.
- `internal/runtime` records REST/CLI-visible runtime operations without
  becoming a telemetry-specific orchestration layer.
- `internal/proxy` records byte counts, direction, duration and close reason
  without parsing post-auth protocol contents.
- `internal/rest` and `internal/rest/adapters` expose `/metrics`, request
  spans, status classes and route names through generated OpenAPI boundaries.

Do not add package-level mutable global telemetry state. Use cohesive types and
narrow interfaces so tests can create isolated registries, exporters and
recorders without cross-test leakage.

## M4.1 Observability Runtime and Sink Lifecycle

### Purpose

Create the production observability service that fans normalized events into
logging, metrics and tracing sinks with explicit lifecycle ownership.

### In Scope

- Add a cohesive observability runtime type that owns:
  - structured logger
  - Prometheus registry and instruments
  - OpenTelemetry tracer provider
  - OTLP trace exporter
  - shutdown and flush behavior
- Build the runtime from typed `config.ObservabilityConfig`.
- Provide a single recorder implementation to existing packages through Fx.
- Keep `observability.NoopRecorder` available for focused unit tests and
  packages that intentionally do not emit telemetry.
- Normalize invalid or nil sink combinations into safe behavior:
  - logging enabled by default
  - metrics enabled only when configured
  - tracing enabled only when configured
  - no-op tracing provider when tracing is disabled
- Fail typed config validation for impossible local configuration, such as an
  unknown tracing exporter, invalid sample ratio or unsupported metrics path.
- Do not fail the mail/control data path solely because a remote collector is
  temporarily unavailable after successful startup.
- Flush trace exporters and stop background telemetry work during Fx shutdown.

### Out of Scope

- Making observability sinks mutable through REST.
- Adding a dedicated telemetry sidecar process.
- Replacing package-local domain events with direct calls into Prometheus or
  OpenTelemetry APIs.

### Expected Files or Packages

```text
internal/observability/runtime.go
internal/observability/recorder.go
internal/observability/logger.go
internal/observability/prometheus.go
internal/observability/otel.go
internal/observability/runtime_test.go
internal/app/module.go
internal/app/server.go
```

### Implementation Notes

- Use Go standard library logging primitives where they satisfy the behavior,
  and add external packages only where they clearly reduce risk or maintenance
  cost.
- Prometheus and OpenTelemetry libraries are justified M4 dependencies because
  the project needs standards-compatible output. Pin exact released versions
  during implementation, then run `go mod tidy` and `go mod vendor`.
- The observability runtime must not use global default registries in a way that
  causes duplicate metric registration or cross-test state leakage.
- Startup must order observability before listeners, health runners, REST
  server and reapers so early lifecycle events are not dropped.
- Shutdown must stop protocol/control work first, then flush and stop
  observability exporters within the remaining shutdown timeout.
- Collector export failures after startup must be observable as bounded
  telemetry failure counters/log events, not as unbounded log spam.

### Required Unit Tests

- Runtime construction succeeds for default observability config.
- Runtime construction rejects unknown tracing exporter values.
- Runtime construction rejects `sample_ratio` outside `0.0` through `1.0`.
- Runtime construction rejects unsupported non-`/metrics` paths unless OpenAPI
  route generation is updated in the same change.
- Disabled metrics returns a disabled metrics provider without registering
  runtime instruments.
- Disabled tracing returns a no-op tracer provider without attempting OTLP
  export.
- Shutdown flushes the trace provider and is idempotent.
- Multiple runtime instances in one test process do not duplicate Prometheus
  collectors.

### Required Integration or E2E Tests

- Start the production server with default observability config and verify it
  reaches readiness.
- Start the production server with tracing disabled and verify normal IMAP and
  control behavior still works.
- Start the production server with metrics disabled and verify the metrics
  endpoint reports the configured disabled state without exposing stale data.

### Acceptance Criteria

- One production recorder fans events into configured sinks.
- Fx owns observability lifecycle ordering and shutdown flushing.
- Invalid local observability config fails before listeners bind.
- Collector outages after startup do not break normal protocol/control work.

### Review Checklist

- Verify no package owns its own Prometheus registry or OTLP exporter.
- Verify no observability initialization reads Viper or raw config maps.
- Verify no package-level mutable telemetry state leaks across tests.

## M4.2 OpenTelemetry Traces and Context Propagation

### Purpose

Emit useful OpenTelemetry traces for existing session, auth, routing, backend,
proxy, REST and runtime-control boundaries without exposing credentials or
high-cardinality user material.

### In Scope

- Implement an OpenTelemetry tracer provider for
  `observability.tracing.enabled`.
- Implement the OTLP trace exporter for `observability.tracing.exporter: otlp`.
- Use `observability.tracing.service_name` as the resource service name.
- Include process version and component resource attributes when available.
- Use parent-based trace ID ratio sampling from
  `observability.tracing.sample_ratio`.
- Preserve prepared span names:
  - `nauthilus_director.session`
  - `nauthilus_director.imap.pre_auth`
  - `nauthilus_director.nauthilus.auth`
  - `nauthilus_director.routing.resolve`
  - `nauthilus_director.backend.select`
  - `nauthilus_director.backend.connect`
  - `nauthilus_director.proxy.pipe`
  - `nauthilus_director.rest.request`
  - prepared future boundaries for LMTP, ManageSieve and POP3
- Propagate context through the existing production call path so child spans
  attach to the accepted session or REST request where applicable.
- Add span attributes only from the bounded telemetry policy.
- Add span status and error classification without recording raw error text.
- Record backend identifiers in traces only when needed for operator diagnosis;
  never use backend identifiers as metric labels.
- Add trace ID and span ID to structured logs when an active span context
  exists.

### Out of Scope

- Accepting arbitrary frontend mail-protocol trace context from clients.
- Emitting raw usernames, recipients, client IPs, passwords, tokens, SASL blobs
  or protected config values as span attributes.
- Remote authenticated OTLP headers without a typed protected config shape.
- Tracing POP3, LMTP or ManageSieve runtime behavior before those protocol
  entrypoints exist.

### Expected Files or Packages

```text
internal/observability/otel.go
internal/observability/tracing.go
internal/observability/attributes.go
internal/listener/observability.go
internal/protocol/imap/observability.go
internal/nauthilus/
internal/routing/
internal/backend/
internal/runtime/
internal/proxy/
internal/rest/
```

### Implementation Notes

- Use one internal helper to start spans from a `TraceBoundary` so span names
  remain centralized.
- Existing event recording may create or enrich spans, but it must not require
  domain packages to import exporter-specific code.
- REST request spans should use generated route names or normalized route
  templates, not raw URLs with query strings.
- Nauthilus auth spans may include transport and mechanism; they must not
  include request bodies or credentials.
- Routing spans may include resolver operation, result and reason class; they
  must not include unsafe auth attributes.
- Redis spans or events may include operation class and Redis mode; they must
  not include raw keys.
- Backend connect spans may include protocol, pool, shard and backend
  identifier as trace attributes, but backend identifier remains forbidden as a
  Prometheus label.

### Required Unit Tests

- Prepared span names still match the architecture document.
- Tracing disabled avoids exporter construction.
- Tracing enabled uses parent-based ratio sampling from config.
- Span attributes reject or redact secret-bearing fields.
- Span attributes reject raw usernames, recipients, client IPs and Redis keys.
- Structured log records include trace/span correlation when a span context is
  active.

### Required Integration or E2E Tests

- Run a production-server IMAP login/proxy scenario with an in-process or local
  test collector and verify spans for session, pre-auth, Nauthilus auth,
  routing, backend selection, backend connect and proxy lifetime.
- Run a REST runtime operation and verify a REST span with a normalized route
  attribute.
- Verify exported spans do not contain passwords, bearer tokens, SASL blobs or
  raw usernames.

### Acceptance Criteria

- Traces are emitted through OTLP when tracing is enabled and a collector is
  available.
- Missing or unavailable collectors after startup do not break mail/control
  behavior.
- Span naming and attributes remain centralized and policy-checked.

### Review Checklist

- Verify trace attributes do not bypass the metric/log safety policy.
- Verify mail protocol handlers do not parse external trace headers.
- Verify no raw error text is used as a span attribute.

## M4.3 Prometheus Metrics and `/metrics` Provider

### Purpose

Expose real Prometheus metrics through the generated control API while keeping
cardinality bounded and preserving the OpenAPI-first REST boundary.

### In Scope

- Replace the placeholder metrics response with a Prometheus-compatible gatherer.
- Use a process-local Prometheus registry owned by the observability runtime.
- Expose metrics through `GET /metrics` in the generated REST boundary.
- Register counters, gauges and histograms for existing behavior:
  - process up state
  - listener starts/stops
  - active sessions
  - session starts/ends
  - pre-auth command outcomes
  - Nauthilus auth totals and durations
  - routing resolver totals and durations
  - affinity open/close/clear outcomes
  - backend selection totals and durations
  - backend health state aggregates
  - backend maintenance/drain/runtime operation totals
  - backend active-session aggregate counts
  - proxy bytes by direction
  - proxy lifetime durations
  - REST request totals and durations
  - reload totals and outcomes
  - Redis operation totals and durations
  - runtime operation totals
- Use explicit histogram buckets appropriate to mail-session, REST, Redis and
  backend-connect timing rather than relying on unreviewed defaults everywhere.
- Register runtime Go/process collectors only when
  `observability.metrics.runtime_metrics` is true.
- Serve metrics only when `observability.metrics.enabled` is true.
- Keep metrics endpoint responses free of protected values and raw
  high-cardinality identifiers.

### Out of Scope

- Metrics labels outside the existing allowlist.
- Per-user, per-session, per-recipient, per-client-IP or per-backend-identifier
  time series.
- Dynamic metrics path aliases outside the OpenAPI contract.
- Scraping Redis directly from the metrics endpoint as a replacement for the
  runtime domain model.

### Expected Files or Packages

```text
internal/observability/prometheus.go
internal/observability/metrics.go
internal/observability/policy.go
internal/rest/adapters/handler.go
internal/rest/server_test.go
internal/observability/*_test.go
test/e2e/
```

### Implementation Notes

- Allowed metric labels remain:

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

- Forbidden metric labels remain:

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

- Backend health and maintenance metrics must aggregate by bounded dimensions
  such as protocol, backend pool, shard tag, maintenance mode, result and reason
  class. Raw backend identifiers belong in REST diagnostics, logs and traces,
  not in metrics.
- REST metrics must use route templates or operation names, not raw paths with
  embedded user/session/backend values.
- Redis metrics must use operation classes such as `open`, `heartbeat`,
  `close`, `lookup`, `reap`, `backend_runtime_set` and `user_move`, not raw
  Redis command text or keys.
- Metrics must be deterministic enough for tests to assert names and labels
  without depending on timing-sensitive values.

### Required Unit Tests

- Every registered metric uses only allowlisted labels.
- Forbidden labels are rejected before registration or observation.
- Metrics disabled prevents business metrics from being served.
- Runtime collectors are registered only when configured.
- REST route labels use generated route templates or stable operation names.
- Backend health metrics do not include backend identifiers.
- Redis metrics do not include Redis keys.
- Repeated runtime construction in tests does not panic on duplicate
  registrations.

### Required Integration or E2E Tests

- Start the production server and scrape `/metrics`.
- Perform a successful IMAP login/proxy flow and verify session, auth, routing,
  backend selection and proxy metrics change.
- Perform a REST runtime operation and verify REST/runtime metrics change.
- Verify the metrics body does not contain usernames, passwords, bearer tokens,
  SASL blobs, session IDs, raw client IPs or raw backend identifiers.

### Acceptance Criteria

- `/metrics` returns real Prometheus output from the generated control API.
- All metrics use the documented low-cardinality allowlist.
- Metrics remain useful without leaking user, session, recipient or credential
  material.

### Review Checklist

- Verify no metric label can be populated from raw request or Redis state.
- Verify the configured metrics path is not silently ignored.
- Verify metrics tests cover both enabled and disabled modes.

## M4.4 Structured Logging and Correlation

### Purpose

Make structured logs useful for operations while keeping runtime logs safe by
default and clearly separating log-field policy from metric-label policy.

### In Scope

- Implement structured logging from the production recorder.
- Honor:
  - `observability.log.level`
  - `observability.log.json`
  - `observability.log.add_source`
  - `observability.log.redact_secrets`
- Keep credential-bearing values redacted or omitted regardless of log level.
- Log one normalized event record per recorded runtime event.
- Include stable fields where available:
  - event name
  - component
  - operation
  - result
  - reason class
  - protocol
  - service
  - listener
  - transport
  - mechanism
  - backend pool
  - shard tag
  - maintenance mode
  - route template
  - status class
  - trace ID and span ID when tracing context exists
- Allow backend identifiers in logs for operator diagnostics when they are
  necessary to understand backend health, drain, runtime override or connect
  failures.
- Keep raw usernames, recipients, client IPs, session IDs, passwords, tokens,
  SASL blobs, private keys and protected config values out of logs by default.
- Keep Fx lifecycle logging routed through the same recorder and redaction
  policy.
- Add tests that debug-level output still does not leak secrets.

### Out of Scope

- Logging post-auth IMAP command payloads.
- Logging Sieve script contents before ManageSieve exists.
- Logging message content or LMTP DATA payloads in future protocol work.
- Adding user-hash correlation to runtime logs in M4. The existing protected
  `username_hash_salt_file` path remains reserved until a later explicit
  privacy decision defines how pseudonymous user correlation should behave.

### Expected Files or Packages

```text
internal/observability/logger.go
internal/observability/logging.go
internal/observability/policy.go
internal/app/fx_logger.go
internal/observability/*_test.go
test/e2e/
```

### Implementation Notes

- `redact_secrets: false` must not allow credentials, bearer tokens, SASL blobs
  or private keys into runtime logs. If the setting is retained for future
  diagnostics, its behavior must be narrower than "log secrets".
- Logs may carry high-cardinality diagnostic values only when explicitly
  allowed by the log policy. They must not reuse the metric allowlist as a
  blanket log policy.
- Trace IDs and span IDs are useful in logs but remain forbidden as metric
  labels.
- Backend identifiers are useful in logs and traces but remain forbidden as
  metric labels.
- Request bodies and route lookup input must not be logged. Log normalized route
  templates and validation outcomes instead.

### Required Unit Tests

- JSON logging emits parseable structured records.
- Text logging emits stable key/value records.
- Log level filtering drops debug records at info level.
- Debug logging does not include passwords, tokens, SASL blobs or private keys.
- Backend identifiers can be present in allowed diagnostic logs but are still
  rejected as metric labels.
- Trace/span IDs can be present in logs but are still rejected as metric labels.
- Fx errors are redacted through the shared policy.

### Required Integration or E2E Tests

- Start the production server with JSON logs and capture observable output from
  an IMAP login/proxy flow.
- Verify logs include event, operation, result and reason class for the flow.
- Verify logs do not include the test password, bearer token, SASL blob, raw
  username, raw session ID or protected config values.

### Acceptance Criteria

- Logs are structured, correlated and useful for runtime diagnosis.
- Secret redaction is enforced independently of log level.
- Log policy and metric-label policy are distinct and tested.

### Review Checklist

- Verify no `fmt.Printf` or raw logger shortcut bypasses the recorder for
  production events.
- Verify no runtime error is logged as raw unbounded text when it may contain
  credentials or high-cardinality values.
- Verify `redact_secrets` cannot be interpreted as permission to log secrets.

## M4.5 Runtime Instrumentation Coverage

### Purpose

Ensure the existing M0 through M3 runtime behavior emits enough telemetry to
debug real deployments without adding telemetry-specific business logic.

### In Scope

- Instrument listener lifecycle:
  - bind success/failure
  - accept-loop stop
  - shutdown timeout
- Instrument IMAP sessions:
  - session start/end
  - TLS/STARTTLS mode
  - PROXY protocol accept/reject reason class
  - pre-auth command outcomes
  - auth mechanism
  - backend connect/auth/proxy outcomes
- Instrument Nauthilus auth:
  - transport
  - authority/service name
  - mechanism
  - result
  - reason class
  - duration
- Instrument routing:
  - resolver operation
  - result
  - reason class
  - duration
- Instrument Redis state operations:
  - operation class
  - Redis mode
  - result
  - reason class
  - duration
- Instrument backend selection and health:
  - selection result
  - exclusion reason class
  - health state changes
  - maintenance/drain/runtime changes
  - active-session aggregate changes
- Instrument runtime control:
  - backend runtime operations
  - user move/kick/affinity clear
  - session kill/reap
  - route lookup
  - reload
- Instrument REST:
  - route template
  - method
  - status class
  - duration
- Instrument proxy:
  - bytes by direction
  - duration
  - close reason class

### Out of Scope

- Parsing post-auth protocol commands for telemetry.
- Emitting telemetry from fake services as if it were production telemetry.
- Adding high-cardinality dimensions to make one-off debugging easier.

### Expected Files or Packages

```text
internal/listener/observability.go
internal/protocol/imap/observability.go
internal/nauthilus/
internal/routing/
internal/backend/
internal/state/
internal/runtime/observability.go
internal/proxy/observability.go
internal/rest/
internal/observability/
```

### Implementation Notes

- Add timing helpers at domain boundaries rather than sprinkling stopwatch code
  through low-level parsing loops.
- Redis instrumentation must wrap state store methods, not every internal Lua
  helper branch.
- REST instrumentation should happen at the generated route wrapper or adapter
  boundary so route labels are stable.
- Proxy byte counters must use direction labels such as `client_to_backend` and
  `backend_to_client`.
- Reason classes must remain bounded and normalized before reaching metrics.
- Where current event hooks lack duration or byte data, extend the event model
  in a backward-compatible internal way rather than adding parallel telemetry
  calls.

### Required Unit Tests

- Listener events map failure causes to bounded reason classes.
- IMAP auth/proxy observations never include credentials or SASL blobs.
- Nauthilus auth observations classify timeout, denied, tempfail and malformed
  responses without raw response bodies.
- Routing observations filter unsafe auth attributes.
- Redis observations hide raw keys and classify ambiguous script results.
- Proxy observations count both directions and classify close outcomes.
- Runtime-control observations match REST/CLI operation names.

### Required Integration or E2E Tests

- Exercise successful IMAP login/proxy and verify all major event categories are
  visible through logs and metrics.
- Exercise an auth failure and verify the failure is observable without leaking
  the attempted credential.
- Exercise one runtime-control mutation and verify backend/runtime observability
  changes through public REST or CLI behavior.
- Exercise route lookup and verify it remains side-effect-free while observable.

### Acceptance Criteria

- Existing runtime behavior is observable at the boundaries operators need.
- Telemetry does not introduce a second implementation of routing, selection or
  runtime state.
- All new observations are tested for secret safety and bounded labels.

### Review Checklist

- Verify instrumentation is attached to cohesive domain methods.
- Verify no instrumentation requires protocol packages to mutate observability
  internals.
- Verify telemetry does not hide or swallow production errors.

## M4.6 E2E, Documentation and Guardrails

### Purpose

Prove M4 observability through external system boundaries and keep operator
documentation aligned with the implemented behavior.

### In Scope

- Extend deterministic E2E tests to:
  - start the production `nauthilus-director` binary
  - start fake Nauthilus and fake IMAP backends
  - optionally start an in-process or local OTLP test collector
  - scrape the generated `/metrics` endpoint
  - capture structured logs
  - verify an IMAP login/proxy path produces logs, metrics and traces
  - verify a REST/CLI runtime operation produces logs, metrics and traces
- Keep `make e2e` Docker-independent.
- Keep `make e2e-interop` as the real IMAP regression lane and run it when M4
  changes IMAP backend/proxy/bootstrap behavior that real Dovecot can regress.
- Update docs when implementation changes:
  - `docs/config/nauthilus-director.target.yml`
  - `docs/config/metadata.yml`
  - generated `docs/reference/config-defaults.yaml`
  - generated `docs/reference/config-paths.md`
  - `docs/man/nauthilus-director.1`
  - `docs/man/nauthilus-directorctl.1`
  - `docs/man/nauthilus-director.yaml.5`
  - a dedicated operator observability document under `docs/` if the final
    behavior needs more than manpage/reference coverage
- Run validation through Makefile targets.

### Out of Scope

- Relying on real external collector infrastructure in the guardrail lane.
- Treating Docker interop as the only observability proof.
- Adding tutorial-style operational migration docs; broad production hardening
  documentation remains M8.

### Expected Files or Packages

```text
test/e2e/
docs/
docs/config/metadata.yml
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
docs/man/
Makefile
scripts/
```

### Implementation Notes

- E2E tests should assert observable behavior through public sockets, REST
  endpoints, CLI commands, captured process output and test collectors.
- E2E tests must not import internal packages to inspect metric registries or
  trace exporters.
- Test collectors must use bounded timeouts and deterministic cleanup.
- Metrics assertions should check metric names and labels, not fragile exact
  timing values.
- Log assertions should check structured fields and absence of secrets.
- Trace assertions should check span names, parent/child shape where practical
  and absence of secrets.

### Required Unit Tests

- Documentation generator metadata covers any new config paths.
- Generated docs remain stable after `make generate-docs`.
- OpenAPI generated artifacts remain stable if the metrics route contract
  changes.

### Required Integration or E2E Tests

- Production binary emits metrics for a successful IMAP login/proxy flow.
- Production binary emits structured logs for the same flow without leaking
  credentials.
- Production binary exports expected spans to a test collector when tracing is
  enabled.
- REST/CLI runtime operation telemetry is visible through logs, metrics and
  traces.
- Metrics disabled, tracing disabled and debug logging modes are covered by
  focused integration or E2E checks.

### Acceptance Criteria

- `make docs-check` passes after documentation changes.
- `make check-openapi` passes after any OpenAPI route or generated-code change.
- `make e2e` proves the M4 observability path through public system boundaries.
- `make guardrails` passes before M4 is marked complete or committed.
- `make e2e-interop` is run and recorded when M4 changes IMAP interop-sensitive
  paths.

### Review Checklist

- Verify E2E tests do not read internal registries or exporters directly.
- Verify docs do not advertise unsupported exporter, metrics or profile modes.
- Verify generated config docs and manpages match actual behavior.

## Top-Level Acceptance Checklist

M4 is complete only when all items below are true:

- [ ] One production observability runtime owns logging, metrics, tracing,
      exporters and shutdown flushing.
- [ ] Fx starts observability before listeners, REST handlers, health runners
      and reapers, then flushes observability during shutdown.
- [ ] Invalid observability config fails before listeners bind.
- [ ] Collector outages after startup do not break mail/control behavior.
- [ ] Tracing uses OpenTelemetry with the configured service name, OTLP exporter
      and parent-based ratio sampling.
- [ ] Prepared span names match the architecture document.
- [ ] IMAP session, pre-auth, Nauthilus auth, routing, backend selection,
      backend connect, proxy, REST, reload, runtime-control and health paths
      produce traces where implemented behavior exists.
- [ ] Trace attributes are policy-checked and do not contain credentials, SASL
      blobs, bearer tokens, raw usernames, recipients, client IPs or Redis keys.
- [ ] Logs include structured event, operation, result and reason-class fields.
- [ ] Logs include trace/span correlation when available.
- [ ] Runtime logs never include credentials, bearer tokens, SASL blobs, private
      keys or protected config values, regardless of log level.
- [ ] Backend identifiers may appear in logs/traces only for diagnostics and
      remain forbidden as metric labels.
- [ ] `/metrics` returns real Prometheus output from the generated control API
      when metrics are enabled.
- [ ] Metrics disabled mode is explicit and tested.
- [ ] Runtime Go/process collectors obey `observability.metrics.runtime_metrics`.
- [ ] All metric labels are from the documented low-cardinality allowlist.
- [ ] Metrics never contain username, user hash, recipient, session ID,
      trace ID, request ID, client IP, raw backend identifier, raw error text or
      secret-bearing values as labels.
- [ ] Redis operation telemetry uses operation classes and Redis mode, not raw
      keys or raw command text.
- [ ] REST telemetry uses generated route templates or stable operation names,
      not raw URL paths with embedded values.
- [ ] Proxy telemetry records byte counts by direction and duration without
      parsing post-auth command payloads.
- [ ] Deterministic E2E proves metrics, logs and traces through the production
      server binary and public system boundaries.
- [ ] Secret-safety E2E checks cover credentials, bearer tokens, SASL blobs,
      raw usernames, session IDs and protected config values.
- [ ] Config docs, generated references, OpenAPI artifacts and manpages are
      updated when behavior changes.
- [ ] `make guardrails` is the final local gate before any commit or pull
      request that contains M4 implementation work.

## Required M4 Review Pass

Before closing M4, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `docs/ARCHITECTURE_ROADMAP.md`, especially sections 17, 18, 19, 20,
   21, 22, 23 and 24.
3. Re-read `docs/specs/implementation/M0_FOUNDATION_SPEC.md`.
4. Re-read `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`.
5. Re-read `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`.
6. Re-read `docs/config/nauthilus-director.target.yml`.
7. Re-read `docs/reference/config-paths.md`.
8. Re-read `docs/specs/openapi/nauthilus-director.yaml`.
9. Compare implementation and docs against this specification and the source
   documents.
10. Fix drift, duplicated telemetry state, false config support, unsupported
    exporter documentation, OpenAPI route mismatch, raw high-cardinality metric
    labels and accidental secret logging.
11. Run `make check-openapi` after any OpenAPI schema or generated-code change.
12. Run `make check-docs` after any typed config, config metadata or generated
    docs change.
13. Run targeted observability, config, REST, IMAP, runtime and state tests.
14. Run `make e2e` and record the M4 observability proof.
15. Run and record `make e2e-interop` when IMAP backend/proxy/bootstrap
    behavior that real Dovecot interoperability can regress was changed.
16. Run `make guardrails` before any commit or pull request.
17. Record `git status --short` and the exact validation result in the M4
    closeout.

## Decisions and Open Questions

These decisions are recorded so M4 implementation does not rediscover them in
code.

1. Decision: `/metrics` remains the canonical v1 generated control API path.

   `observability.metrics.path` is already a stable config path, but the
   current OpenAPI contract exposes `GET /metrics`. M4 must not silently ignore
   a non-default path. The implementation either keeps `/metrics` as the only
   supported value and validates that explicitly, or changes the OpenAPI
   contract and generated artifacts first. Dynamic undocumented aliases are not
   part of M4.

2. Decision: collector unavailability is not a mail-path failure after startup.

   Invalid local observability config fails closed before listeners bind.
   Collector outages, backpressure or transient export failures after startup
   must be bounded, observable and non-fatal for normal protocol and control
   behavior.

3. Decision: M4 implements OTLP tracing without secret-bearing exporter
   headers.

   The existing tracing config is enough for a local or explicitly configured
   OTLP collector endpoint. Authenticated collector headers or token-bearing
   exporter configuration require a typed protected config shape, redaction
   metadata, generated docs and tests in a later explicit change.

4. Decision: log, trace and metric policies are related but distinct.

   Prometheus labels remain low-cardinality only. Logs and traces may carry
   trace/span IDs and backend identifiers for operator diagnosis, but they still
   must not contain credentials, SASL blobs, bearer tokens, protected config
   values, raw usernames, recipients or raw client IPs by default.

5. Decision: pprof and block profile endpoints remain out of M4.

   The typed profile config remains present, but exposing diagnostic profile
   endpoints belongs to M8 production hardening unless a later architecture
   decision explicitly moves it forward.

No blocking open questions remain in this specification. If implementation
uncovers a need for non-local OTLP credentials, dynamic metrics paths or
pseudonymous user correlation, record that as a new explicit decision before
changing config or public behavior.
