# M1 IMAP MVP Specification

Status: completed. The IMAP MVP implementation is in place. `make guardrails`
and `make e2e-interop` passed on 2026-05-22; the real-server interoperability
lane used pinned `dovecot/dovecot:2.4.3-dev` with backend STARTTLS. A
2026-05-26 closeout correction wired the production `nauthilus-director`
server entrypoint and added real-binary E2E proof for the public IMAP listener.

This document defines the first externally usable IMAP/IMAPS implementation
phase for `nauthilus-director`. M1 starts configured IMAP listeners,
authenticates through Nauthilus, resolves director-owned routing facts, opens
Redis-backed active affinity/session state, selects an IMAP backend, performs
backend authentication and then enters transparent proxy mode.

M1 builds on the completed M0 foundation. It is not a proof-of-concept
migration. The archived implementation under `poc/` may be read only as
historical source material, and production code must not import it, preserve
its package layout or use it as a compatibility target.

## Source Documents

M1 is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/specs/README.md`
- `.gitignore`

If this specification conflicts with those source documents, fix the drift
before implementation continues.

## M1 Goal

M1 implements the first production IMAP director flow:

```text
IMAP client
  -> listener lifecycle and TLS/STARTTLS
  -> optional trusted HAProxy PROXY protocol
  -> IMAP pre-auth state machine
  -> ID, LOGIN or AUTHENTICATE credential extraction
  -> Nauthilus HTTP/gRPC authentication
  -> director-owned routing fact resolution
  -> Redis-backed active affinity or deterministic initial placement
  -> backend selection
  -> backend connect and backend authentication
  -> transparent bidirectional proxy mode
  -> session lease cleanup and observable outcome
```

M1 remains an IMAP MVP. It supports only the pre-auth protocol surface needed
to authenticate, route, select a backend and proxy. It must not grow into a
complete IMAP server or mailbox semantics implementation.

## Global Scope

In scope:

- Add the production IMAP listener/session/proxy packages outside `poc/`.
- Start configured IMAP and IMAPS listeners from the typed M0 config snapshot.
- Implement strict HAProxy PROXY protocol v1/v2 handling for trusted upstreams.
- Implement IMAP greeting, `CAPABILITY`, `NOOP`, `LOGOUT`, `STARTTLS`, `ID`,
  `LOGIN`, `AUTHENTICATE PLAIN`, `AUTHENTICATE XOAUTH2` and
  `AUTHENTICATE OAUTHBEARER`.
- Implement `SASL-IR` for the supported `AUTHENTICATE` mechanisms.
- Reject unsupported IMAP `{N}` literals before authentication or backend
  connection.
- Process supported pre-auth pipelined commands in wire order and hand buffered
  post-auth bytes to proxy mode without loss.
- Map IMAP `ID` client metadata into Nauthilus `client_id` context without
  populating HTTP-only `user_agent`.
- Authenticate through the configured Nauthilus HTTP or gRPC authority.
- Route with the M0 `auth_attribute` and deterministic hash resolver pipeline.
- Open, heartbeat, close and lookup Redis-backed active affinity/session state.
- Select IMAP backends from static config, static maintenance state and
  deterministic selector rules.
- Connect to IMAP backends over TCP only.
- Implement IMAP backend TLS/SNI verification and backend authentication.
- Implement both IMAP backend auth modes: `master_user` and full
  `credential_replay`.
- Enter transparent proxy mode only after frontend auth, routing, session open,
  backend selection, backend connect and backend auth all succeed.
- Extend the fake-service E2E lane and add mandatory real IMAP server
  interoperability via `make e2e-interop`.

Out of scope:

- Complete IMAP server behavior and post-auth command parsing.
- IMAP mailbox semantics.
- IMAP `{N}` literal support.
- POP3, LMTP and ManageSieve protocol entrypoints.
- Dynamic backend health checks, max-connection enforcement and runtime
  in/out/drain operations.
- Redis move, kick, clear, reap, administrative pin and backend runtime
  override scripts.
- Full REST route lookup implementation. M1 may keep the endpoint as an
  explicit structured stub, but must hand M3 a read-only integration follow-up.
- Unix socket IMAP backend connectivity.
- Local OIDC bearer-token validation in the director.

## Target Package Boundaries

M1 adds or expands these production packages:

```text
internal/listener/
internal/protocol/imap/
internal/proxy/
```

A small `internal/session/` package may be added only if it gives session
objects cohesive ownership and avoids package-level mutable state. Do not add a
grab-bag helper package.

Boundary rules:

- `internal/listener` owns network listener lifecycle, TLS listener wrapping,
  per-listener accept loops, connection limits, graceful shutdown hooks and
  optional listener transport pre-processing.
- `internal/protocol/imap` owns IMAP pre-auth parsing, command dispatch,
  mechanism extraction, backend IMAP auth choreography and the transition to
  proxy mode.
- `internal/proxy` owns bidirectional byte copying, deadlines, idle timeouts,
  byte accounting and close/error classification after the protocol handler has
  selected and authenticated the backend.
- `internal/nauthilus` remains the Nauthilus auth transport boundary.
- `internal/routing` remains the logical routing fact resolver.
- `internal/state` remains the Redis-backed affinity/session/runtime state
  boundary.
- `internal/backend` remains backend registry and selector ownership.
- `internal/observability` remains logging, metrics, tracing and label policy
  ownership.
- Protocol handlers must use narrow interfaces from those packages. They must
  not parse config maps, mutate Redis directly, build REST DTOs or call Viper.

## M1.1 Listener Lifecycle and IMAP Session Boundary

### Purpose

Start and stop configured IMAP/IMAPS listeners safely, create bounded session
contexts and prepare the transport stream before IMAP pre-auth handling starts.

### In Scope

- Support `director.listeners.<name>` entries whose `protocol` is `imap`.
- Support STARTTLS-style IMAP listeners and implicit TLS IMAPS listeners.
- Bind only configured `network` and `address` values.
- Apply `runtime.timeouts.preauth`, `runtime.timeouts.auth`,
  `runtime.timeouts.backend_connect`, `runtime.timeouts.proxy_idle` and
  `runtime.process.shutdown_timeout`.
- Enforce `director.security.max_preauth_line_bytes` and
  `director.security.max_preauth_literal_bytes`.
- Apply listener TLS minimum version settings.
- Keep stable session IDs internally without using session IDs as metric labels.
- Graceful shutdown: stop accepting, let proxy sessions drain until shutdown
  timeout, then close remaining connections.
- Implement HAProxy PROXY protocol v1 and v2 for trusted upstream peers.

### Out of Scope

- POP3, LMTP and ManageSieve listeners.
- Unix socket listener support unless already supported by M0 control surfaces.
- Accepting untrusted client-supplied PROXY source addresses.
- PROXY protocol `LOCAL` command support.

### Expected Files or Packages

```text
internal/listener/listener.go
internal/listener/tcp.go
internal/listener/tls.go
internal/listener/proxyproto.go
internal/listener/*_test.go
internal/protocol/imap/session.go
internal/protocol/imap/context.go
internal/app/module.go
```

### Implementation Notes

- Use the typed M0 config snapshot. Do not read Viper or raw config maps from
  listener/protocol code.
- HAProxy PROXY protocol is in M1 scope because it is essential for enterprise
  deployments behind load balancers.
- Use a small, justified, pinned dependency for PROXY protocol parsing instead
  of hand-rolling this security-sensitive boundary. The preferred package is
  `github.com/pires/go-proxyproto` because it supports PROXY protocol v1 and v2
  and provides connection trust policies. Pin the exact released version during
  implementation, then run `go mod tidy` and `go mod vendor`.
- `proxy_protocol.enabled: false` means no PROXY preface is read.
- `proxy_protocol.enabled: true` means the listener expects and parses a PROXY
  protocol header before any TLS handshake or IMAP greeting.
- `trusted_cidrs` is required and non-empty when PROXY protocol is enabled.
- Connections from untrusted peers fail closed before IMAP greeting.
- A trusted upstream that omits the PROXY header, sends a malformed header, uses
  an unsupported command, exceeds the header timeout or supplies an unsupported
  address family fails closed before IMAP greeting.
- Accept only stream TCP source/destination address families needed by IMAP and
  IMAPS. Reject UDP, Unix and unspecified address families for mail listeners.
- For implicit TLS listeners, consume and validate the PROXY header before the
  TLS handshake.
- For STARTTLS listeners, consume and validate the PROXY header before the
  cleartext IMAP greeting.
- Log only secret-safe PROXY fields. Do not use raw client IP, remote address or
  session ID as metric labels.

### Required Unit Tests

- Listener config filters IMAP and IMAPS entries by protocol.
- STARTTLS listeners start without implicit TLS and advertise TLS later through
  IMAP capability handling.
- IMAPS listeners wrap accepted connections in TLS before greeting.
- Listener shutdown stops accept loops and closes remaining sessions after
  timeout.
- PROXY protocol config validation rejects enabled listeners with empty
  `trusted_cidrs`.
- PROXY protocol trust policy rejects untrusted peers.
- PROXY protocol v1 and v2 headers produce the expected safe connection context.
- PROXY `LOCAL`, malformed headers and unsupported address families fail closed.

### Required Integration or E2E Tests

- Start public IMAP and IMAPS sockets from test config.
- Connect through PROXY v1 and PROXY v2 from trusted test peers.
- Reject untrusted source, missing header and malformed header before greeting.
- Verify implicit TLS after PROXY and STARTTLS after PROXY with test
  certificates.

### Acceptance Criteria

- IMAP and IMAPS listeners start from typed config and shut down gracefully.
- PROXY protocol v1 and v2 are implemented with strict trusted CIDR checks,
  header timeouts, TCP-only validation and public-socket tests.
- Listener TLS and STARTTLS transport boundaries are covered by tests.

### Review Checklist

- Verify listener/protocol code does not call Viper.
- Verify TLS is never silently downgraded.
- Verify untrusted PROXY source addresses cannot influence client context.
- Verify raw client IP and session ID are not metric labels.

## M1.2 IMAP Pre-Auth Parser and Command Handling

### Purpose

Implement the small IMAP pre-auth command surface needed to authenticate, route
and transition into transparent proxy mode without implementing a full IMAP
server.

### In Scope

M1 supports these frontend commands before proxy mode:

- `CAPABILITY`
- `NOOP`
- `LOGOUT`
- `STARTTLS`
- `LOGIN`
- `AUTHENTICATE PLAIN`
- `AUTHENTICATE XOAUTH2`
- `AUTHENTICATE OAUTHBEARER`
- `ID`

### Out of Scope

- Complete IMAP parser behavior.
- Post-auth command interpretation.
- IMAP `{N}` literal handling, including for `LOGIN` and `ID`.
- `ENABLE`.
- Mailbox semantics.

### Expected Files or Packages

```text
internal/protocol/imap/parser.go
internal/protocol/imap/commands.go
internal/protocol/imap/capability.go
internal/protocol/imap/id.go
internal/protocol/imap/starttls.go
internal/protocol/imap/*_test.go
```

### Implementation Notes

- Command names are case-insensitive.
- Use tagged responses for command outcomes.
- Enforce line length, literal marker and pre-auth timeout limits before auth.
- Implement a small parser for atoms, quoted strings and bounded base64
  payloads.
- Literal markers such as `{123}` are unsupported in M1, must not trigger
  continuation reads and fail with a tagged error before any authentication or
  backend connection.
- M1 must be pipeline-safe for the supported pre-auth command subset. If a
  client sends multiple supported pre-auth commands without waiting for each
  response, process them in wire order.
- Do not implement a full post-auth IMAP command state machine in the director.
- Any bytes already buffered by the pre-auth reader that belong to post-auth
  backend traffic must be handed to `internal/proxy` and sent to the backend
  before continuing live bidirectional copy.
- Buffered proxy handoff is a performance requirement. Post-auth traffic must
  not be delayed, reparsed, reordered or dropped by the director.
- Advertise only configured mechanisms and extensions that M1 actually supports.
- Treat omitted configurable capabilities as deny rules. Missing `ID`,
  `STARTTLS`, `SASL-IR` or `AUTH=<mechanism>` must disable the related command,
  initial-response shape or authentication mechanism instead of merely hiding it
  from `CAPABILITY`.
- Implement `ID` and advertise or accept it only when configured.
- Implement `SASL-IR` and accept initial responses only when configured.
- Do not implement or advertise `ENABLE`. If target config still lists
  `ENABLE`, M1 must adjust config/defaults or reject the unsupported
  advertisement during validation.
- Advertise and accept `STARTTLS` only when configured, before TLS is active and
  only for listener TLS mode `starttls`.
- Advertise `LOGINDISABLED` if plaintext password authentication is disabled
  before TLS by policy.

### IMAP ID Rules

- `ID` is mandatory M1 behavior and privacy-safe.
- Support `ID NIL` and bounded RFC-2971-style parenthesized key/value pairs.
- Parse enough of `ID` to extract client identity for Nauthilus before
  authentication.
- Do not use `ID` metadata for routing, affinity or backend selection.
- Populate `nauthilus.RequestContext.ClientID` from the first available
  normalized value in this order:
  1. `client_id`
  2. `client-id`
  3. `name`
- Do not populate `nauthilus.RequestContext.UserAgent` from IMAP `ID`.
  `user_agent` is HTTP request context, not mail protocol context.
- Bound the number of ID pairs, key length, value length and total command
  length through the pre-auth size limits.
- Reject malformed, duplicate-sensitive or oversized `ID` commands before
  authentication without leaking raw values.
- Store only the normalized client ID needed for the subsequent Nauthilus
  request. Do not retain the arbitrary ID map in session state.
- Do not log raw ID values and do not expose them in metrics, traces, REST or
  Redis. Logs may record only whether client ID context was present.
- Default behavior is permissive: if the client does not send `ID`, M1 still
  allows authentication.
- M1 must define a non-default listener policy such as
  `director.listeners.<name>.imap.require_id_before_auth: true`. When enabled,
  authentication commands before a usable `ID` command fail with a generic
  tagged response and do not call Nauthilus.

### Required Unit Tests

- IMAP line parser, tags, command dispatch and invalid-command responses.
- `CAPABILITY` output for plaintext, STARTTLS and implicit TLS states.
- Missing `ID`, `STARTTLS`, `SASL-IR` and `AUTH=<mechanism>` capabilities deny
  the associated pre-auth extension behavior.
- `STARTTLS` state transition and post-STARTTLS capability behavior.
- `ID NIL`, valid ID pairs, malformed ID, oversized ID and missing ID under
  `require_id_before_auth`.
- Unsupported `{N}` literal markers fail before auth/backend connection and do
  not trigger continuation reads.
- Supported pre-auth pipelined commands are processed in wire order.
- Buffered post-auth bytes are handed to proxy mode without loss or reordering.

### Required Integration or E2E Tests

- IMAP greeting, `CAPABILITY`, `NOOP`, `LOGOUT`, `STARTTLS`, `ID`, `LOGIN` and
  `AUTHENTICATE` are exercised over public sockets.
- A pipelined pre-auth flow proves buffered post-auth handoff to the backend.
- Capability output does not advertise unsupported `ENABLE` or missing
  mechanisms, and omitted capabilities disable the related extension behavior.

### Acceptance Criteria

- IMAP pre-auth command handling is implemented and tested.
- Capability advertisement matches implemented behavior.
- Unsupported literals, unsupported mechanisms, malformed commands and
  oversized inputs fail safely.
- `ID` maps usable client metadata into Nauthilus `client_id` context without
  populating HTTP-only `user_agent`.
- `ID` is permissive by default and can be required by non-default listener
  policy.

### Review Checklist

- Verify post-auth IMAP commands are not parsed by the director.
- Verify the proxy handoff receives already buffered bytes.
- Verify raw ID values are not logged, traced, stored in Redis or exposed in
  metrics.

## M1.3 SASL and Credential Handling

### Purpose

Extract frontend credentials safely, preserve mechanism identity for Nauthilus
and backend replay, and keep credential lifetime short.

### In Scope

- `LOGIN`
- `AUTHENTICATE PLAIN`
- `AUTHENTICATE XOAUTH2`
- `AUTHENTICATE OAUTHBEARER`
- SASL initial response for supported mechanisms because M1 advertises
  `SASL-IR`.

### Out of Scope

- Local OIDC bearer-token validation.
- SASL mechanisms outside the M1 list.
- IMAP literal-based credential input.

### Expected Files or Packages

```text
internal/protocol/imap/auth.go
internal/protocol/imap/sasl.go
internal/protocol/imap/secret.go
internal/protocol/imap/*_test.go
internal/nauthilus/request.go
```

### Implementation Notes

- Passwords, bearer tokens, SASL blobs, master credentials and private keys must
  never be logged, traced, exposed in metrics or returned through REST.
- Mechanism names are normalized while preserving original mechanism identity
  needed by Nauthilus and optional backend credential replay.
- `PLAIN` decodes `authzid NUL authcid NUL password`.
- `LOGIN` extracts username and password from IMAP command arguments.
- `XOAUTH2` parses enough of the SASL envelope to extract username and bearer
  token and preserve mechanism identity.
- `OAUTHBEARER` parses enough of the SASL envelope to extract auth identity and
  bearer token and preserve mechanism identity.
- Bearer material size must respect
  `auth.authorities.<name>.mechanisms.bearer.token_max_bytes`.
- Invalid base64, malformed SASL envelopes, oversized credentials and missing
  identities fail authentication without leaking raw input.
- Credential material may be retained only as long as needed for the Nauthilus
  auth call and configured backend credential replay.
- Avoid broad credential storage on session objects.

### Required Unit Tests

- `LOGIN` parsing and redaction.
- `AUTHENTICATE PLAIN` parsing with valid, malformed and oversized payloads.
- `AUTHENTICATE XOAUTH2` parsing with valid, malformed and oversized payloads.
- `AUTHENTICATE OAUTHBEARER` parsing with valid, malformed and oversized
  payloads.
- SASL-IR and continuation response flows for all supported mechanisms.
- Token size limit enforcement.
- Secret formatting never emits credential material.

### Required Integration or E2E Tests

- Authenticate through the public IMAP listener with `LOGIN`, `PLAIN`,
  `XOAUTH2` and `OAUTHBEARER`.
- Fake Nauthilus observes mechanism identity without receiving director-owned
  routing/backend fields.
- Logs from director and fake services do not contain passwords, bearer tokens
  or raw SASL blobs.

### Acceptance Criteria

- M1 credential extraction covers the required mechanisms.
- `SASL-IR` works for supported `AUTHENTICATE` mechanisms.
- Credential and bearer material remain redacted and short-lived.

### Review Checklist

- Verify OIDC token validation is delegated to Nauthilus.
- Verify no credential is stored in long-lived session state after backend
  auth/proxy transition.
- Verify malformed credential payloads fail without leaking raw input.

## M1.4 Authentication, Routing and Placement Pipeline

### Purpose

Wire frontend credential handling into the M0 Nauthilus auth boundary, then
apply director-owned routing facts and placement decisions.

### In Scope

- Select `auth.authorities.<listener.authority>`.
- Use configured Nauthilus HTTP or gRPC transport.
- Send `protocol: imap`.
- Map Nauthilus outcomes into IMAP responses.
- Resolve routing facts through `internal/routing`.
- Open Redis-backed active affinity/session state.
- Select a concrete IMAP backend through `internal/backend`.

### Out of Scope

- Asking Nauthilus for concrete backend decisions.
- Local routing inside the Nauthilus client.
- Starting routing or Redis state mutation after Nauthilus tempfail/transport
  failure.

### Expected Files or Packages

```text
internal/protocol/imap/session.go
internal/protocol/imap/auth.go
internal/nauthilus/
internal/routing/
internal/state/
internal/backend/
```

### Implementation Notes

- Nauthilus authenticates only. Backend selection remains director-owned.
- HTTP auth requests must not include a top-level `service` field.
- HTTP auth requests must not send nested `tls`, nested `proxy`, `listener`,
  `session_id`, `backend_identifier` or `routing_hint`.
- Nauthilus `authenticated` continues to routing and backend selection.
- Nauthilus `rejected` returns tagged `NO [AUTHENTICATIONFAILED]` with the
  authority-provided status message when present. Fall back to
  `Authentication failed` only when Nauthilus returns an empty message.
- Rejected-status text is owned by Nauthilus. The director must not
  reinterpret, enrich or replace it with local policy text.
- The director may only apply IMAP response framing hygiene to rejected status
  text: bound rendered response length, strip or replace CR/LF and control
  characters, and prevent response injection.
- Raw rejected-status text must not become a metric label or unsanitized log
  field.
- Nauthilus tempfail, timeout or transport failure returns tagged
  `NO [UNAVAILABLE] Authentication service temporarily unavailable`.
- Nauthilus tempfail, timeout or transport failure must not start routing,
  Redis session open, backend selection or backend connection. The frontend
  session remains unauthenticated in pre-auth state unless normal pre-auth
  timeout, command limit or shutdown handling closes it.
- Routing pipeline:

```text
AuthResult + listener context
  -> normalize account and tenant
  -> internal/routing resolver
  -> candidate shard_tag from auth_attribute or deterministic hash fallback
  -> Redis active affinity/session open
  -> final shard_tag for this active session
  -> internal/backend selector for protocol + backend_pool + shard_tag
  -> concrete IMAP backend
```

- Routing is side-effect-free until session open.
- `auth_attribute` routing must work with Nauthilus-provided attributes.
- Deterministic hash fallback must work when allowed by config.
- Ambiguous routing facts fail closed.
- Active affinity takes precedence over initial deterministic placement while a
  matching user has open sessions.
- Affinity pins logical `shard_tag` first. Backend selector maps
  `shard_tag + protocol + backend_pool` to a concrete IMAP backend.

### Required Unit Tests

- Nauthilus auth request mapping from IMAP mechanisms.
- HTTP auth requests include `protocol: imap` and omit forbidden director
  fields.
- Nauthilus rejected outcomes map authority-provided status messages into safe
  tagged `NO [AUTHENTICATIONFAILED]` responses.
- Nauthilus tempfail, timeout and transport outcomes map to
  `NO [UNAVAILABLE] Authentication service temporarily unavailable`.
- Tempfail/timeout/transport failures do not route, mutate Redis or connect a
  backend.
- Routing pipeline uses `auth_attribute`.
- Deterministic hash fallback is stable.
- Ambiguous routing facts fail closed.

### Required Integration or E2E Tests

- Fake Nauthilus HTTP and gRPC authorities authenticate equivalent users and
  attributes.
- Fake Nauthilus attributes drive backend routing through the public IMAP
  listener.
- Nauthilus rejected status messages are visible through sanitized IMAP
  responses.
- Nauthilus unavailable responses do not create Redis sessions.

### Acceptance Criteria

- IMAP auth uses configured Nauthilus HTTP or gRPC transport.
- Nauthilus remains authentication-only.
- Routing resolver consumes authenticated attributes and deterministic fallback.
- No routing/backend selection begins after Nauthilus tempfail/transport error.

### Review Checklist

- Verify HTTP bodies have `protocol`, not `service`.
- Verify Nauthilus client code does not select backends.
- Verify auth failures do not leak credentials.

## M1.5 Redis Affinity, Session Leases and Backend Selection

### Purpose

Implement the minimum Redis-backed state and static backend selection behavior
needed by IMAP sessions.

### In Scope

- Redis scripts:
  - `open`
  - `heartbeat`
  - `close`
  - `lookup`
- Static config-backed IMAP backend registry and selector.
- Static backend maintenance handling.
- Static weight handling for initial placement.

### Out of Scope

- Redis move, kick, clear, reap, administrative pin and backend runtime
  override scripts.
- Dynamic backend health checks.
- Max-connection enforcement.
- Runtime in/out/drain operations.

### Expected Files or Packages

```text
internal/state/affinity.go
internal/state/sessions.go
internal/state/scripts/
internal/state/*_test.go
internal/backend/registry.go
internal/backend/selector.go
internal/backend/*_test.go
```

### Implementation Notes

- Redis scripts use per-affinity key groups with Cluster hash tags.
- Scripts use Redis server time.
- Scripts update a generation counter where relevant.
- Session liveness is lease-based.
- Redis state fails closed on ambiguous state.
- Raw usernames are avoided in Redis keys.
- Return payloads contain enough structured state for routing decisions and
  audit logs without exposing secrets.
- M1 key shape, generation counter, lease fields and return payloads must be
  compatible with adding M2 scripts without Redis schema redesign.
- M1 backend selection is static config-backed only.
- Select only backends whose `protocol` matches `imap`.
- Enforce the listener's configured `backend_pool`.
- Select within the final `shard_tag`.
- Support the configured deterministic selector for initial placement.
- Static maintenance rules:
  - `disabled`: eligible
  - `soft`: excluded from new initial placements; active pins may remain when
    `director.maintenance.soft_allows_active_pins` is true
  - `hard`: excluded from new sessions
- Static `weight: 0` is ineligible for weighted initial placement but is not
  hard maintenance.
- Health is not a selector signal in M1. If all statically eligible backends
  fail at connect time, the session fails closed and the failure is observable.
- Raw backend identifiers are not metric labels.

### Required Unit Tests

- Redis `open`, `heartbeat`, `close` and `lookup` script behavior.
- Lease expiry and close behavior.
- Cluster hash tag key grouping.
- Redis ambiguous state fail-closed classification.
- Static backend registry by protocol, pool and shard.
- Static maintenance handling for disabled, soft and hard.
- Static `weight: 0` placement behavior.
- No raw username requirement in Redis keys.

### Required Integration or E2E Tests

- Use real Redis or Redis-compatible service for active affinity.
- Active-user stickiness across concurrent or sequential IMAP sessions with the
  same affinity key.
- Session close releases or expires affinity according to configured grace and
  lease semantics.
- Backend routing is externally visible through fake backend observations.

### Acceptance Criteria

- Redis active affinity pins logical `shard_tag` and overrides initial
  placement while sessions are active.
- Session open, heartbeat and close use Redis-backed lease semantics.
- M1 implements only Redis `open`, `heartbeat`, `close` and `lookup`.
- Backend selector maps `shard_tag + protocol + backend_pool` to concrete IMAP
  backends and respects static maintenance rules.
- Health checks, max-connection limits and runtime in/out/drain remain M2 scope.

### Review Checklist

- Verify normal routing does not use distributed locks.
- Verify local caches are accelerators only.
- Verify M2 scripts can be added without key-schema redesign.
- Verify backend identifiers are not metric labels.

## M1.6 Backend Connect, Backend Auth and Proxy Transition

### Purpose

Connect to selected IMAP backends, establish configured backend authentication
and switch into transparent byte proxying.

### In Scope

- TCP-only IMAP backend connectivity.
- Backend TLS modes:
  - disabled or plaintext, if explicitly configured
  - `starttls`
  - `implicit`
- TLS SNI and hostname verification.
- Backend auth modes:
  - `master_user`
  - `credential_replay`
- Transparent proxy transition and session cleanup.

### Out of Scope

- Unix socket IMAP backend connectivity.
- Silent TLS downgrade.
- Backend auth mode stubs or silent backend-auth skips.
- Post-auth IMAP parsing in the director.

### Expected Files or Packages

```text
internal/protocol/imap/backend.go
internal/protocol/imap/backend_auth.go
internal/proxy/pipe.go
internal/proxy/deadlines.go
internal/proxy/accounting.go
internal/proxy/*_test.go
```

### Implementation Notes

- Use `runtime.timeouts.backend_connect`.
- Support TCP backends from typed config only.
- Unix socket backend addresses fail config validation or listener/backend
  startup with a clear operator error.
- Control API Unix-socket transport is a separate config/control-plane topic,
  not M1 IMAP backend connectivity.
- When backend TLS is enabled and the TCP address is not the certificate name,
  require `tls.server_name` for SNI and hostname verification.
- Keep `insecure_skip_verify` false by default and explicit when allowed.
- Never silently downgrade backend TLS.
- `master_user` is the default safe production mode for IMAP backends.
- `master_user` uses the configured master credential and `user_format` without
  logging user or master credentials.
- `credential_replay` is opt-in and must enforce configured TLS, mechanism and
  secret-lifetime restrictions.
- `credential_replay` supports `PLAIN`, `LOGIN`, `XOAUTH2` and `OAUTHBEARER`.
- `credential_replay.require_backend_tls: true` is enforced before replaying
  any password, bearer token or SASL blob. If the selected backend connection is
  not protected by verified TLS, replay fails closed.
- `credential_replay.preserve_mechanism: true` replays the original accepted
  frontend mechanism when backend config allows it.
- When `preserve_mechanism` is false, M1 may normalize password mechanisms
  only: frontend `LOGIN` or `PLAIN` may replay as backend `PLAIN` or `LOGIN`
  when backend config and backend CAPABILITY allow it.
- Bearer mechanisms remain strict: frontend `XOAUTH2` replays only as
  `XOAUTH2`, and frontend `OAUTHBEARER` replays only as `OAUTHBEARER`.
- Do not silently map between `XOAUTH2` and `OAUTHBEARER`.
- If no allowed backend mechanism matches the credential type and
  `preserve_mechanism` policy, backend auth fails closed.
- Replayed credential material remains in redaction-aware secret wrappers, is
  not stored beyond the backend-auth attempt and is cleared from long-lived
  session state before proxy mode.
- Backend auth invalid for selected mechanism, TLS state or backend capability
  response fails closed with a secret-safe operator-visible reason.
- Bidirectional proxy starts only after frontend authentication, routing,
  session open, backend selection, backend connect and backend auth succeed.
- Proxy mode copies bytes without parsing post-auth IMAP commands.
- Apply proxy idle timeout.
- Track byte counters by direction with allowed metric labels only.
- Close both sides on EOF, timeout, backend failure, frontend close or shutdown.
- Always close or expire Redis session lease on session end.
- Heartbeat while proxy mode is active.
- Result classes such as `client_closed`, `backend_closed`, `timeout`,
  `shutdown`, `backend_auth_failed` and `state_failed` must not use raw error
  text as metric labels.

### Required Unit Tests

- TCP-only backend transport validation and Unix-socket rejection.
- Backend TLS config validation and SNI requirements.
- Backend STARTTLS and implicit TLS state handling.
- `master_user` auth command generation without secret leakage.
- `credential_replay` for `PLAIN`, `LOGIN`, `XOAUTH2` and `OAUTHBEARER`.
- Credential replay TLS enforcement.
- Credential replay mechanism allowlists and preserve/normalize rules.
- Credential cleanup before proxy mode.
- Proxy close/error classification and byte accounting.
- Buffered pre-auth bytes are sent to backend before live copy.

### Required Integration or E2E Tests

- Fake IMAP backend proves `master_user` succeeds.
- Fake IMAP backend proves credential replay succeeds for allowed mechanisms and
  fails closed for TLS/allowlist violations.
- Real IMAP server interop proves a successful login and post-auth proxy
  handoff through the public director listener.

### Acceptance Criteria

- Backend connect, backend TLS and backend auth are implemented with tests.
- `master_user` and full IMAP `credential_replay` are implemented in M1.
- Transparent proxy mode starts only after all preconditions succeed.
- Proxy close paths clean up or expire session leases.

### Review Checklist

- Verify replay secrets are removed from long-lived session state.
- Verify backend auth cannot be skipped silently.
- Verify post-auth bytes are proxied, not parsed.

## M1.7 Observability, E2E, Interoperability and Guardrails

### Purpose

Make the IMAP MVP observable, prove behavior through public sockets and keep the
guardrail lane fast while requiring a real IMAP server proof before M1 closes.

### In Scope

- Structured logs with secret-safe fields.
- OpenTelemetry span boundaries for the IMAP session path.
- Prometheus metrics through the M0 low-cardinality label policy.
- Fake-service guardrail E2E lane through `make e2e`.
- Real IMAP server interoperability through `make e2e-interop`.
- M1 closeout review and `make guardrails`.

### Out of Scope

- Treating fake-service success as sufficient proof of real IMAP
  interoperability.
- Making Docker interop part of the fast `make e2e` target.
- Using forbidden metric labels or raw error text.

### Expected Files or Packages

```text
internal/observability/
test/e2e/
test/e2e/fakes/imap_backend/
test/e2e/interop/
Makefile
```

### Implementation Notes

Structured logs cover:

- listener start/stop
- session start/end
- auth result
- routing source
- affinity source
- backend selection result
- backend connect
- backend auth result
- proxy end

OpenTelemetry spans:

```text
nauthilus_director.session
nauthilus_director.imap.pre_auth
nauthilus_director.nauthilus.auth
nauthilus_director.routing.resolve
nauthilus_director.backend.select
nauthilus_director.backend.connect
nauthilus_director.proxy.pipe
```

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

Fake-service guardrail lane:

- Start the real `nauthilus-director` binary for at least one public IMAP
  entrypoint proof; additional deterministic edge cases may use test processes
  when they still cross public sockets.
- Listen on public IMAP and IMAPS sockets from test config.
- Start fake Nauthilus HTTP and gRPC authorities on public test sockets.
- Start fake IMAP backend test processes on public test sockets.
- Use real Redis or a Redis-compatible test service for active affinity.
- Authenticate through the public IMAP listener.
- Assert backend routing externally through fake backend observations.
- Assert `auth_attribute` routing from fake Nauthilus attributes.
- Assert deterministic hash fallback where configured.
- Assert active-user stickiness.
- Assert lease close/expiry behavior.
- Assert STARTTLS and implicit TLS behavior.
- Assert backend TLS/SNI behavior.
- Assert `master_user` and `credential_replay` backend auth behavior.
- Scrape Prometheus metrics when enabled and verify no forbidden labels appear.
- Assert logs from director and fake services do not contain passwords, bearer
  tokens or raw SASL blobs.
- Run through `make e2e` as part of `make guardrails`.

Real-server interoperability lane:

- `make e2e-interop` is mandatory for M1 acceptance.
- It remains separate from the fast `make e2e` guardrail lane.
- Docker is an implementation detail of this interoperability lane, not the
  target name.
- Use a real IMAP server as backend, preferably pinned Dovecot
  project-provided Docker assets.
- Another real IMAP server is acceptable only when the implementation spec or
  closeout justifies it and pins the image or artifact.
- Prove at least one successful end-to-end IMAP login and post-auth proxy
  handoff against the real backend through the public director listener
  started by the production `nauthilus-director` binary.
- Cover both configured backend auth modes where the selected real IMAP backend
  supports them. If a mode is unsupported by the selected real server setup, M1
  acceptance requires an equivalent real-server proof before closeout.
- `make e2e-interop` may skip during ordinary local runs when Docker or the
  selected real backend artifact is unavailable, but an explicit skip is not
  sufficient to mark M1 complete. M1 closeout requires a passing real-server
  interop run on a Docker-capable environment.

REST route lookup:

- M1 may leave REST route lookup as an explicit `501 Not Implemented` stub.
- Route lookup remains director-only and side-effect-free.
- It must not authenticate credentials, call Nauthilus, create sessions,
  refresh leases or mutate Redis.
- M1 must shape shared domain services so M3 can wire route lookup read-only
  without a parallel routing model.
- M1 closeout must hand M3 an explicit follow-up for read-only route lookup.

### Required Unit Tests

- Metric label registration rejects forbidden labels.
- Structured log fields redact secrets.
- Span names are prepared for the IMAP session path.
- Route lookup stub does not call Nauthilus or mutate state.
- Result classes do not expose raw error text as labels.

### Required Integration or E2E Tests

- Fake-service guardrail lane through `make e2e`.
- Real-server interoperability through `make e2e-interop`.
- Public socket assertions for IMAP, IMAPS, PROXY, STARTTLS, backend routing and
  proxy handoff.
- Log and metric checks for secret safety.

### Acceptance Criteria

- Metrics use only the low-cardinality allowlist.
- E2E guardrail lane uses fake Nauthilus, fake IMAP backends and real or
  compatible Redis through public sockets.
- Real IMAP server interoperability, preferably with pinned Dovecot Docker
  assets, is implemented as `make e2e-interop`.
- M1 is not complete until `make e2e-interop` passes on a Docker-capable
  environment.
- `make guardrails` is the final local gate before commit or pull request, and
  M1 closeout additionally records the passing real-server interop run.

### Review Checklist

- Verify fake services do not replace real-server proof.
- Verify interop images/artifacts are pinned.
- Verify all observability output is secret-safe.
- Verify M3 route lookup follow-up is explicit.

## Top-Level Acceptance Checklist

M1 is complete only when all items below are true:

- [ ] IMAP and IMAPS listeners start from typed config and shut down gracefully.
- [ ] Listener TLS and STARTTLS behavior are covered by tests.
- [ ] PROXY protocol v1 and v2 are implemented with strict trusted CIDR checks,
      header timeouts, TCP-only validation and public-socket tests.
- [ ] IMAP greeting, `CAPABILITY`, `NOOP`, `LOGOUT`, `STARTTLS`, `LOGIN` and
      `AUTHENTICATE` are covered by unit and E2E tests.
- [ ] Configured IMAP capabilities are the pre-auth extension boundary:
      omitted `ID`, `STARTTLS`, `SASL-IR` and `AUTH=<mechanism>` entries are not
      advertised and are not accepted.
- [ ] IMAP `ID` is implemented, advertised, covered by unit and E2E tests, and
      maps usable client metadata into Nauthilus `client_id` context without
      populating HTTP-only `user_agent` or logging raw ID values.
- [ ] IMAP `ID` is permissive by default, and a non-default listener policy can
      require usable `ID` before authentication without calling Nauthilus on
      missing-ID attempts.
- [ ] Capability advertisement matches implemented behavior.
- [ ] Unsupported IMAP `{N}` literals, unsupported mechanisms, malformed
      commands and oversized inputs fail safely before authentication or backend
      connection.
- [ ] Supported pre-auth pipelined commands are processed in wire order, and
      buffered post-auth bytes are handed to proxy mode without loss,
      reordering or director-side post-auth parsing.
- [ ] `PLAIN`, `XOAUTH2` and `OAUTHBEARER` credential extraction is
      implemented and covered, and `LOGIN` password extraction is covered.
- [ ] No credential, token, SASL blob, master password or private key is logged.
- [ ] IMAP auth uses configured Nauthilus HTTP or gRPC transport.
- [ ] HTTP auth requests include `protocol: imap` and do not send forbidden
      director fields.
- [ ] Nauthilus rejected outcomes return tagged `NO [AUTHENTICATIONFAILED]`
      with the authority-provided status message after IMAP framing hygiene.
- [ ] Nauthilus tempfail, timeout and transport outcomes return tagged
      `NO [UNAVAILABLE] Authentication service temporarily unavailable` and do
      not start routing, Redis session open or backend connection.
- [ ] Routing resolver consumes authenticated attributes and deterministic
      fallback as specified.
- [ ] Redis active affinity pins logical `shard_tag` and overrides initial
      placement while sessions are active.
- [ ] Session open, heartbeat and close use Redis-backed lease semantics.
- [ ] M1 implements only Redis `open`, `heartbeat`, `close` and `lookup`
      scripts.
- [ ] Redis move, kick, clear, reap, administrative pins and backend runtime
      overrides remain M2 scope without requiring a later key-schema redesign.
- [ ] Backend selector maps `shard_tag + protocol + backend_pool` to concrete
      IMAP backends and respects static maintenance rules.
- [ ] M1 backend selection is static config-backed only. Health checks,
      max-connection limits and runtime in/out/drain remain M2 scope.
- [ ] Backend connect, backend TLS and backend auth are implemented with tests.
- [ ] `master_user` and full IMAP `credential_replay` backend auth are
      implemented in M1.
- [ ] Credential replay supports `PLAIN`, `LOGIN`, `XOAUTH2` and
      `OAUTHBEARER`, enforces backend TLS and mechanism allowlists, and removes
      replay secrets from long-lived session state before proxy mode.
- [ ] IMAP backend connectivity is TCP-only in M1; Unix socket backend addresses
      fail clearly, while any future control API Unix-socket transport remains
      a separate config/control-plane topic.
- [ ] Transparent proxy mode starts only after frontend auth, routing, session
      open, backend selection, backend connect and backend auth succeed.
- [ ] Proxy close paths clean up or expire session leases.
- [ ] Route lookup may remain an explicit stub in M1, but it remains
      director-only, side-effect-free and covered by tests.
- [ ] M1 closeout hands M3 an explicit follow-up to connect route lookup
      read-only to the shared domain pipeline.
- [ ] Metrics use only the low-cardinality allowlist.
- [ ] E2E guardrail lane uses fake Nauthilus, fake IMAP backends and real or
      compatible Redis through public sockets.
- [ ] Real IMAP server interoperability, preferably with pinned Dovecot Docker
      assets, is implemented as `make e2e-interop`.
- [ ] M1 is not complete until `make e2e-interop` passes on a Docker-capable
      environment.
- [ ] `make guardrails` is the final local gate before commit or pull request,
      and M1 closeout records the passing real-server interop run.

## Required M1 Review Pass

Before closing M1, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `docs/ARCHITECTURE_ROADMAP.md`, especially sections 9, 10, 17, 20,
   21, 22 and 24.
3. Re-read `docs/specs/implementation/M0_FOUNDATION_SPEC.md`.
4. Re-read `docs/config/nauthilus-director.target.yml`.
5. Compare implementation and docs against this specification and the source
   documents.
6. Fix drift, missing constraints, accidental POC coupling, false capability
   advertisement and vague acceptance criteria.
7. Run targeted docs/spec review and `git status --short`.
8. Run `make guardrails` before any commit or pull request that contains M1
   implementation work.
9. Run and record a passing `make e2e-interop` on a Docker-capable environment
   before marking M1 complete.
