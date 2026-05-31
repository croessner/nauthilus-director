# M6 ManageSieve Proxy Specification

Status: implementation-ready M6 specification

This document defines the ManageSieve milestone for `nauthilus-director`. M6
adds a production-ready ManageSieve proxy entrypoint within the explicit scope
below: listener startup, frontend pre-auth handling, STARTTLS and implicit TLS,
SASL credential extraction, Nauthilus authentication, director-owned routing,
user placement hold enforcement, active-affinity-safe backend selection,
backend ManageSieve authentication, transparent post-auth proxying,
observability, deterministic E2E coverage and real-server interoperability
proof.

M6 builds on the completed M0 foundation, the completed M1 IMAP MVP, the
completed M2/M3 backend runtime and control implementation, the completed M4
observability runtime, the completed M5 LMTP production implementation and the
completed M3 user placement hold and backend-pin follow-ups. It is not a
proof-of-concept migration and not a script-management implementation inside
the director. The archived implementation under `poc/` may be read only as
historical source material, and production code must not import it, preserve
its package layout or use it as a compatibility target.

## Source Documents

M6 is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`
- `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-director.1`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.yaml.5`
- `test/e2e/README.md`
- `test/e2e/interop/README.md`
- `Makefile`
- RFC 5804, `A Protocol for Remotely Managing Sieve Scripts`

If this specification conflicts with those source documents, fix the drift
before implementation continues. In particular, do not silently change stable
config paths, REST behavior, runtime-control semantics, metric-label policy,
active-affinity semantics, user placement hold behavior or security defaults to
make ManageSieve easier to implement.

## M6 Goal

M6 implements the first production ManageSieve director flow:

```text
ManageSieve client
  -> nauthilus-director Sieve or implicit-TLS Sieve listener
      -> optional PROXY protocol
      -> implicit TLS or STARTTLS
      -> ManageSieve greeting and pre-auth capability surface
      -> AUTHENTICATE credential extraction
      -> Nauthilus HTTP/gRPC authentication
      -> director-owned routing fact resolution
      -> user placement hold gate
      -> Redis-backed active affinity or deterministic initial placement
      -> protocol/backend-pool-scoped backend-pin evaluation
      -> runtime-aware ManageSieve backend selection
      -> backend ManageSieve connect, TLS and backend auth/trust
      -> frontend AUTHENTICATE success only after backend access is ready
      -> transparent bidirectional proxy mode
      -> session lease cleanup and secret-safe observable outcome
```

M6 must keep Sieve script semantics out of the director. The director handles
only the protocol surface required before authentication succeeds, then proxies
post-auth ManageSieve traffic as opaque bytes. Script names, script contents,
post-auth command bodies and backend script diagnostics belong to the backend
ManageSieve service, not to director routing, metrics or logs.

The hard invariant is same-shard user-stateful routing. ManageSieve uses the
same authoritative tenant and normalized account key as IMAP active affinity,
user movement, user placement holds, user backend pins and LMTP
delivery-scoped active-affinity holds. If an IMAP session or LMTP delivery hold
already pins the account to a shard, a new ManageSieve session for the same
account must select the ManageSieve backend entry for that active shard. If no
active affinity exists, ManageSieve establishes it for user-stateful placement
just like IMAP.

## Delivery Shape

Implement M6 as explicit implementation slices:

1. Config stabilization, validation and listener dispatch for protocol `sieve`.
2. Frontend ManageSieve parser, capability greeting, STARTTLS and SASL auth.
3. Nauthilus auth, routing, placement hold, affinity and backend selection.
4. Backend ManageSieve connector, backend auth/trust and deep health checks.
5. Post-auth proxy handoff, buffered-byte handling and session cleanup.
6. Runtime state, maintenance, reload and route-lookup integration.
7. ManageSieve observability, documentation and generated reference updates.
8. Fake-service E2E, real Dovecot ManageSieve interoperability and closeout
   review.

The slices may be committed separately, but M6 is not complete until the
production `nauthilus-director` binary starts configured ManageSieve listeners,
authenticates through public sockets, proves same-shard behavior with existing
IMAP and LMTP active-affinity state, proxies script-management traffic without
inspecting it, keeps script and credential material out of unsafe telemetry,
passes deterministic `make e2e` coverage and passes a real-server
interoperability lane with a real ManageSieve backend.

## Global Scope

In scope:

- Start configured `sieve` and `sieves` listeners from the typed config
  snapshot. The canonical protocol string is `sieve`; do not introduce
  `managesieve` as a second protocol value in config, route lookup, metrics or
  runtime state.
- Generalize listener dispatch so IMAP, LMTP and ManageSieve handlers are
  selected by protocol without duplicating transport lifecycle code.
- Support the RFC 5804 non-authenticated command surface:
  `CAPABILITY`, `STARTTLS`, `AUTHENTICATE`, `LOGOUT` and `NOOP`.
- Reject all other commands before successful authentication with a protocol
  `NO` response and a bounded reason class.
- Support ManageSieve quoted-string and bounded literal parsing only as needed
  for the pre-auth command surface and SASL exchange. Post-auth script literals
  remain opaque proxy bytes.
- Support frontend SASL mechanisms required by the architecture for
  user-stateful protocols where the configured Nauthilus authority supports
  them: `PLAIN`, `XOAUTH2` and `OAUTHBEARER`.
- Support optional one-round-trip initial responses for mechanisms that do not
  negotiate a SASL security layer.
- Support cancellation of an in-progress `AUTHENTICATE` exchange without
  logging the SASL payload.
- Support implicit TLS for `sieves` and STARTTLS for `sieve` when configured.
- Require frontend TLS before accepting credential-bearing SASL mechanisms,
  including `PLAIN`, `XOAUTH2` and `OAUTHBEARER`. This is a director-owned
  transport safety gate, not a Nauthilus policy decision; Nauthilus is called
  only after implicit TLS or successful STARTTLS for such credentials.
- Authenticate through the configured Nauthilus HTTP or gRPC authority. The
  Nauthilus request must use protocol identity `sieve`, not a `service` body
  field.
- Populate the flat Nauthilus SSL request fields from the frontend TLS state,
  including `ssl`, protocol, cipher and available client-certificate metadata.
- Treat Nauthilus as the authentication and identity authority only.
  Nauthilus may provide canonical account, tenant and routing facts; it must
  not provide concrete ManageSieve backend identifiers.
- Enforce the shared user placement hold gate after authoritative
  authentication and routing fact resolution, but before frontend auth success,
  backend selection, backend capacity reservation, backend connect, backend
  auth/trust or proxy mode.
- Use the shared routing resolver and active-affinity model. Existing IMAP
  sessions and LMTP delivery holds for the same account must influence
  ManageSieve placement through the shared shard affinity.
- Apply backend pins only when the pin's protocol and backend pool match the
  ManageSieve placement request. A pin for an IMAP, LMTP or later POP3 backend
  must never name the concrete ManageSieve backend.
- Select ManageSieve backends through the existing runtime-aware selector,
  preserving health, maintenance, runtime out, drain, weight, max-connection and
  explicit operator backend-pin semantics.
- Connect to ManageSieve backends with configured plaintext, STARTTLS or
  implicit TLS modes without disabling certificate verification by default.
- Support backend auth modes for user-stateful protocols: `master_user` and
  `credential_replay`.
- Require `credential_replay` to be explicit, restricted to configured allowed
  mechanisms, protected by verified backend TLS and cleared from memory as soon
  as backend auth succeeds or fails.
- Enter transparent proxy mode only after frontend auth has succeeded at
  Nauthilus, placement has passed the hold gate, a backend has been selected and
  counted, backend transport is established and backend auth/trust has
  succeeded.
- Keep post-auth `HAVESPACE`, `PUTSCRIPT`, `LISTSCRIPTS`, `SETACTIVE`,
  `GETSCRIPT`, `DELETESCRIPT`, `RENAMESCRIPT`, `CHECKSCRIPT`,
  `UNAUTHENTICATE` and any extension commands backend-owned by proxying them as
  opaque bytes.
- Extend route lookup diagnostics for `protocol: sieve` without credential
  authentication, backend connect, backend auth, Redis mutation or script
  inspection.
- Extend observability with ManageSieve pre-auth, auth, placement, backend and
  proxy events using only the approved low-cardinality metric labels.
- Extend deterministic fake-service E2E to cover public sockets, STARTTLS,
  implicit TLS, SASL auth, hold gate behavior, backend-pin scoping,
  active-affinity consistency, proxy handoff, secret safety and script-content
  opacity.
- Extend real-server interoperability with a Dovecot ManageSieve backend while
  preserving the existing real IMAP and LMTP interop lanes.

Out of scope:

- Executing, parsing, validating, rewriting or linting Sieve scripts inside the
  director.
- Implementing mailbox semantics, quota semantics, active script semantics or
  script storage.
- Inspecting post-auth ManageSieve commands for routing decisions.
- Logging, metric-labeling or tracing script names, script contents, post-auth
  command bodies, SASL blobs, passwords, bearer tokens, private keys or raw
  authorization headers.
- Adding script name, user, user hash, session ID, request ID, trace ID, client
  IP, raw backend identifier, raw error text or operator hold reason as a
  Prometheus label.
- Treating Nauthilus as a backend selector.
- Calling Nauthilus credential-authentication during route lookup.
- Adding ManageSieve recipient lookup behavior. ManageSieve is a mailbox-user
  login protocol; route lookup for ManageSieve uses caller-supplied user facts.
- Silently falling back to an old backend when a placement hold remains active,
  a pinned backend is unusable or runtime state is ambiguous.
- Letting an IMAP or LMTP backend pin select a ManageSieve backend directly.
- Exposing LMTP delivery holds as ManageSieve login sessions.
- Replacing deterministic fake-service E2E with Docker interoperability tests.
- Supporting SASL security layers in the director.
- Supporting multi-step SCRAM or GSSAPI authentication in M6 unless the
  Nauthilus authority exposes a safe challenge/response API and this
  specification is amended before implementation.

## Stable Config Paths

M6 stabilizes the ManageSieve listener and backend config paths introduced for
this milestone. These paths must not be renamed, removed or inverted without an
explicit breaking-change decision plus docs, examples, migration notes and
tests:

- `director.listeners.sieve`
- `director.listeners.sieves`
- common listener fields under those listeners: `protocol`, `service_name`,
  `network`, `address`, `authority`, `backend_pool`, `proxy_protocol` and `tls`
- `director.listeners.sieve.sieve.auth_mechanisms`
- `director.listeners.sieve.sieve.capabilities.implementation`
- `director.listeners.sieve.sieve.capabilities.version`
- `director.listeners.sieve.sieve.capabilities.script_extensions`
- `director.listeners.sieve.sieve.capabilities.language`
- matching `director.listeners.sieves.sieve.*` paths
- `director.backend_pools.sieve-default`
- `director.backend_pools.sieve-default.protocol`
- `director.backend_pools.sieve-default.selector`
- `director.backend_pools.sieve-default.backends`
- ManageSieve backend entries under `director.backends.*` where
  `protocol: sieve`
- ManageSieve backend TLS paths: `tls.mode`, `tls.ca_file`, `tls.cert`,
  `tls.key`, `tls.server_name`, `tls.min_tls_version` and
  `tls.insecure_skip_verify`
- ManageSieve backend auth paths already used by user-stateful protocols:
  `auth.mode`, `auth.master_user.*` and `auth.credential_replay.*`
- ManageSieve backend health, maintenance, weight, max-connection and HAProxy
  paths

M6 may add these paths to the typed defaults and generated references with
safe local-loopback examples. The canonical default listener names should be:

```yaml
director:
  listeners:
    sieve:
      protocol: sieve
      service_name: sieve
      tls:
        mode: starttls
    sieves:
      protocol: sieve
      service_name: sieves
      tls:
        mode: implicit
```

ManageSieve capability output is not a blind echo of YAML. The runtime
capability surface is the effective intersection of configured desired
capabilities, implemented pre-auth behavior, listener TLS state, configured
auth mechanisms, backend-pool script capability policy and backend transport
safety. Omitting `STARTTLS` or an authentication mechanism from the effective
surface disables the associated command or mechanism for that session.

`SIEVE`, `IMPLEMENTATION` and `VERSION` capabilities are required by RFC 5804.
Because the director cannot select a user backend before authentication, the
pre-auth `SIEVE` extension list must come from typed config as the operator's
declared common backend-pool capability set. If no common set is declared, M6
must advertise an empty `SIEVE` value rather than guessing or connecting to a
backend before authentication.

M6 must keep redaction metadata intact for listener TLS keys, backend TLS keys,
backend master-user password files and any credential-replay or bearer-token
material.

## Target Package Boundaries

M6 expands existing production packages and adds a new protocol package:

```text
internal/protocol/sieve/
internal/listener/
internal/app/
internal/config/
internal/nauthilus/
internal/routing/
internal/backend/
internal/state/
internal/runtime/
internal/proxy/
internal/observability/
internal/rest/
internal/rest/adapters/
test/e2e/
test/e2e/fakes/managesieve_backend/
test/e2e/interop/
docs/
```

Boundary rules:

- `internal/protocol/sieve` owns ManageSieve greeting, capability rendering,
  pre-auth parsing, STARTTLS command handling, SASL credential extraction,
  backend ManageSieve auth choreography and the transition to proxy mode.
- `internal/listener` owns listener lifecycle, transport preparation, PROXY
  protocol and frontend TLS wrapping. It must not contain ManageSieve command
  logic.
- `internal/app` owns Fx wiring, dependency construction and protocol handler
  dispatch. It must not become a protocol state machine.
- `internal/config` owns typed ManageSieve config validation, defaults,
  redaction metadata and generated docs inputs. It must not read raw Viper
  values from protocol code.
- `internal/nauthilus` remains the authentication transport boundary. It must
  not select director backends.
- `internal/routing` owns logical user-to-shard facts only. It must not open
  Redis sessions, select backends or log raw usernames.
- `internal/backend` owns ManageSieve-capable registry and selector behavior,
  effective backend state, health policy and backend runtime constraints.
- `internal/state` owns Redis-backed active affinity, session leases, backend
  runtime counts and user runtime state.
- `internal/runtime` exposes side-effect-free diagnostics and runtime controls
  without inventing a second ManageSieve routing model.
- `internal/proxy` owns bidirectional byte copying, deadlines, idle timeouts,
  byte accounting and lease heartbeats after ManageSieve auth has completed.
- `internal/observability` owns metric instruments, logs, spans and redaction
  policy. Protocol packages record normalized events only.
- `internal/rest` and `internal/rest/adapters` stay generated-contract oriented.
  If M6 changes route-lookup DTOs for ManageSieve diagnostics, update OpenAPI
  first and regenerate the boundary.

Do not add package-level mutable global state. Use cohesive types and narrow
interfaces so unit tests can exercise parser, auth, placement and backend
handoff behavior without starting the full application.

## M6.1 Config, Validation and Protocol Listener Dispatch

### Purpose

Add typed ManageSieve configuration and wire protocol dispatch without
duplicating listener lifecycle behavior that already exists for IMAP and LMTP.

### In Scope

- Add `sieve` as a valid listener, backend-pool and backend protocol.
- Keep the canonical protocol value `sieve` across config, route lookup,
  runtime state, logs, traces and metrics.
- Add typed listener sub-config for `director.listeners.<name>.sieve`.
- Add safe defaults for `sieve` and `sieves` listeners, `sieve-default`
  backend pool and two example protocol-specific backend entries.
- Validate that `protocol: sieve` listeners include a `sieve` listener
  sub-config and do not include IMAP or LMTP-only sub-config as the active
  protocol behavior.
- Validate that a `sieve` listener references a backend pool whose protocol is
  also `sieve`.
- Validate configured auth mechanisms against the Nauthilus authority's
  supported mechanism classes.
- Reject configuration that would advertise or accept credential-bearing SASL
  mechanisms before frontend TLS is active.
- Validate ManageSieve capabilities as typed values, not arbitrary protocol
  transcript snippets.
- Validate backend auth modes so `sieve` backends support `master_user` and
  `credential_replay` only.
- Extend generated config references, metadata and manpages when typed config
  changes.

### Out of Scope

- Adding POP3 config.
- Changing stable IMAP or LMTP config paths.
- Adding a feature-specific Redis subtree for ManageSieve.
- Adding YAML rewrite behavior through REST or CLI.

### Expected Files or Packages

```text
internal/config/config.go
internal/config/defaults.go
internal/config/validate.go
internal/config/normalize.go
internal/config/*_test.go
internal/app/module.go
internal/app/server.go
docs/config/nauthilus-director.target.yml
docs/config/metadata.yml
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
docs/man/nauthilus-director.yaml.5
```

### Implementation Notes

- Reuse the shared listener config fields. Do not create a parallel
  ManageSieve listener model.
- The default `sieve` listener should use STARTTLS mode. The default `sieves`
  listener should use implicit TLS mode if enabled in defaults.
- Capability config should express stable facts, not raw wire lines. Rendering
  to RFC 5804 quoted capability lines belongs in `internal/protocol/sieve`.
- `script_extensions` means the common Sieve language extensions that all
  backends in the pool can safely expose before backend selection. It is not
  discovered dynamically before user auth.
- Config docs must be regenerated through the Makefile targets, not manually
  patched after typed config changes.

### Required Unit Tests

- Config defaults include safe `sieve` protocol examples.
- Config validation accepts `sieve` listener and backend-pool wiring.
- Config validation rejects `sieve` listeners without a `sieve` sub-config.
- Config validation rejects `sieve` listeners that reference non-`sieve` pools.
- Config validation rejects unsupported ManageSieve auth mechanisms and
  malformed capability values.
- Config validation rejects `credential_replay` without verified backend TLS.
- Generated config references include all stable M6 paths and protected
  metadata for credential-bearing paths.

### Required Integration or E2E Tests

- Start the production binary with one STARTTLS `sieve` listener and one
  implicit-TLS `sieves` listener.
- Verify listener runtime listing and route lookup accept `protocol: sieve`.
- Verify IMAP and LMTP listeners still start from the same config file.

### Acceptance Criteria

- Typed config, generated references and validation understand protocol
  `sieve`.
- Listener dispatch starts ManageSieve handlers without duplicating listener
  lifecycle code.
- Existing IMAP and LMTP config behavior remains compatible.

### Review Checklist

- Verify no raw Viper reads exist in `internal/protocol/sieve`.
- Verify `managesieve` is not introduced as a second protocol value.
- Verify config changes are reflected in generated docs and manpages.
- Verify protected config paths remain redacted by default.

## M6.2 Frontend ManageSieve State Machine, TLS and SASL Auth

### Purpose

Implement the minimal RFC 5804 pre-auth surface needed to authenticate, route
and safely hand off to a backend without becoming a full ManageSieve server.

### In Scope

- Send a ManageSieve capability greeting when the frontend connection is ready.
- Render capability lines as RFC 5804 ManageSieve strings and terminate the
  greeting with `OK`.
- Implement `CAPABILITY` before auth and after STARTTLS as the effective
  frontend capability surface.
- Implement `NOOP` and `LOGOUT` before auth.
- Implement `STARTTLS` only when advertised and only on non-implicit TLS
  listeners.
- Remove `STARTTLS` from the effective capability set after TLS is active.
- Implement `AUTHENTICATE` for configured mechanisms:
  - `PLAIN`
  - `XOAUTH2`
  - `OAUTHBEARER`
- Support an optional initial response for one-round-trip mechanisms.
- Support bounded quoted-string and literal parsing for AUTH mechanism names,
  initial responses and challenge responses.
- Reject SASL security layer negotiation. The director does not implement SASL
  wrapping for post-auth traffic.
- Enforce `runtime.timeouts.preauth`, `runtime.timeouts.auth`,
  `director.security.max_preauth_line_bytes` and
  `director.security.max_preauth_literal_bytes`.
- Process supported pre-auth pipelined commands in wire order. If a pipelined
  group contains `AUTHENTICATE` or `STARTTLS`, enforce RFC 5804 ordering rules
  and preserve only safe buffered bytes for the correct transport state.
- Authenticate through Nauthilus and keep credentials secret-safe throughout.
- Delay frontend `AUTHENTICATE` success until placement and backend access are
  ready.
- Return `NO (TRYLATER)` for temporary placement or backend-readiness failures
  that occur after Nauthilus accepts the user.

### Out of Scope

- Full post-auth command parsing.
- `HAVESPACE`, `PUTSCRIPT`, `LISTSCRIPTS`, `SETACTIVE`, `GETSCRIPT`,
  `DELETESCRIPT`, `RENAMESCRIPT`, `CHECKSCRIPT` or extension command semantics
  in the director.
- SASL security layers.
- SCRAM, GSSAPI, DIGEST-MD5 or other multi-step mechanisms unless a separate
  Nauthilus challenge/response design is accepted.
- Client certificate identity mapping as mailbox-user authentication.
- Local OIDC bearer-token validation in the director.

### Expected Files or Packages

```text
internal/protocol/sieve/session.go
internal/protocol/sieve/parser.go
internal/protocol/sieve/commands.go
internal/protocol/sieve/capability.go
internal/protocol/sieve/auth.go
internal/protocol/sieve/sasl.go
internal/protocol/sieve/starttls.go
internal/protocol/sieve/responses.go
internal/protocol/sieve/secret.go
internal/protocol/sieve/*_test.go
```

### Implementation Notes

- RFC 5804 permits only `AUTHENTICATE`, `CAPABILITY`, `STARTTLS`, `LOGOUT` and
  `NOOP` before authentication. Treat that as the explicit M6 parser boundary.
- The initial greeting is generated by the director because no user backend has
  been selected yet.
- `IMPLEMENTATION`, `VERSION` and `SIEVE` capability lines must always be
  present. `SIEVE` uses the configured common extension set and may be empty.
- `SASL` may be empty only when `STARTTLS` is advertised and TLS is required
  before mechanisms are exposed.
- Do not use human-readable response text as program semantics. Tests should
  assert bounded response code and result classes.
- The SASL service name for auth context is `sieve`.
- A failed `AUTHENTICATE` may allow another auth attempt within pre-auth
  attempt limits. A successful `AUTHENTICATE` transitions to backend placement
  and then proxy mode; re-authentication is backend-owned only after proxy mode.
- Credential-bearing mechanisms before TLS must fail closed with
  `NO (ENCRYPT-NEEDED)` before Nauthilus is called. M6 must not add a
  compatibility flag that permits password or bearer auth on plaintext
  frontend connections.

### Required Unit Tests

- Greeting renders required capabilities and omits unsafe mechanisms before TLS.
- `CAPABILITY` changes after STARTTLS and remains stable otherwise.
- `STARTTLS` fails when not advertised, succeeds when configured and rejects
  leftover plaintext command injection across the TLS boundary.
- `AUTHENTICATE PLAIN`, `XOAUTH2` and `OAUTHBEARER` parse valid initial
  responses and reject malformed or oversized payloads.
- SASL cancellation returns a safe `NO` without leaking payloads.
- Unsupported mechanisms and SASL security-layer requests fail closed.
- Unsupported pre-auth commands return `NO` and do not reach routing or backend
  code.
- Pipelining rules are enforced for `AUTHENTICATE` and `STARTTLS`.
- Nauthilus requests use `protocol: sieve` and do not include a forbidden
  `service` body field.
- Nauthilus requests include truthful frontend SSL DTO fields for plaintext,
  STARTTLS and implicit TLS states.

### Required Integration or E2E Tests

- Connect to public `sieve` and `sieves` sockets and verify greeting,
  `CAPABILITY`, `NOOP`, `LOGOUT`, STARTTLS and auth behavior.
- Verify plaintext password auth is rejected before STARTTLS on the default
  `sieve` listener.
- Verify bearer mechanisms pass only bearer material to Nauthilus and do not
  log tokens.

### Acceptance Criteria

- ManageSieve pre-auth handling is complete inside the M6 boundary.
- Authentication succeeds only through Nauthilus and only for configured
  mechanisms.
- Frontend auth success is not sent until backend access is ready.

### Review Checklist

- Verify the parser does not understand script-management semantics before auth.
- Verify STARTTLS and SASL payloads cannot leak through logs, traces, metrics or
  test failure output.
- Verify unsupported mechanisms do not trigger fallback credential parsing.

## M6.3 Authenticated Placement, Hold Gate, Affinity and Backend Selection

### Purpose

Route authenticated ManageSieve users through the same director-owned placement
model as IMAP, including user placement holds, active affinity, backend pins and
runtime-aware selection.

### In Scope

- Convert Nauthilus auth success into the canonical account key, tenant and
  routing attributes used by the shared resolver.
- Resolve routing facts through `internal/routing`, not through backend or REST
  packages.
- Apply the shared user placement hold gate after auth and routing, before
  frontend auth success and before backend selection.
- If the hold clears or expires within the bounded wait budget, re-read active
  affinity, movement overrides, backend-pin state, backend health and capacity
  before selecting.
- If the hold remains active past the wait budget, return a generic
  `NO (TRYLATER)` temporary failure and do not fall back to the old backend.
- Open Redis-backed active affinity/session state for ManageSieve sessions.
- Treat ManageSieve sessions as user-stateful active sessions visible through
  session APIs with protocol `sieve`, but without script names or command
  payloads.
- Select a concrete ManageSieve backend from
  `effective_shard_tag + protocol=sieve + backend_pool`.
- Apply operator backend pins only when protocol, backend pool and selected
  shard match.
- Let explicit backend pins bypass `weight_zero` for the pinned backend only,
  while preserving every other fail-closed exclusion.
- Reuse backend attach/capacity reservation behavior and rollback on placement,
  connect or backend-auth failure.
- Preserve existing active affinity from IMAP sessions and LMTP delivery holds.

### Out of Scope

- Creating a second ManageSieve-specific routing model.
- Letting client-supplied usernames become authoritative after Nauthilus returns
  canonical identity facts.
- Holding unauthenticated sockets before the director knows the user key.
- Exposing waiter lists through v1 REST APIs.
- Treating route lookup as a placement operation.

### Expected Files or Packages

```text
internal/protocol/sieve/placement.go
internal/runtime/users.go
internal/state/
internal/backend/
internal/routing/
internal/protocol/sieve/*_test.go
test/e2e/
```

### Implementation Notes

- Use the existing `runtime.PlacementGate` interface. M6 should not add a
  protocol-specific hold implementation.
- The placement gate request must use `Protocol: "sieve"` plus the listener and
  service names from the frontend session context.
- ManageSieve session records should use the same normalized affinity key model
  as IMAP. Raw usernames must not be Redis key material.
- If active affinity already exists for the user, it chooses the shard. The
  ManageSieve selector then resolves that shard to a protocol-specific
  `sieve` backend entry.
- If a backend pin is present for another protocol or backend pool, report the
  mismatch in route lookup but ignore it for live placement.
- If a matching backend pin names an unusable backend, fail closed. Do not
  silently select another backend.

### Required Unit Tests

- Successful Nauthilus auth feeds the shared routing resolver.
- Placement hold wait runs after auth/routing and before backend selection.
- Hold timeout returns `NO (TRYLATER)` and does not open a session, reserve
  backend capacity, connect to a backend or send auth success.
- Existing IMAP active affinity controls ManageSieve selected shard.
- Existing LMTP delivery-scoped active affinity controls ManageSieve selected
  shard.
- ManageSieve opens and heartbeats a visible user session after placement.
- Backend pins apply only for matching `protocol=sieve` and backend pool.
- Cross-protocol backend pins do not name the concrete ManageSieve backend.
- Matching backend pins bypass only `weight_zero` and fail closed for all other
  exclusions.
- Placement rollback closes affinity/session state after backend selection,
  attach, connect or backend-auth failure.

### Required Integration or E2E Tests

- Public ManageSieve login routes to the same shard as an active IMAP session.
- Public ManageSieve login routes to the same shard as an in-flight LMTP
  delivery hold for the same resolved account.
- `nauthilus-directorctl users hold set` causes a public ManageSieve auth to
  wait and then temporary-fail without backend connect when the hold remains
  active.
- `nauthilus-directorctl users backend-pin set` routes only matching
  ManageSieve sessions to the pinned `sieve` backend.
- An IMAP or LMTP backend pin does not select a concrete ManageSieve backend.

### Acceptance Criteria

- ManageSieve placement uses the same active-affinity and runtime-control model
  as IMAP.
- Holds and backend pins are enforced at the correct boundary.
- Same-shard cross-protocol behavior is proven through public sockets.

### Review Checklist

- Verify frontend auth success cannot be returned before hold and backend
  readiness checks complete.
- Verify raw usernames are not Redis keys or metric labels.
- Verify backend-pin handling does not cross protocol or backend-pool scopes.
- Verify failures clean up session and backend capacity state.

## M6.4 Backend ManageSieve Connector, Auth and Health

### Purpose

Connect to selected ManageSieve backends, establish the configured backend
transport and authenticate or establish trust before frontend auth success.

### In Scope

- Implement ManageSieve backend connect over TCP.
- Support backend TLS modes:
  - `none`
  - `starttls`
  - `implicit`
- Verify backend certificates by default when TLS is enabled.
- Read backend greeting and capabilities without logging script extension lists
  as unbounded text.
- Perform backend auth modes:
  - `master_user`
  - `credential_replay`
- Support backend `AUTHENTICATE PLAIN` for master-user auth when configured and
  advertised by the backend.
- Support credential replay only for configured allowed mechanisms and only
  when backend TLS is verified if policy requires it.
- Clear replayed frontend credentials immediately after backend auth succeeds or
  fails.
- Consume backend auth success/failure and map failures to safe frontend
  response classes.
- Implement ManageSieve backend deep health checks: connect, TLS/STARTTLS,
  greeting, `CAPABILITY`, configured health auth, optional `NOOP`, `LOGOUT`.
- Keep health checks away from script-management commands.

### Out of Scope

- Unix socket backend connectivity unless already provided generically.
- Backend script operation health checks.
- Backend referrals as automatic client redirection.
- Trusting a backend that cannot authenticate the selected user.
- Translating frontend auth mechanisms into unsupported backend mechanisms.

### Expected Files or Packages

```text
internal/protocol/sieve/backend.go
internal/protocol/sieve/backend_auth.go
internal/protocol/sieve/health.go
internal/backend/
internal/config/
internal/protocol/sieve/*_test.go
```

### Implementation Notes

- Backend auth behavior should reuse IMAP user-stateful auth concepts where the
  protocol allows it, but keep ManageSieve wire syntax in `internal/protocol/sieve`.
- Backend `credential_replay` extends the lifetime of user secrets and must
  remain opt-in.
- Backend auth failure after Nauthilus success is a backend-readiness failure to
  the frontend, not proof that the user credentials were invalid at Nauthilus.
  Prefer `NO (TRYLATER)` for ambiguous backend failures.
- If a backend sends a `REFERRAL`, the director must not automatically redirect
  the client in M6. Treat it as an operator-visible backend failure unless a
  later architecture decision adds referral support.
- Deep health must never send `HAVESPACE`, `PUTSCRIPT`, `SETACTIVE`,
  `CHECKSCRIPT` or any command that can mutate or inspect user scripts.

### Required Unit Tests

- Backend connect handles plaintext, STARTTLS and implicit TLS.
- Backend STARTTLS requires advertised support and fails closed on TLS errors.
- Backend certificate verification is on by default.
- `master_user` auth formats the selected user and master credential without
  logging the password.
- `credential_replay` requires allowed mechanisms and verified TLS when
  configured.
- Backend auth failure maps to safe temporary frontend failure text.
- Backend health checks stop before script-management commands.
- Backend health does not log health username, password, script names or raw
  backend status text.

### Required Integration or E2E Tests

- Fake ManageSieve backend proves backend auth mode `master_user`.
- Fake ManageSieve backend proves credential replay with verified TLS.
- Fake ManageSieve backend forces auth, greeting, STARTTLS and capability
  failures so the director fails closed and cleans up runtime state.
- Health runner marks ManageSieve backends healthy/unhealthy through public
  runtime diagnostics without exposing backend identifiers as metric labels.

### Acceptance Criteria

- Backend ManageSieve access is established before frontend auth success.
- Backend auth is explicit, tested and secret-safe.
- Health checks are protocol-aware and non-mutating.

### Review Checklist

- Verify backend auth code does not share IMAP parser internals by accident.
- Verify credential replay cannot run over unverified plaintext by default.
- Verify backend health cannot create, read, modify or delete scripts.

## M6.5 Proxy Handoff, Buffered Bytes and Session Cleanup

### Purpose

Hand authenticated ManageSieve sessions into transparent proxy mode without
losing pipelined bytes, parsing script commands or leaking script contents.

### In Scope

- Send frontend auth success only after backend auth/trust is complete.
- Handle RFC 5804 post-auth capability behavior safely. The director may relay
  backend post-auth capability results only after validating their protocol
  framing; otherwise it must send a bounded effective capability response.
- Preserve buffered post-auth client bytes and forward them to the selected
  backend after auth succeeds.
- Use `internal/proxy` for bidirectional stream copy after handoff.
- Heartbeat the ManageSieve session lease while proxy mode is active.
- Close session state and backend capacity accounting when proxy mode ends.
- Keep post-auth ManageSieve commands and literals opaque to the director.
- Preserve proxy idle timeouts, byte accounting and graceful shutdown behavior.

### Out of Scope

- Parsing script names or script bodies for telemetry, routing, policy or
  validation.
- Transforming post-auth ManageSieve commands.
- Retrying post-auth commands on another backend after proxy mode begins.
- Spooling script bodies.

### Expected Files or Packages

```text
internal/protocol/sieve/session.go
internal/protocol/sieve/proxy.go
internal/proxy/
internal/state/
test/e2e/fakes/managesieve_backend/
```

### Implementation Notes

- Treat script literals exactly like opaque bytes. The proxy pipe should not
  attempt to understand ManageSieve post-auth framing.
- Handoff must be careful around AUTH success: any client bytes already read by
  the pre-auth parser and not consumed by auth must be sent to the backend in
  order.
- If backend auth succeeds but the frontend auth success response cannot be
  written, close the backend connection and roll back session state.
- If proxy mode exits with an error, report bounded reason classes only.

### Required Unit Tests

- Buffered post-auth bytes after successful auth reach the backend exactly once.
- Backend-to-client buffered bytes from backend auth/capability handling are
  relayed or safely replaced according to policy.
- Proxy close calls session cleanup and backend detach exactly once.
- Script names and script contents in proxied bytes are not recorded by
  observability events.
- Failed frontend success write rolls back backend and session state.

### Required Integration or E2E Tests

- Through the public ManageSieve listener, authenticate and issue
  `LISTSCRIPTS`, `PUTSCRIPT`, `SETACTIVE` and `GETSCRIPT` against a fake backend.
- Include unique sentinel script names and script content, then assert logs,
  metrics, traces and test observations do not leak them.
- Verify graceful shutdown lets an active ManageSieve proxy session drain until
  timeout, then closes it.

### Acceptance Criteria

- Post-auth ManageSieve traffic is transparent and opaque.
- Runtime leases and backend counts are cleaned up after proxy exit.
- Script material does not appear in unsafe observable output.

### Review Checklist

- Verify no post-auth parser is introduced in the director.
- Verify buffered bytes cannot be dropped or replayed.
- Verify proxy telemetry remains byte/duration oriented, not command oriented.

## M6.6 Runtime State, Maintenance, Reload and Route Lookup

### Purpose

Integrate ManageSieve with the completed runtime-control model without adding a
parallel management surface.

### In Scope

- Include ManageSieve sessions in session runtime state as protocol `sieve`.
- Let backend runtime state, soft/hard maintenance, runtime out, drain, weight
  override and max-connection limits affect ManageSieve selection.
- Keep soft maintenance semantics: exclude from new initial placements while
  preserving existing active sessions and active pins by default.
- Keep hard maintenance and drain behavior consistent with IMAP user-stateful
  sessions.
- Ensure reload changes affect new ManageSieve sessions without breaking active
  proxy sessions unexpectedly.
- Extend route lookup for `protocol: sieve` using the existing
  side-effect-free route lookup service.
- Route lookup must report routing source, selected shard, active affinity,
  backend-pin context, user-hold context, backend eligibility and fail-closed
  reasons.
- Route lookup must not authenticate credentials, create sessions, refresh
  leases, wait on holds, connect to backends, perform backend auth or inspect
  scripts.

### Out of Scope

- ManageSieve-specific REST mutation endpoints.
- Script-management REST APIs.
- Backend referral control APIs.
- Route lookup accepting passwords, bearer tokens, SASL blobs or script names.

### Expected Files or Packages

```text
internal/runtime/
internal/rest/adapters/
internal/rest/generated/
docs/specs/openapi/nauthilus-director.yaml
cmd/nauthilus-directorctl/
docs/man/nauthilus-directorctl.1
```

### Implementation Notes

- The existing route lookup schema may already accept arbitrary protocol
  strings. If generated docs or validation constrain the protocol set, update
  OpenAPI first and regenerate server/client artifacts.
- The CLI should support `nauthilus-directorctl route lookup --protocol sieve`
  with the same user-key and attribute model as IMAP.
- Route lookup output must not include operator hold reason text, raw backend
  identifiers as metric labels or script names.
- Runtime APIs should expose backend identifiers in REST diagnostics where the
  existing policy permits them, but never as Prometheus labels.

### Required Unit Tests

- Session list filters include `protocol=sieve`.
- Runtime maintenance and drain exclude new ManageSieve placement as expected.
- Route lookup for `protocol=sieve` uses the shared resolver and selector.
- Route lookup reports active user hold without waiting.
- Route lookup reports matching, mismatched and unusable backend-pin context.
- Route lookup rejects credential-bearing and script-bearing input.
- Route lookup performs no Redis mutations or backend connections.

### Required Integration or E2E Tests

- `nauthilus-directorctl sessions list --protocol sieve` reports active
  ManageSieve sessions without script data.
- `nauthilus-directorctl route lookup --protocol sieve ...` predicts the same
  backend selected by a later public ManageSieve login when runtime state is
  unchanged.
- Runtime out and maintenance changes affect new ManageSieve sessions through
  public control API and CLI commands.

### Acceptance Criteria

- ManageSieve participates in the existing runtime model.
- Route lookup remains diagnostic and side-effect-free.
- Reload and maintenance behavior is consistent with IMAP.

### Review Checklist

- Verify no ManageSieve route lookup code calls Nauthilus credential auth.
- Verify no script names or contents enter REST or CLI diagnostics.
- Verify runtime behavior is not duplicated in protocol code.

## M6.7 Observability, Metrics, Logs and Traces

### Purpose

Make ManageSieve behavior observable enough for operators to diagnose auth,
routing, hold, backend and proxy failures without exposing credentials or
script-management data.

### In Scope

- Add or activate ManageSieve pre-auth span:

```text
nauthilus_director.sieve.pre_auth
```

- Reuse existing spans for:
  - `nauthilus_director.session`
  - `nauthilus_director.nauthilus.auth`
  - `nauthilus_director.routing.resolve`
  - `nauthilus_director.backend.select`
  - `nauthilus_director.backend.connect`
  - `nauthilus_director.proxy.pipe`
- Add bounded events for:
  - ManageSieve session start/end
  - greeting/capability render result
  - STARTTLS result
  - AUTHENTICATE mechanism/result
  - Nauthilus auth result
  - placement hold wait/release/timeout
  - active-affinity open/heartbeat/close
  - backend-pin applied/mismatch/fail-closed
  - backend select/connect/auth result
  - proxy start/end
- Add Prometheus observations using only approved labels.
- Use bounded status classes and reason classes, not raw backend text.
- Allow backend identifiers in logs/traces only where the existing policy
  permits operator diagnostics.
- Keep script names, script contents, post-auth command bodies, raw usernames,
  passwords, bearer tokens, SASL blobs and private keys out of logs, metrics
  and traces.

### Out of Scope

- Script command counters by script name.
- Script content sampling.
- Full ManageSieve transcript logging.
- Raw backend response text as a metric label.
- Pseudonymous user correlation unless a separate privacy decision adds it.

### Expected Files or Packages

```text
internal/observability/
internal/protocol/sieve/observability.go
internal/backend/
internal/routing/
internal/state/
test/e2e/
```

### Implementation Notes

Allowed metric labels remain:

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

Forbidden metric labels remain:

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

M6 also treats the following as forbidden observable payloads outside the
client/backend wire:

```text
script_name
script_content
post_auth_command_body
operator_hold_reason
```

ManageSieve metrics should cover:

- pre-auth command totals
- auth totals and durations
- placement hold outcomes
- backend selection/connect/auth outcomes
- active session counts and durations
- proxy bytes and durations

### Required Unit Tests

- ManageSieve metric registration uses only allowed labels.
- Script name and content sent through fake proxy bytes are rejected by
  observability policy and do not become event fields.
- Span attributes do not contain raw usernames, script data, SASL blobs, bearer
  tokens, client IPs or session IDs.
- Reason classes are bounded for parser, auth, routing, hold, backend and proxy
  failures.

### Required Integration or E2E Tests

- `/metrics` exposes ManageSieve auth/session/proxy counters after a public
  ManageSieve flow.
- Logs for a ManageSieve flow contain operation/result/reason classes but no
  credentials, raw usernames, script names or script contents.
- Tracing captures ManageSieve pre-auth and nested routing/backend/proxy
  boundaries when tracing is enabled.

### Acceptance Criteria

- Operators can distinguish auth failures, hold timeouts, backend-pin failures,
  backend failures and proxy failures.
- No unsafe credential, identity or script material appears in observable
  output.

### Review Checklist

- Verify no ManageSieve metric label violates the allowlist.
- Verify script contents are not logged even in test failure paths.
- Verify backend identifiers remain forbidden as metric labels.

## M6.8 E2E, Interoperability, Documentation and Guardrails

### Purpose

Prove ManageSieve through public system boundaries, keep fake-service edge
coverage deterministic and preserve existing IMAP and LMTP real-server
interop lanes.

### In Scope

- Extend `make e2e` to prove ManageSieve through public sockets.
- Extend `make e2e-interop` with a real ManageSieve backend scenario.
- Keep existing real IMAP and LMTP interoperability coverage intact.
- Use the production `nauthilus-director` binary in E2E tests.
- Use fake Nauthilus HTTP and gRPC authority sockets where deterministic auth
  and routing outcomes are needed.
- Use fake IMAP, LMTP and ManageSieve backends where cross-protocol
  active-affinity and edge cases must be forced deterministically.
- Use Dovecot project-provided assets as the real ManageSieve backend where
  practical.
- Update docs, manpages and generated config references when ManageSieve
  behavior or config changes.
- Run `make check-openapi` after any OpenAPI or generated REST/client change.
- Run `make check-docs` after typed config, metadata or generated docs changes.
- Run `make guardrails` before any commit or pull request containing M6
  implementation work.

### Out of Scope

- Depending on Docker interop for deterministic edge coverage.
- Removing or weakening existing IMAP or LMTP interop tests.
- Testing backend Sieve execution as a director correctness requirement.
- Requiring external network access in default guardrail tests.

### Expected Files or Packages

```text
test/e2e/
test/e2e/fakes/managesieve_backend/
test/e2e/interop/
contrib/demo-stack/
docs/
docs/man/
Makefile
```

### Implementation Notes

Deterministic fake-service E2E should:

- start the production `nauthilus-director` binary;
- start fake Nauthilus authority sockets;
- start fake ManageSieve backends on public loopback sockets;
- exercise `sieve` STARTTLS and `sieves` implicit TLS;
- authenticate with password and bearer mechanisms;
- force routing to multiple shards;
- prove active IMAP affinity influences ManageSieve placement;
- prove an in-flight LMTP delivery hold influences ManageSieve placement;
- prove ManageSieve active affinity influences a concurrent IMAP login;
- prove user placement hold timeout returns `NO (TRYLATER)` before backend
  connect;
- prove backend-pin matching, mismatch and fail-closed behavior;
- proxy post-auth commands containing sentinel script names and content;
- assert sentinel script names and content do not appear in logs, metrics,
  traces or route lookup output.

Real-server interop should:

- preserve the existing Dovecot IMAP lane;
- preserve the existing Postfix-to-Director-to-Dovecot LMTP lane;
- start a real Dovecot ManageSieve backend;
- authenticate through the director to the real backend;
- perform at least one real script-management operation through the director,
  such as `LISTSCRIPTS`, `PUTSCRIPT`, `SETACTIVE` and `GETSCRIPT`;
- prove the same account routes to the same shard for ManageSieve and IMAP;
- skip with an explicit stable message when Docker or the real backend tool
  container is unavailable.

### Required Unit Tests

- Fake ManageSieve backend status scripting is deterministic.
- Fake backend observations hide script names, script contents and credentials.
- Interop skip messages are stable and explicit.

### Required Integration or E2E Tests

- `make e2e` proves ManageSieve public listener behavior, auth, routing, hold
  gate, backend-pin scoping, proxy handoff and script-data secrecy.
- `make e2e` proves ManageSieve and IMAP same-shard consistency.
- `make e2e` proves LMTP delivery-hold-to-ManageSieve shard consistency.
- `make e2e-interop` proves real Dovecot ManageSieve access through the
  director on a Docker-capable environment.
- Existing IMAP and LMTP interop scenarios remain available and are not removed
  or weakened by the ManageSieve changes.

### Acceptance Criteria

- Deterministic fake-service E2E covers forced ManageSieve edge cases.
- Real-server ManageSieve interop passes before M6 is considered complete.
- Existing IMAP and LMTP interop coverage is preserved.
- Documentation and generated references match supported ManageSieve behavior.

### Review Checklist

- Verify fake-service success is not used as a substitute for real ManageSieve
  interop.
- Verify real interop is skipped only with stable environment-related reasons.
- Verify E2E proves cross-protocol active-affinity behavior.
- Verify docs/manpages describe protocol value `sieve` and not a second
  `managesieve` config value.

## Top-Level Acceptance Checklist

M6 is complete only when all items below are true:

- [ ] `sieve` and `sieves` listeners start from typed config through the
      production server binary.
- [ ] Listener dispatch supports IMAP, LMTP and ManageSieve without duplicating
      transport lifecycle behavior.
- [ ] ManageSieve capability advertisement matches implemented behavior and RFC
      5804 framing.
- [ ] `SIEVE`, `IMPLEMENTATION` and `VERSION` capabilities are present, and
      pre-auth script extension advertisement is configured as a common
      backend-pool capability set.
- [ ] STARTTLS and implicit TLS behavior are implemented and tested.
- [ ] Credential-bearing SASL mechanisms require frontend TLS before
      Nauthilus is called.
- [ ] `AUTHENTICATE PLAIN`, `XOAUTH2` and `OAUTHBEARER` are authenticated
      through Nauthilus when configured.
- [ ] The Nauthilus auth request uses `protocol: sieve` and does not send a
      forbidden `service` body field.
- [ ] Frontend auth success is returned only after Nauthilus auth, routing,
      hold gate, backend selection, backend connect and backend auth/trust all
      succeed.
- [ ] ManageSieve checks user placement holds after authoritative auth and
      routing facts, before backend selection or auth success.
- [ ] Hold timeout returns a generic temporary failure and never falls back to
      the old backend.
- [ ] ManageSieve placement consumes health, maintenance, runtime out, drain,
      weight, max-connection and backend-pin state.
- [ ] Backend pins apply only when protocol, backend pool and selected shard
      match the ManageSieve placement request.
- [ ] An IMAP, LMTP or later POP3 backend pin never names the concrete
      ManageSieve backend.
- [ ] Existing IMAP active affinity influences ManageSieve placement for the
      same account.
- [ ] Existing LMTP delivery-scoped active affinity influences ManageSieve
      placement for the same account.
- [ ] Active ManageSieve sessions influence later user-stateful placement for
      the same account.
- [ ] Backend ManageSieve connect, TLS, capability discovery and configured
      backend auth are implemented.
- [ ] Backend deep health proves connect, TLS, greeting, `CAPABILITY`,
      configured backend auth, optional `NOOP` and `LOGOUT` without script
      commands.
- [ ] Post-auth ManageSieve traffic is transparent and opaque to the director.
- [ ] Script names, script contents and post-auth command bodies are not logged,
      traced, metric-labeled, stored or used for routing.
- [ ] Route lookup supports `protocol: sieve` without credential auth, Redis
      mutation, backend connect or script inspection.
- [ ] ManageSieve metrics use only approved low-cardinality labels.
- [ ] `make e2e` proves ManageSieve through public sockets, the production
      binary and cross-protocol active-affinity invariants.
- [ ] `make e2e-interop` proves real Dovecot ManageSieve access through the
      director on a Docker-capable environment while preserving existing IMAP
      and LMTP lanes.
- [ ] Config docs, generated references, OpenAPI artifacts and manpages are
      updated when behavior changes.
- [ ] `make guardrails` is the final local gate before any commit or pull
      request that contains M6 implementation work.

## Required M6 Review Pass

Before closing M6, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `docs/ARCHITECTURE_ROADMAP.md`, especially sections 8, 9, 10, 12,
   13, 17, 18, 20, 21, 22 and 23.
3. Re-read `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`.
4. Re-read `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`.
5. Re-read `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`.
6. Re-read `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`.
7. Re-read `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`.
8. Re-read `docs/config/nauthilus-director.target.yml`.
9. Re-read `docs/reference/config-paths.md`.
10. Re-read `docs/specs/openapi/nauthilus-director.yaml` if route lookup,
    session listing or REST diagnostics changed.
11. Re-read RFC 5804 sections for capabilities, pre-auth commands, STARTTLS,
    AUTHENTICATE and response codes.
12. Compare implementation and docs against this specification and the source
    documents.
13. Fix drift, false capability advertisement, IMAP-only selector assumptions,
    LMTP-only delivery-hold assumptions, active-affinity misuse, unsafe script
    logging, buffered proxy handoff mistakes and unsupported config
    documentation.
14. Run `make check-openapi` after any OpenAPI schema or generated-code change.
15. Run `make check-docs` after any typed config, config metadata or generated
    docs change.
16. Run targeted ManageSieve, listener, config, routing, backend, state,
    runtime, observability and REST tests.
17. Run `make e2e` and record the ManageSieve proof, including IMAP and LMTP
    active-affinity interaction.
18. Run `make e2e-interop` on a Docker-capable environment and record the real
    ManageSieve proof plus existing IMAP and LMTP lane status.
19. Run `make guardrails` before any commit or pull request.
20. Record `git status --short` and exact validation results in the M6 closeout.

## Decisions and Open Questions

These decisions are recorded so M6 implementation does not rediscover them in
code.

1. Decision: the canonical protocol value is `sieve`.

   The human-facing feature is ManageSieve, but the repository already reserves
   `internal/protocol/sieve`, `nauthilus_director.sieve.pre_auth` and
   `active_user_pinning.required_for: ["imap", "pop3", "sieve"]`. M6 keeps
   that as the single protocol value. Listener names may be `sieve` and
   `sieves`, but config, route lookup, runtime state, metrics and backend pools
   must not also introduce `managesieve`.

2. Decision: the director does not execute or inspect Sieve scripts.

   The director terminates only enough ManageSieve protocol to authenticate and
   place the user. After successful backend auth, all script-management
   semantics are backend-owned. This includes script names, script contents,
   quotas, active script state, warnings and Sieve language extensions.

3. Decision: pre-auth capabilities are director-generated.

   No backend is selected before user authentication, so the initial greeting
   cannot be a live backend capability transcript. The director renders a safe
   configured pre-auth surface and treats Sieve language extension advertisement
   as an operator-declared common backend-pool capability set.

4. Decision: ManageSieve auth success is delayed until backend access is ready.

   A client-visible successful `AUTHENTICATE` response implies the user can
   manage scripts. M6 must not send it while an operator placement hold is
   active, while backend selection is unresolved or before backend auth/trust
   has succeeded.

5. Decision: user placement holds apply to ManageSieve like IMAP.

   The hold gate runs after Nauthilus has authenticated the user and supplied
   canonical account facts, but before any backend placement side effects. Hold
   timeout returns a temporary failure and never silently falls back to the old
   backend.

6. Decision: backend pins are protocol/backend-pool scoped.

   A backend pin naming an IMAP or LMTP backend is not a concrete ManageSieve
   target. Cross-protocol consistency comes from shared shard affinity. After
   the shard is known, ManageSieve resolves a protocol-specific backend entry.

7. Decision: ManageSieve sessions are active user sessions.

   Unlike LMTP delivery holds, authenticated ManageSieve proxy connections are
   user login sessions for runtime accounting and session APIs. The session
   record must still omit script names and post-auth command payloads.

8. Decision: route lookup for ManageSieve is user-key diagnostic only.

   ManageSieve route lookup does not authenticate credentials and does not need
   LMTP-style recipient identity lookup. The caller supplies user identity facts
   or routing attributes, and the director runs the shared dry-run resolver and
   selector without side effects.

9. Decision: backend referrals are not followed in M6.

   ManageSieve `REFERRAL` may be meaningful for a standalone server, but M6 is
   a director-owned backend selection implementation. Automatic referral
   handling would create a second backend-selection path and is out of scope
   unless a later architecture decision explicitly adds it.

10. Decision: SCRAM is deferred until Nauthilus exposes a SASL
    challenge/response contract.

    RFC 5804 calls for SCRAM-SHA-1 and PLAIN over TLS for interoperability, but
    the current architecture delegates authentication to Nauthilus and does not
    define a director-to-Nauthilus SCRAM exchange. M6 must therefore not
    implement SCRAM-SHA-1, SCRAM-SHA-256, GSSAPI or other multi-step SASL
    mechanisms inside the director, and it must not advertise them. A later
    feature may add SCRAM only after Nauthilus owns the challenge/response
    state and the director remains a protocol relay.

11. Decision: M6 real-server interop proves script management, not Sieve
    execution.

    M6 correctness requires that the director authenticates, routes and proxies
    ManageSieve operations to the correct backend while keeping script material
    opaque. The required interop lane must prove operations such as
    `PUTSCRIPT`, `SETACTIVE`, `LISTSCRIPTS` and `GETSCRIPT` through the
    director, plus same-shard consistency with IMAP. Proving that an uploaded
    script later changes LMTP delivery behavior exercises backend Sieve
    execution and may be useful as a later demo-stack or hardening proof, but it
    is not an M6 acceptance criterion.

No blocking open questions remain for the initial M6 implementation.
