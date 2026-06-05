# M7 POP3 Proxy Specification

Status: completed.

This document defines the POP3 milestone for `nauthilus-director`. M7 adds a
production-ready POP3 proxy entrypoint within the explicit scope below:
listener startup, frontend POP3 authorization-state handling, STLS and
implicit TLS, `USER`/`PASS` and bearer credential extraction, Nauthilus
authentication, director-owned routing, user placement hold enforcement,
active-affinity-safe backend selection, backend POP3 authentication,
transparent transaction/update-state proxying, observability, deterministic E2E
coverage and real-server interoperability proof.

M7 builds on the completed M0 foundation, the completed M1 IMAP MVP, the
completed M2/M3 backend runtime and control implementation, the completed M4
observability runtime, the completed M5 LMTP production implementation, the
completed M6 ManageSieve proxy implementation and the completed backend-node
affinity, user placement hold and backend-pin follow-ups. It is not a
proof-of-concept migration and not a mailbox server implementation inside the
director. The archived implementation under `poc/` may be read only as
historical source material, and production code must not import it, preserve
its package layout or use it as a compatibility target.

## Source Documents

M7 is governed by:

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
- `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`
- `docs/specs/implementation/M5_BACKEND_PROXY_PROTOCOL_FOLLOWUP.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/developer/AFFINITY_SESSION_HANDLING.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-director.1`
- `docs/man/nauthilus-directorctl.1`
- `docs/man/nauthilus-director.yaml.5`
- `test/e2e/README.md`
- `test/e2e/interop/README.md`
- `test/e2e/fakes/pop3_backend/README.md`
- `contrib/demo-stack/`
- `contrib/demo-stack/scripts/`
- `Makefile`
- RFC 1939, `Post Office Protocol - Version 3`
- RFC 2449, `POP3 Extension Mechanism`
- RFC 2595, `Using TLS with IMAP, POP3 and ACAP`
- RFC 5034, `The Post Office Protocol (POP3) Simple Authentication and
  Security Layer (SASL) Authentication Mechanism`
- RFC 7628, `A Set of Simple Authentication and Security Layer (SASL)
  Mechanisms for OAuth`

If this specification conflicts with those source documents, fix the drift
before implementation continues. In particular, do not silently change stable
config paths, REST behavior, runtime-control semantics, metric-label policy,
active-affinity semantics, user placement hold behavior, backend-node
stickiness, outbound backend transport behavior or security defaults to make
POP3 easier to implement.

## M7 Goal

M7 implements the first production POP3 director flow:

```text
POP3 client
  -> nauthilus-director POP3 or POP3S listener
      -> optional PROXY protocol
      -> implicit TLS or STLS
      -> POP3 greeting and authorization-state capability surface
      -> USER/PASS or AUTH bearer credential extraction
      -> Nauthilus HTTP/gRPC authentication
      -> director-owned routing fact resolution
      -> user placement hold gate
      -> Redis-backed active affinity or retained backend binding
      -> protocol/backend-pool-scoped backend-pin evaluation
      -> runtime-aware POP3 backend selection
      -> backend POP3 connect, TLS and backend auth/trust
      -> frontend login success only after backend access is ready
      -> transparent bidirectional proxy mode
      -> session lease cleanup and secret-safe observable outcome
```

M7 must keep POP3 mailbox semantics out of the director. The director handles
only the protocol surface required before authentication succeeds, then proxies
transaction and update-state POP3 traffic as opaque bytes. Message sizes, UIDLs,
message numbers, deletion state, `LIST`, `RETR`, `DELE`, `TOP`, `UIDL`,
backend maildrop locks and backend response text belong to the backend POP3
service, not to director routing, metrics or logs.

The hard invariant is same-backend-node user-stateful routing. POP3 uses the
same authoritative tenant and normalized account key as IMAP active affinity,
retained backend binding, ManageSieve sessions, LMTP delivery-scoped holds,
user movement, user placement holds and user backend pins. If an IMAP session,
ManageSieve session, LMTP delivery hold or retained binding already pins the
account to a backend node, a new POP3 session for the same account must select
the POP3 backend entry for that backend node. If no active or retained affinity
exists, POP3 establishes backend-node placement just like IMAP and ManageSieve.

The implementation must prefer shared production boundaries over POP3-specific
side paths. POP3 may have its own wire parser and response syntax, but it must
reuse the existing listener lifecycle, frontend TLS and PROXY handling,
Nauthilus auth mapping, routing resolver, placement gate, `placement.SessionPlacer`,
backend-node selector, runtime state, backend connect request, outbound backend
PROXY preface, transparent proxy pipe, route lookup model and observability
policy wherever those boundaries already exist.

## Delivery Shape

Implement M7 as explicit implementation slices:

1. Config stabilization, validation and listener dispatch for protocol `pop3`.
2. Frontend POP3 authorization-state parser, CAPA, STLS and authentication.
3. Nauthilus auth, routing, placement hold, affinity and backend selection.
4. Backend POP3 connector, backend auth/trust and deep health checks.
5. Proxy handoff, buffered bytes and session cleanup.
6. Runtime state, maintenance, reload and route-lookup integration.
7. POP3 observability, documentation and generated reference updates.
8. Fake-service E2E, real Dovecot POP3 interoperability, demo-stack proof and
   closeout review.

The slices may be committed separately, but M7 is not complete until the
production `nauthilus-director` binary starts configured POP3 listeners,
authenticates through public sockets, proves backend-node behavior with
existing IMAP, ManageSieve and LMTP active or retained affinity state, proxies
maildrop traffic without inspecting it, keeps credentials and mailbox material
out of unsafe telemetry, passes deterministic `make e2e` coverage and passes a
real-server interoperability lane with a real POP3 backend plus the final
`contrib/demo-stack` operator proof when Docker/Compose is available.

## Global Scope

In scope:

- Start configured `pop3` and `pop3s` listeners from the typed config snapshot.
  The canonical protocol string is `pop3`; do not introduce `pop` or `pop3s`
  as alternative protocol values in config, route lookup, metrics or runtime
  state. `pop3s` is a service/listener name only.
- Generalize listener dispatch so IMAP, LMTP, ManageSieve and POP3 handlers are
  selected by protocol without duplicating transport lifecycle code.
- Support the POP3 authorization-state command surface required by the
  architecture:
  - `CAPA`
  - `STLS`
  - `USER`
  - `PASS`
  - `AUTH XOAUTH2`
  - `AUTH OAUTHBEARER`
  - `QUIT`
  - `NOOP`
- Reject all other commands before successful authentication with a POP3
  `-ERR` response and a bounded reason class.
- Treat command names as case-insensitive and argument parsing as strictly
  bounded by `director.security.max_preauth_line_bytes`.
- Support one-shot bearer SASL payloads with either an initial response or one
  bounded continuation response. Do not implement SASL security layers in M7.
- Support implicit TLS for `pop3s` and STLS for `pop3` when configured.
- Require frontend TLS before accepting credential-bearing commands, including
  `USER`/`PASS`, `AUTH XOAUTH2` and `AUTH OAUTHBEARER`. This is a
  director-owned transport safety gate; Nauthilus is called only after implicit
  TLS or successful STLS for such credentials.
- Authenticate through the configured Nauthilus HTTP or gRPC authority. The
  Nauthilus request must use protocol identity `pop3`, not a `service` body
  field.
- Populate the flat Nauthilus SSL request fields from the frontend TLS state,
  including `ssl`, protocol, cipher and available client-certificate metadata.
- Treat Nauthilus as the authentication and identity authority only. Nauthilus
  may provide canonical account, tenant and routing facts; it must not provide
  concrete POP3 backend identifiers.
- Treat a client-supplied `USER` value as provisional protocol input only until
  Nauthilus accepts the credentials. It must not become an authoritative
  affinity key, hold key, backend-pin key, Redis key or metric dimension.
- Enforce the shared user placement hold gate after authoritative
  authentication and routing fact resolution, but before frontend login
  success, backend selection, backend capacity reservation, backend connect,
  backend auth/trust or proxy mode.
- Use the shared routing resolver and backend-node affinity model. Existing
  IMAP sessions, ManageSieve sessions, LMTP delivery holds and retained
  bindings for the same account must influence POP3 placement through the
  shared backend node.
- Apply backend pins only when the pin's protocol and backend pool match the
  POP3 placement request. A pin for an IMAP, LMTP or ManageSieve backend must
  never name the concrete POP3 backend.
- Select POP3 backends through the existing runtime-aware selector, preserving
  health, maintenance, runtime out, drain, weight, max-connection and explicit
  operator backend-pin semantics.
- Connect to POP3 backends with configured plaintext, STLS/STARTTLS or implicit
  TLS modes without disabling certificate verification by default.
- Support backend auth modes for user-stateful protocols: `master_user` and
  `credential_replay`.
- Require `credential_replay` to be explicit, restricted to configured allowed
  mechanisms, protected by verified backend TLS and cleared from memory as soon
  as backend auth succeeds or fails.
- Enter transparent proxy mode only after frontend auth has succeeded at
  Nauthilus, placement has passed the hold gate, a backend has been selected and
  counted, backend transport is established and backend auth/trust has
  succeeded.
- Keep post-auth `STAT`, `LIST`, `RETR`, `DELE`, `RSET`, `TOP`, `UIDL`, `NOOP`,
  `QUIT`, extension commands, backend response text and message content
  backend-owned by proxying them as opaque bytes.
- Extend route lookup diagnostics for `protocol: pop3` without credential
  authentication, backend connect, backend auth, Redis mutation or mailbox
  inspection.
- Extend observability with POP3 pre-auth, auth, placement, backend and proxy
  events using only the approved low-cardinality metric labels.
- Extend deterministic fake-service E2E to cover public sockets, STLS, implicit
  TLS, password and bearer auth, hold gate behavior, backend-pin scoping,
  active-affinity consistency, proxy handoff, secret safety and mailbox-content
  opacity.
- Extend real-server interoperability with a Dovecot POP3 backend while
  preserving the existing real IMAP, LMTP and ManageSieve interop lanes.

Out of scope:

- Implementing a complete POP3 server.
- Implementing mailbox semantics, maildrop locking, message numbering, UIDL
  generation, deletion state, retention policy, quota semantics or message
  content handling in the director.
- Parsing or transforming post-auth POP3 commands for routing, policy or
  telemetry.
- Logging, metric-labeling or tracing message numbers, UIDLs, message sizes,
  subjects, message content, raw backend response text, raw usernames, SASL
  blobs, passwords, bearer tokens, private keys or authorization headers.
- Adding message number, UIDL, message size, user, user hash, session ID,
  request ID, trace ID, client IP, raw backend identifier, raw error text or
  operator hold reason as a Prometheus label.
- Adding POP3 `APOP` support. Its shared-secret digest model is not part of the
  Nauthilus-backed authentication boundary and must not be added as a shortcut.
- Adding POP3 `AUTH PLAIN`, `AUTH LOGIN`, SCRAM, GSSAPI, DIGEST-MD5 or other
  multi-step SASL mechanisms in M7 unless a separate Nauthilus
  challenge/response design is accepted and this specification is amended.
- Treating TLS client certificates as mailbox-user authentication.
- Local OIDC bearer-token validation in the director.
- Treating Nauthilus as a backend selector.
- Calling Nauthilus credential-authentication during route lookup.
- Adding POP3 recipient lookup behavior. POP3 is a mailbox-user login protocol;
  route lookup for POP3 uses caller-supplied user facts.
- Silently falling back to an old backend when a placement hold remains active,
  a pinned backend is unusable or runtime state is ambiguous.
- Letting an IMAP, LMTP or ManageSieve backend pin select a POP3 backend
  directly.
- Exposing LMTP delivery holds as POP3 login sessions.
- Replacing deterministic fake-service E2E with Docker interoperability tests.
- Adding a feature-specific Redis subtree for POP3.

## Stable Config Paths

M7 stabilizes the POP3 listener and backend config paths introduced for this
milestone. These paths must not be renamed, removed or inverted without an
explicit breaking-change decision plus docs, examples, migration notes and
tests:

- `director.listeners.pop3`
- `director.listeners.pop3s`
- common listener fields under those listeners: `protocol`, `service_name`,
  `network`, `address`, `authority`, `backend_pool`, `proxy_protocol` and `tls`
- `director.listeners.pop3.pop3.auth_mechanisms`
- `director.listeners.pop3.pop3.capabilities`
- matching `director.listeners.pop3s.pop3.*` paths
- `director.backend_pools.pop3-default`
- `director.backend_pools.pop3-default.protocol`
- `director.backend_pools.pop3-default.selector`
- `director.backend_pools.pop3-default.backends`
- POP3 backend entries under `director.backends.*` where `protocol: pop3`
- POP3 backend TLS paths: `tls.mode`, `tls.ca_file`, `tls.cert`, `tls.key`,
  `tls.server_name`, `tls.min_tls_version` and `tls.insecure_skip_verify`
- POP3 backend auth paths already used by user-stateful protocols:
  `auth.mode`, `auth.master_user.*` and `auth.credential_replay.*`
- POP3 backend health, maintenance, weight, max-connection and HAProxy paths

M7 may add these paths to the typed defaults and generated references with safe
local-loopback examples. The canonical default listener names should be:

```yaml
director:
  listeners:
    pop3:
      protocol: pop3
      service_name: pop3
      tls:
        mode: starttls
    pop3s:
      protocol: pop3
      service_name: pop3s
      tls:
        mode: implicit
```

Recommended safe example ports are loopback-only `127.0.0.1:10110` for POP3
and `127.0.0.1:10995` for POP3S. Example backend ports may use loopback-only
high ports such as `127.0.0.1:1110` and `127.0.0.1:2110`. These are examples
only; the typed config must not assume deployment-specific public POP3 ports.

POP3 CAPA output is not a blind echo of YAML. The runtime capability surface is
the effective intersection of configured desired capabilities, implemented
authorization-state behavior, listener TLS state, configured auth mechanisms
and backend transport safety. Omitting `STLS`, `USER` or a SASL mechanism from
the effective surface disables the associated command or mechanism for that
session.

M7 should treat `auth_mechanisms` as frontend method policy. The value
`userpass` controls the POP3 `USER`/`PASS` method even though it is not a SASL
mechanism. The values `xoauth2` and `oauthbearer` control the corresponding
POP3 `AUTH` mechanisms. M7 must not advertise `SASL PLAIN` just because the
Nauthilus authority supports password-class authentication.

M7 must keep redaction metadata intact for listener TLS keys, backend TLS keys,
backend master-user password files and any credential-replay or bearer-token
material.

## Target Package Boundaries

M7 expands existing production packages and adds a new protocol package:

```text
internal/protocol/pop3/
internal/protocol/saslcred/
internal/protocol/tlscontext/
internal/listener/
internal/app/
internal/config/
internal/nauthilus/
internal/routing/
internal/placement/
internal/backend/
internal/state/
internal/runtime/
internal/proxy/
internal/observability/
internal/rest/
internal/rest/adapters/
test/e2e/
test/e2e/fakes/pop3_backend/
test/e2e/interop/
docs/
```

Boundary rules:

- `internal/protocol/pop3` owns POP3 greeting, CAPA rendering,
  authorization-state parsing, STLS command handling, credential extraction,
  backend POP3 auth choreography and the transition to proxy mode.
- `internal/protocol/pop3` must not own routing decisions, Redis affinity,
  backend runtime selection, route lookup, listener transport setup or proxy
  byte-copy internals.
- `internal/protocol/saslcred` owns reusable one-shot SASL credential parsing
  for PLAIN, XOAUTH2 and OAUTHBEARER where protocol packages can consume it
  safely. M7 should extend or consume this boundary instead of duplicating
  bearer envelope parsing in POP3.
- `internal/protocol/tlscontext` owns shared extraction of frontend TLS context
  for Nauthilus auth requests where the existing boundary already covers IMAP,
  LMTP and ManageSieve.
- `internal/listener` owns listener lifecycle, transport preparation, PROXY
  protocol and frontend TLS wrapping. It must not contain POP3 command logic.
- `internal/app` owns Fx wiring, dependency construction and protocol handler
  dispatch. It must not become a protocol state machine.
- `internal/config` owns typed POP3 config validation, defaults, redaction
  metadata and generated docs inputs. It must not read raw Viper values from
  protocol code.
- `internal/nauthilus` remains the authentication transport boundary. It must
  not select director backends.
- `internal/routing` owns logical user-to-shard facts only. It must not open
  Redis sessions, select backends or log raw usernames.
- `internal/placement` owns cross-protocol backend-node placement, active and
  retained binding reuse, backend-pin evaluation, holder open/rollback and
  capacity attachment for user-stateful sessions. POP3 must consume the narrow
  `placement.SessionPlacer` API instead of composing Redis state, backend
  selectors and backend pins inside `internal/protocol/pop3`.
- `internal/backend` owns POP3-capable registry and selector behavior,
  effective backend state, health policy, backend runtime constraints and the
  shared outbound backend transport preface. POP3 backend connectors must use
  the existing `backend.ConnectRequest` and shared transport reason classes
  rather than defining protocol-local transport metadata.
- `internal/state` owns Redis-backed active affinity, session leases, backend
  runtime counts and user runtime state.
- `internal/runtime` exposes side-effect-free diagnostics and runtime controls
  without inventing a second POP3 routing model.
- `internal/proxy` owns bidirectional byte copying, deadlines, idle timeouts,
  byte accounting and lease heartbeats after POP3 auth has completed.
- `internal/observability` owns metric instruments, logs, spans and redaction
  policy. Protocol packages record normalized events only.
- `internal/rest` and `internal/rest/adapters` stay generated-contract
  oriented. If M7 changes route-lookup DTOs for POP3 diagnostics, update
  OpenAPI first and regenerate the boundary.

Do not add package-level mutable global state. Use cohesive types and narrow
interfaces so unit tests can exercise parser, auth, placement and backend
handoff behavior without starting the full application. Where IMAP, LMTP or
ManageSieve already share a production boundary, M7 must extend that boundary
for `protocol=pop3` instead of creating a POP3-specific copy. This applies to
listener dispatch, auth context construction, routing resolver input,
placement, backend-node selection, outbound backend PROXY handling, route
lookup, session runtime state and transparent proxy lifecycle.

## M7.1 Config, Validation and Protocol Listener Dispatch

### Purpose

Add typed POP3 configuration and wire protocol dispatch without duplicating
listener lifecycle behavior that already exists for IMAP, LMTP and
ManageSieve.

### In Scope

- Add `pop3` as a valid listener, backend-pool and backend protocol.
- Keep the canonical protocol value `pop3` across config, route lookup,
  runtime state, logs, traces and metrics.
- Add typed listener sub-config for `director.listeners.<name>.pop3`.
- Add safe defaults for `pop3` and `pop3s` listeners, `pop3-default` backend
  pool and two example protocol-specific backend entries.
- Validate that `protocol: pop3` listeners include a `pop3` listener
  sub-config and do not include IMAP, LMTP or Sieve-only sub-config as active
  protocol behavior.
- Validate that a `pop3` listener references a backend pool whose protocol is
  also `pop3`.
- Validate configured POP3 auth methods against the Nauthilus authority's
  supported password and bearer mechanism classes.
- Reject configuration that would advertise or accept credential-bearing
  methods before frontend TLS is active.
- Validate POP3 capabilities as bounded capability policy, not arbitrary wire
  transcript snippets.
- Validate backend auth modes so `pop3` backends support `master_user` and
  `credential_replay` only.
- Extend generated config references, metadata and manpages when typed config
  changes.

### Out of Scope

- Changing stable IMAP, LMTP or ManageSieve config paths.
- Adding a feature-specific Redis subtree for POP3.
- Adding YAML rewrite behavior through REST or CLI.
- Adding POP3 public defaults that bind to non-loopback interfaces.

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

- Reuse the shared listener config fields. Do not create a parallel POP3
  listener model.
- Extend the existing listener manager and application `SessionHandlerFactory`
  dispatch for `protocol=pop3`. Do not add a second listener manager, accept
  loop, TCP/TLS setup path or PROXY-protocol trust boundary for POP3.
- The default `pop3` listener should use STLS-capable starttls mode. The
  default `pop3s` listener should use implicit TLS mode if enabled in defaults.
- Capability config should express stable facts, not arbitrary POP3 response
  lines. Rendering to RFC 2449 CAPA output belongs in `internal/protocol/pop3`.
- `SASL` CAPA content must be derived from configured POP3 auth methods and
  Nauthilus authority support, then mediated by frontend TLS state.
- Config docs must be regenerated through the Makefile targets, not manually
  patched after typed config changes.

### Required Unit Tests

- Config defaults include safe `pop3` protocol examples.
- Config validation accepts `pop3` listener and backend-pool wiring.
- Config validation rejects `pop3` listeners without a `pop3` sub-config.
- Config validation rejects `pop3` listeners that reference non-`pop3` pools.
- Config validation rejects unsupported POP3 auth methods and malformed
  capability values.
- Config validation rejects plaintext credential auth on non-TLS POP3 listener
  policy.
- Config validation rejects `credential_replay` without verified backend TLS.
- Generated config references include all stable M7 paths and protected
  metadata for credential-bearing paths.
- Listener manager tests prove `imap`, `lmtp`, `sieve` and `pop3` are selected
  through the same supported-protocol path and that unsupported protocol values
  still fail closed before sockets bind.

### Required Integration or E2E Tests

- Start the production binary with one STLS `pop3` listener and one implicit-TLS
  `pop3s` listener.
- Verify listener runtime listing and route lookup accept `protocol: pop3`.
- Verify IMAP, LMTP and ManageSieve listeners still start from the same config
  file.

### Acceptance Criteria

- Typed config, generated references and validation understand protocol `pop3`.
- Listener dispatch starts POP3 handlers without duplicating listener lifecycle
  code.
- Existing IMAP, LMTP and ManageSieve config behavior remains compatible.

### Review Checklist

- Verify no raw Viper reads exist in `internal/protocol/pop3`.
- Verify `pop` and `pop3s` are not introduced as second protocol values.
- Verify config changes are reflected in generated docs and manpages.
- Verify protected config paths remain redacted by default.

## M7.2 Frontend POP3 State Machine, TLS and Authentication

### Purpose

Implement the minimal POP3 authorization-state surface needed to authenticate,
route and safely hand off to a backend without becoming a full POP3 server.

### In Scope

- Send a POP3 `+OK` greeting when the frontend connection is ready.
- Implement `CAPA` before auth as the effective frontend capability surface.
- Implement `NOOP` and `QUIT` before auth.
- Implement `STLS` only when advertised and only on non-implicit TLS listeners.
- Remove `STLS` from the effective CAPA set after TLS is active.
- Implement `USER` and `PASS` as a password-class frontend auth method:
  - `USER` stores only a provisional login name.
  - `PASS` authenticates the provisional login and supplied secret through
    Nauthilus.
  - `PASS` without `USER` fails before Nauthilus is called.
- Implement `AUTH` for configured bearer mechanisms:
  - `XOAUTH2`
  - `OAUTHBEARER`
- Support an optional initial response or one bounded continuation response for
  the bearer mechanisms.
- Support SASL cancellation without logging the payload.
- Reject SASL security layer negotiation. The director does not implement SASL
  wrapping for post-auth traffic.
- Enforce `runtime.timeouts.preauth`, `runtime.timeouts.auth`,
  `director.security.max_preauth_line_bytes` and
  `director.security.max_preauth_literal_bytes` for any continuation payloads.
- Authenticate through Nauthilus and keep credentials secret-safe throughout.
- Delay frontend login success until placement and backend access are ready.
- Return a generic POP3 temporary failure for temporary placement or
  backend-readiness failures that occur after Nauthilus accepts the user.

### Out of Scope

- Full post-auth command parsing.
- `STAT`, `LIST`, `RETR`, `DELE`, `RSET`, `TOP`, `UIDL` or extension command
  semantics in the director.
- `APOP`.
- `AUTH PLAIN`, `AUTH LOGIN`, SCRAM, GSSAPI, DIGEST-MD5 or other multi-step
  mechanisms unless a separate Nauthilus challenge/response design is accepted.
- SASL security layers.
- Client certificate identity mapping as mailbox-user authentication.
- Local OIDC bearer-token validation in the director.

### Expected Files or Packages

```text
internal/protocol/pop3/session.go
internal/protocol/pop3/parser.go
internal/protocol/pop3/commands.go
internal/protocol/pop3/capability.go
internal/protocol/pop3/auth.go
internal/protocol/pop3/sasl.go
internal/protocol/pop3/starttls.go
internal/protocol/pop3/responses.go
internal/protocol/pop3/secret.go
internal/protocol/saslcred/
internal/protocol/pop3/*_test.go
```

### Implementation Notes

- RFC 1939 starts POP3 in authorization state. Treat M7 as owning only enough
  authorization-state behavior to reach backend proxy mode.
- `USER` must never be used as the authoritative hold key or affinity key.
  Store it as short-lived auth input only, and replace it with Nauthilus'
  canonical account and tenant after authentication succeeds.
- CAPA is generated by the director because no user backend has been selected
  yet.
- `SASL` in CAPA may be absent before TLS when bearer mechanisms require TLS.
  `USER` may likewise be omitted when the `userpass` method is disabled or
  blocked by plaintext frontend state.
- Do not use human-readable POP3 response text as program semantics. Tests
  should assert bounded response class and reason class.
- The SASL service name and Nauthilus auth context protocol are `pop3`.
- If bearer envelope parsing, secret wrappers or Nauthilus auth-context mapping
  overlaps with IMAP or ManageSieve, extract or reuse shared behavior through a
  narrow protocol-neutral boundary. `internal/protocol/pop3` must not import
  IMAP or Sieve internals and must not copy their auth pipeline when a shared
  abstraction already exists or can be introduced cleanly.
- A failed `PASS` or `AUTH` may allow another auth attempt within pre-auth
  attempt limits. A successful auth attempt transitions to backend placement
  and then proxy mode; re-authentication is backend-owned only after proxy
  mode.
- Credential-bearing commands before TLS must fail closed before Nauthilus is
  called. M7 must not add a compatibility flag that permits password or bearer
  auth on plaintext frontend connections.
- STLS must reject plaintext command injection across the TLS boundary. Any
  bytes buffered in the old plaintext state after a successful STLS response
  must be treated as unsafe unless the existing listener/TLS boundary already
  proves they are part of the TLS handshake.

### Required Unit Tests

- Greeting renders a safe POP3 `+OK` response without leaking instance secrets.
- `CAPA` renders configured and implemented capabilities and omits unsafe auth
  methods before TLS.
- `CAPA` changes after STLS and remains stable otherwise.
- `STLS` fails when not advertised, succeeds when configured and rejects
  leftover plaintext command injection across the TLS boundary.
- `USER` stores only provisional login input and does not call routing,
  placement, state or backend code.
- `PASS` without `USER` fails before Nauthilus.
- `USER`/`PASS` parse valid bounded credentials and reject oversized input.
- `AUTH XOAUTH2` and `AUTH OAUTHBEARER` parse valid initial or continuation
  responses and reject malformed or oversized payloads.
- SASL cancellation returns a safe `-ERR` without leaking payloads.
- Unsupported mechanisms and SASL security-layer requests fail closed.
- Unsupported pre-auth commands return `-ERR` and do not reach routing or
  backend code.
- Nauthilus requests use `protocol: pop3` and do not include a forbidden
  `service` body field.
- Nauthilus requests include truthful frontend SSL DTO fields for plaintext,
  STLS and implicit TLS states.

### Required Integration or E2E Tests

- Connect to public `pop3` and `pop3s` sockets and verify greeting, `CAPA`,
  `NOOP`, `QUIT`, STLS and auth behavior.
- Verify plaintext password auth is rejected before STLS on the default `pop3`
  listener.
- Verify bearer mechanisms pass only bearer material to Nauthilus and do not
  log tokens.

### Acceptance Criteria

- POP3 authorization-state handling is complete inside the M7 boundary.
- Authentication succeeds only through Nauthilus and only for configured
  methods.
- Frontend login success is not sent until backend access is ready.

### Review Checklist

- Verify the parser does not understand maildrop semantics before auth.
- Verify STLS, passwords and SASL payloads cannot leak through logs, traces,
  metrics or test failure output.
- Verify unsupported mechanisms do not trigger fallback credential parsing.
- Verify provisional `USER` values are never used as authoritative placement
  identity.

## M7.3 Authenticated Placement, Hold Gate, Affinity and Backend Selection

### Purpose

Route authenticated POP3 users through the same director-owned placement model
as IMAP, ManageSieve and LMTP, including user placement holds, active and
retained backend-node affinity, backend pins and runtime-aware selection.

### In Scope

- Convert Nauthilus auth success into the canonical account key, tenant and
  routing attributes used by the shared resolver.
- Resolve routing facts through `internal/routing`, not through backend or REST
  packages.
- Apply the shared user placement hold gate after auth and routing, before
  frontend login success and before backend selection.
- If the hold clears or expires within the bounded wait budget, re-read active
  affinity, retained backend binding, movement overrides, backend-pin state,
  backend health and capacity before selecting.
- If the hold remains active past the wait budget, return a generic temporary
  POP3 failure and do not fall back to the old backend.
- Open Redis-backed active affinity/session state for POP3 sessions, including
  the selected backend node and retained-binding expiry.
- Treat POP3 sessions as user-stateful active sessions visible through session
  APIs with protocol `pop3`, but without message numbers, UIDLs, message sizes
  or command payloads.
- Select a concrete POP3 backend from
  `backend_node + protocol=pop3 + backend_pool`.
- Apply operator backend pins only when protocol, backend pool, selected shard
  and backend node match.
- Let explicit backend pins bypass `weight_zero` for the pinned backend only,
  while preserving every other fail-closed exclusion.
- Reuse backend attach/capacity reservation behavior and rollback on placement,
  connect or backend-auth failure.
- Preserve existing active and retained backend-node affinity from IMAP
  sessions, ManageSieve sessions and LMTP delivery holds.

### Out of Scope

- Creating a second POP3-specific routing model.
- Letting client-supplied usernames become authoritative after Nauthilus returns
  canonical identity facts.
- Holding unauthenticated sockets before the director knows the user key.
- Exposing waiter lists through v1 REST APIs.
- Treating route lookup as a placement operation.

### Expected Files or Packages

```text
internal/protocol/pop3/placement.go
internal/placement/
internal/runtime/users.go
internal/state/
internal/backend/
internal/routing/
internal/protocol/pop3/*_test.go
test/e2e/
```

### Implementation Notes

- Use the existing `runtime.PlacementGate` interface. M7 should not add a
  protocol-specific hold implementation.
- The placement gate request must use `Protocol: "pop3"` plus the listener and
  service names from the frontend session context.
- After the hold gate releases, call `placement.SessionPlacer.PlaceSession`
  with a `placement.SessionRequest` carrying `Protocol: "pop3"`, the
  listener/service names, backend pool, normalized affinity key, lease TTL,
  idle grace, backend-retention TTL and director instance ID. The protocol
  package must not directly call `state.OpenSession`, `state.LookupAffinity`,
  `state.GetUserBackendPin`, `backend.Select`, `backend.SelectInBackendNode`,
  `state.ReserveBackendCapacity` or Redis Lua scripts for normal placement.
- POP3 session records should use the same normalized affinity key model as
  IMAP and ManageSieve. Raw usernames must not be Redis key material.
- If active or retained affinity already exists for the user, it chooses the
  backend node. The POP3 selector then resolves that backend node to a
  protocol-specific `pop3` backend entry through the shared placement service
  and runtime-aware backend-node selector.
- If a backend pin is present for another protocol or backend pool, report the
  mismatch in route lookup but ignore it for live placement.
- If a matching backend pin names an unusable backend, fail closed. Do not
  silently select another backend.
- Placement rollback is owned by the placement lease lifecycle. The POP3
  protocol code may close the returned lease on later backend connect/auth/proxy
  setup failure, but it must not try to repair affinity or backend reservation
  state itself.

### Required Unit Tests

- Successful Nauthilus auth feeds the shared routing resolver.
- Placement hold wait runs after auth/routing and before backend selection.
- Hold timeout returns a temporary POP3 failure and does not open a session,
  reserve backend capacity, connect to a backend or send login success.
- Existing IMAP active or retained affinity controls POP3 selected backend
  node.
- Existing ManageSieve active or retained affinity controls POP3 selected
  backend node.
- Existing LMTP delivery-scoped active or retained affinity controls POP3
  selected backend node.
- POP3 opens and heartbeats a visible user session after placement.
- POP3 placement calls the shared `placement.SessionPlacer` once per
  authenticated session and passes `Protocol: "pop3"` in the request.
- Backend pins apply only for matching `protocol=pop3` and backend pool.
- Cross-protocol backend pins do not name the concrete POP3 backend.
- Matching backend pins bypass only `weight_zero` and fail closed for all other
  exclusions.
- Placement rollback closes affinity/session state after backend selection,
  attach, connect or backend-auth failure.

### Required Integration or E2E Tests

- Public POP3 login routes to the same backend node as an active or retained
  IMAP binding.
- Public POP3 login routes to the same backend node as an active or retained
  ManageSieve binding.
- Public POP3 login routes to the same backend node as an in-flight or retained
  LMTP delivery binding for the same resolved account.
- `nauthilus-directorctl users hold set` causes a public POP3 auth to wait and
  then temporary-fail without backend connect when the hold remains active.
- `nauthilus-directorctl users backend-pin set` routes only matching POP3
  sessions to the pinned `pop3` backend.
- An IMAP, LMTP or ManageSieve backend pin does not select a concrete POP3
  backend.

### Acceptance Criteria

- POP3 placement uses the same active-affinity and runtime-control model as
  IMAP and ManageSieve.
- Holds and backend pins are enforced at the correct boundary.
- Same-backend-node cross-protocol behavior is proven through public sockets.

### Review Checklist

- Verify frontend login success cannot be returned before hold and backend
  readiness checks complete.
- Verify `internal/protocol/pop3` does not reimplement placement by directly
  composing Redis affinity, backend-pin reads, backend selection or backend
  capacity reservations.
- Verify raw usernames are not Redis keys or metric labels.
- Verify backend-pin handling does not cross protocol or backend-pool scopes.
- Verify failures clean up session and backend capacity state.

## M7.4 Backend POP3 Connector, Auth and Health

### Purpose

Connect to selected POP3 backends, establish the configured backend transport
and authenticate or establish trust before frontend login success.

### In Scope

- Implement POP3 backend connect over TCP through the same backend connection
  request boundary used by IMAP, LMTP and ManageSieve.
- Support backend TLS modes:
  - `none`
  - `starttls`
  - `implicit`
- Use `backend.ConnectRequest` for session and health connections, including
  selected backend, timeout, connect purpose, observability and, for real
  sessions, the effective frontend source/destination tuple needed for
  backend-side PROXY protocol.
- Emit outbound backend PROXY protocol through the shared `internal/backend`
  transport helper before any POP3 backend greeting, STLS or auth bytes when
  the selected backend enables it.
- Verify backend certificates by default when TLS is enabled.
- Read backend greeting and CAPA without logging unbounded backend text.
- Perform backend auth modes:
  - `master_user`
  - `credential_replay`
- Support backend `USER`/`PASS` for master-user auth.
- Support credential replay only for configured allowed frontend methods and
  only when backend TLS is verified if policy requires it.
- Clear replayed frontend credentials immediately after backend auth succeeds or
  fails.
- Consume backend auth success/failure and map failures to safe frontend
  response classes.
- Implement POP3 backend deep health checks: connect, TLS/STLS, greeting,
  `CAPA`, configured health `USER`/`PASS`, optional `NOOP`, `QUIT`.
- Integrate POP3 backend health by extending the existing health-runner
  protocol checker dispatch. Do not add a separate POP3 health worker.
- Keep health checks away from mailbox-reading or mailbox-mutating commands.

### Out of Scope

- Unix socket backend connectivity unless already provided generically.
- Backend maildrop operation health checks.
- Backend CAPA extension discovery as a routing input.
- Trusting a backend that cannot authenticate the selected user.
- Translating frontend auth methods into unsupported backend mechanisms.

### Expected Files or Packages

```text
internal/protocol/pop3/backend.go
internal/protocol/pop3/backend_auth.go
internal/protocol/pop3/health.go
internal/backend/
internal/backend/proxy_transport.go
internal/config/
internal/protocol/pop3/*_test.go
```

### Implementation Notes

- Backend auth behavior should reuse IMAP user-stateful auth concepts where the
  protocol allows it, but keep POP3 wire syntax in `internal/protocol/pop3`.
- Backend connection code may follow the IMAP and ManageSieve connector shape,
  but the shared pieces must stay shared: request shape, outbound PROXY
  preface, bounded transport reason classes, TLS verification policy and health
  purpose handling.
- Backend `master_user` should format the selected canonical user through the
  configured `user_format` and then use POP3 `USER` plus `PASS`.
- Backend `credential_replay` extends the lifetime of user secrets and must
  remain opt-in. `USER`/`PASS` replay uses the short-lived accepted frontend
  credential material; bearer replay uses only configured allowed bearer
  mechanisms that the backend advertises or policy declares safe.
- Backend auth failure after Nauthilus success is a backend-readiness failure to
  the frontend, not proof that the user credentials were invalid at Nauthilus.
  Prefer a temporary POP3 failure for ambiguous backend failures.
- Deep health must never send `STAT`, `LIST`, `RETR`, `DELE`, `RSET`, `TOP`,
  `UIDL` or any command that can inspect or mutate a user's maildrop.

### Required Unit Tests

- Backend connect handles plaintext, STLS and implicit TLS.
- Backend STLS requires advertised support and fails closed on TLS errors.
- Backend certificate verification is on by default.
- `master_user` auth formats the selected user and master credential without
  logging the password.
- `credential_replay` requires allowed methods and verified TLS when
  configured.
- Backend auth failure maps to safe temporary frontend failure text.
- Session backend connect writes an outbound PROXY preface when configured and
  uses the effective trusted frontend tuple as source/destination metadata.
- Health backend connect uses `ConnectPurposeHealth`, does not require a
  frontend tuple and reports the shared bounded transport reason classes.
- Backend health checks stop before mailbox commands.
- Backend health does not log health username, password, message numbers, UIDLs
  or raw backend status text.

### Required Integration or E2E Tests

- Fake POP3 backend proves backend auth mode `master_user`.
- Fake POP3 backend proves credential replay with verified TLS.
- Fake POP3 backend forces auth, greeting, STLS and CAPA failures so the
  director fails closed and cleans up runtime state.
- Health runner marks POP3 backends healthy/unhealthy through public runtime
  diagnostics without exposing backend identifiers or backend nodes as metric
  labels.

### Acceptance Criteria

- Backend POP3 access is established before frontend login success.
- Backend auth is explicit, tested and secret-safe.
- Health checks are protocol-aware and non-mutating.

### Review Checklist

- Verify backend auth code does not share IMAP parser internals by accident.
- Verify backend connect does not define a second outbound PROXY protocol
  implementation or protocol-local transport reason vocabulary.
- Verify credential replay cannot run over unverified plaintext by default.
- Verify backend health cannot inspect, retrieve, delete or enumerate mail.

## M7.5 Proxy Handoff, Buffered Bytes and Session Cleanup

### Purpose

Hand authenticated POP3 sessions into transparent proxy mode without losing
pipelined bytes, parsing mailbox commands or leaking mailbox data.

### In Scope

- Send frontend login success only after backend auth/trust is complete.
- Preserve safe buffered post-auth client bytes and forward them to the selected
  backend after auth succeeds.
- Use `internal/proxy` for bidirectional stream copy after handoff.
- Heartbeat the POP3 session lease while proxy mode is active.
- Close session state and backend capacity accounting when proxy mode ends.
- Keep post-auth POP3 commands and responses opaque to the director.
- Preserve proxy idle timeouts, byte accounting and graceful shutdown behavior.

### Out of Scope

- Parsing message numbers, UIDLs, message sizes or message contents for
  telemetry, routing, policy or validation.
- Transforming post-auth POP3 commands.
- Retrying post-auth commands on another backend after proxy mode begins.
- Spooling messages.

### Expected Files or Packages

```text
internal/protocol/pop3/session.go
internal/protocol/pop3/proxy.go
internal/proxy/
internal/state/
test/e2e/fakes/pop3_backend/
```

### Implementation Notes

- Treat post-auth POP3 command arguments and backend response payloads exactly
  like opaque bytes. The proxy pipe should not attempt to understand POP3
  transaction or update-state framing.
- Handoff must be careful around login success: any client bytes already read
  by the authorization-state parser and not consumed by auth must be sent to
  the backend in order.
- If backend auth succeeds but the frontend login success response cannot be
  written, close the backend connection and roll back session state.
- If proxy mode exits with an error, report bounded reason classes only.
- Do not special-case POP3 `QUIT` in proxy mode. Once proxy mode starts,
  backend POP3 owns transaction/update semantics and the generic proxy owns
  connection cleanup.

### Required Unit Tests

- Buffered post-auth bytes after successful auth reach the backend exactly once.
- Backend-to-client buffered bytes from backend auth/CAPA handling are relayed
  or safely replaced according to policy.
- Proxy close calls session cleanup and backend detach exactly once.
- Message numbers, UIDLs and message content in proxied bytes are not recorded
  by observability events.
- Failed frontend success write rolls back backend and session state.

### Required Integration or E2E Tests

- Through the public POP3 listener, authenticate and issue `STAT`, `LIST`,
  `UIDL`, `RETR`, `DELE`, `RSET` and `QUIT` against a fake backend.
- Include unique sentinel UIDLs and message content, then assert logs, metrics,
  traces and test observations do not leak them.
- Verify graceful shutdown lets an active POP3 proxy session drain until
  timeout, then closes it.

### Acceptance Criteria

- Post-auth POP3 traffic is transparent and opaque.
- Runtime leases and backend counts are cleaned up after proxy exit.
- Mailbox material does not appear in unsafe observable output.

### Review Checklist

- Verify no post-auth parser is introduced in the director.
- Verify buffered bytes cannot be dropped or replayed.
- Verify proxy telemetry remains byte/duration oriented, not command oriented.

## M7.6 Runtime State, Maintenance, Reload and Route Lookup

### Purpose

Integrate POP3 with the completed runtime-control model without adding a
parallel management surface.

### In Scope

- Include POP3 sessions in session runtime state as protocol `pop3`.
- Let backend runtime state, soft/hard maintenance, runtime out, drain, weight
  override and max-connection limits affect POP3 selection.
- Keep soft maintenance semantics: exclude from new initial placements while
  preserving existing active sessions and active pins by default.
- Keep hard maintenance and drain behavior consistent with IMAP and ManageSieve
  user-stateful sessions.
- Ensure reload changes affect new POP3 sessions without breaking active proxy
  sessions unexpectedly.
- Extend route lookup for `protocol: pop3` using the existing
  side-effect-free route lookup service.
- Route lookup must report routing source, selected shard, selected backend
  node, active or retained affinity, backend-pin context, user-hold context,
  backend eligibility and fail-closed reasons.
- Route lookup must not authenticate credentials, create sessions, refresh
  leases, wait on holds, connect to backends, perform backend auth or inspect
  mailbox data.

### Out of Scope

- POP3-specific REST mutation endpoints.
- Mailbox operation REST APIs.
- Route lookup accepting passwords, bearer tokens, SASL blobs, message numbers,
  UIDLs or message content.

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
- The CLI should support `nauthilus-directorctl route lookup --protocol pop3`
  with the same user-key and attribute model as IMAP and ManageSieve.
- Route lookup output must not include operator hold reason text, raw backend
  identifiers or backend nodes as metric labels, raw usernames, message
  numbers, UIDLs or message content.
- Runtime APIs should expose backend identifiers and backend nodes in REST
  diagnostics where the existing policy permits them, but never as Prometheus
  labels.

### Required Unit Tests

- Session list filters include `protocol=pop3`.
- Runtime maintenance and drain exclude new POP3 placement as expected.
- Route lookup for `protocol=pop3` uses the shared resolver and selector.
- Route lookup reports active user hold without waiting.
- Route lookup reports matching, mismatched and unusable backend-pin context.
- Route lookup rejects credential-bearing and mailbox-bearing input.
- Route lookup performs no Redis mutations or backend connections.

### Required Integration or E2E Tests

- `nauthilus-directorctl sessions list --protocol pop3` reports active POP3
  sessions without mailbox data.
- `nauthilus-directorctl route lookup --protocol pop3 ...` predicts the same
  backend selected by a later public POP3 login when runtime state is
  unchanged.
- Runtime out and maintenance changes affect new POP3 sessions through public
  control API and CLI commands.

### Acceptance Criteria

- POP3 participates in the existing runtime model.
- Route lookup remains diagnostic and side-effect-free.
- Reload and maintenance behavior is consistent with IMAP and ManageSieve.

### Review Checklist

- Verify no POP3 route lookup code calls Nauthilus credential auth.
- Verify no message numbers, UIDLs or message contents enter REST or CLI
  diagnostics.
- Verify runtime behavior is not duplicated in protocol code.

## M7.7 Observability, Metrics, Logs and Traces

### Purpose

Make POP3 behavior observable enough for operators to diagnose auth, routing,
hold, backend and proxy failures without exposing credentials or mailbox data.

### In Scope

- Add or activate POP3 pre-auth span:

```text
nauthilus_director.pop3.pre_auth
```

- Reuse existing spans for:
  - `nauthilus_director.session`
  - `nauthilus_director.nauthilus.auth`
  - `nauthilus_director.routing.resolve`
  - `nauthilus_director.backend.select`
  - `nauthilus_director.backend.connect`
  - `nauthilus_director.proxy.pipe`
- Add bounded events for:
  - POP3 session start/end
  - greeting/CAPA render result
  - STLS result
  - `USER` and auth mechanism/result, without storing usernames or secrets
  - Nauthilus auth result
  - placement hold wait/release/timeout
  - active-affinity open/heartbeat/close
  - backend-pin applied/mismatch/fail-closed
  - backend select/connect/auth result
  - proxy start/end
- Add Prometheus observations using only approved labels.
- Use bounded status classes and reason classes, not raw backend text.
- Allow backend identifiers and backend nodes in logs/traces only where the
  existing policy permits operator diagnostics.
- Keep message numbers, UIDLs, message sizes, message content, raw usernames,
  passwords, bearer tokens, SASL blobs and private keys out of logs, metrics
  and traces.

### Out of Scope

- Command counters by message number, UIDL, mailbox size or user.
- Message content sampling.
- Full POP3 transcript logging.
- Raw backend response text as a metric label.
- Pseudonymous user correlation unless a separate privacy decision adds it.

### Expected Files or Packages

```text
internal/observability/
internal/protocol/pop3/observability.go
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
backend_node
token
password
sasl_blob
raw_error
```

M7 also treats the following as forbidden observable payloads outside the
client/backend wire:

```text
message_number
uidl
message_size
message_content
post_auth_command_body
operator_hold_reason
```

POP3 metrics should cover:

- pre-auth command totals
- auth totals and durations
- placement hold outcomes
- backend selection/connect/auth outcomes
- active session counts and durations
- proxy bytes and durations

Backend-binding reason classes used by POP3 and shared placement must remain
bounded. The shared set includes:

```text
active_backend_binding
retained_backend_binding
backend_node_missing_protocol
backend_node_unusable
backend_node_mismatch
binding_invalidated_hard_down
binding_retained
binding_expired
```

### Required Unit Tests

- POP3 metric registration uses only allowed labels.
- Message numbers, UIDLs and message content sent through fake proxy bytes are
  rejected by observability policy and do not become event fields.
- Span attributes do not contain raw usernames, message data, SASL blobs,
  bearer tokens, client IPs or session IDs.
- Reason classes are bounded for parser, auth, routing, hold, backend and proxy
  failures.

### Required Integration or E2E Tests

- `/metrics` exposes POP3 auth/session/proxy counters after a public POP3 flow.
- Logs for a POP3 flow contain operation/result/reason classes but no
  credentials, raw usernames, message numbers, UIDLs or message contents.
- Tracing captures POP3 pre-auth and nested routing/backend/proxy boundaries
  when tracing is enabled.

### Acceptance Criteria

- Operators can distinguish auth failures, hold timeouts, backend-pin failures,
  backend failures and proxy failures.
- No unsafe credential, identity or mailbox material appears in observable
  output.

### M7.7 Implementation Evidence

As of 2026-06-05, the POP3 observability slice is implemented at unit/package
level without marking the full M7 milestone complete. POP3 now uses the prepared
`nauthilus_director.pop3.pre_auth` span, the shared session, Nauthilus auth,
routing, backend select/connect and proxy span boundaries, and the shared
Prometheus families with approved low-cardinality labels only.

Focused coverage in `internal/protocol/pop3/observability_test.go` and
`internal/observability/prometheus_test.go` verifies POP3 metric labels, trace
attribute redaction, mailbox sentinel rejection for message numbers, UIDLs,
message sizes and message content, and bounded reason classes for parser, auth,
routing, hold, backend and proxy failures. The 2026-06-05 validation pass for
this slice ran `make check-docs`, `make test` and `make build-check`.

This is not final M7 completion evidence. M7.8 still owns fake-service E2E,
real POP3 interoperability, demo-stack proof, `make guardrails` closeout and
the eventual `### Completion Evidence` section.

### Review Checklist

- Verify no POP3 metric label violates the allowlist.
- Verify mailbox contents are not logged even in test failure paths.
- Verify backend identifiers and backend nodes remain forbidden as metric
  labels.

## M7.8 E2E, Interoperability, Documentation and Guardrails

### Purpose

Prove POP3 through public system boundaries, keep fake-service edge coverage
deterministic and preserve existing IMAP, LMTP and ManageSieve real-server
interop lanes.

### In Scope

- Extend `make e2e` to prove POP3 through public sockets.
- Extend `make e2e-interop` with a real POP3 backend scenario.
- Keep existing real IMAP, LMTP and ManageSieve interoperability coverage
  intact.
- Use the production `nauthilus-director` binary in E2E tests.
- Use fake Nauthilus HTTP and gRPC authority sockets where deterministic auth
  and routing outcomes are needed.
- Use fake IMAP, LMTP, ManageSieve and POP3 backends where cross-protocol
  active-affinity and edge cases must be forced deterministically.
- Use Dovecot project-provided assets as the real POP3 backend where practical.
- Update `contrib/demo-stack` config, images, bootstrap data, backend wiring,
  proof scripts and operator docs when M7 changes operator-visible topology or
  protocol behavior.
- Use the demo stack as the final operator-facing proof for M7 whenever
  Docker/Compose is available.
- Update docs, manpages and generated config references when POP3 behavior or
  config changes.
- Before M7 is marked complete, add a `### Completion Evidence` section to
  this specification after the top-level acceptance checklist. The note must
  record the closeout date, the implemented POP3 surface, deterministic E2E
  proof, real-server interoperability proof, demo-stack proof and final
  validation results.
- Before M7 is marked complete, update `docs/ARCHITECTURE_ROADMAP.md` under
  `### M7: POP3` with a concise `Status: completed` paragraph that points back
  to this specification for detailed completion evidence.
- Run `make check-openapi` after any OpenAPI or generated REST/client change.
- Run `make check-docs` after typed config, metadata or generated docs changes.
- Run `make guardrails` before any commit or pull request containing M7
  implementation work.

### Out of Scope

- Depending on Docker interop for deterministic edge coverage.
- Removing or weakening existing IMAP, LMTP or ManageSieve interop tests.
- Testing backend POP3 mailbox implementation details as a director correctness
  requirement.
- Requiring external network access in default guardrail tests.

### Expected Files or Packages

```text
test/e2e/
test/e2e/fakes/pop3_backend/
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
- start fake POP3 backends on public loopback sockets;
- exercise `pop3` STLS and `pop3s` implicit TLS;
- authenticate with `USER`/`PASS` and bearer mechanisms;
- force routing to multiple shards;
- prove active and retained IMAP affinity influences POP3 placement;
- prove active and retained ManageSieve affinity influences POP3 placement;
- prove an in-flight and retained LMTP delivery hold influences POP3 placement;
- prove POP3 active and retained affinity influences a concurrent or subsequent
  IMAP or ManageSieve login;
- prove user placement hold timeout returns a temporary POP3 failure before
  backend connect;
- prove backend-pin matching, mismatch and fail-closed behavior;
- proxy post-auth commands containing sentinel UIDLs and message content;
- assert sentinel UIDLs and message content do not appear in logs, metrics,
  traces or route lookup output.

Real-server interop should:

- preserve the existing Dovecot IMAP lane;
- preserve the existing Postfix-to-Director-to-Dovecot LMTP lane;
- preserve the existing Dovecot ManageSieve lane;
- start a real Dovecot POP3 backend;
- authenticate through the director to the real backend;
- perform at least one real POP3 mailbox read workflow through the director,
  such as `CAPA`, `USER`/`PASS`, `STAT`, `LIST`, `UIDL`, `RETR` and `QUIT`;
- prove the same account routes to the same backend node for POP3 and IMAP;
- skip with an explicit stable message when Docker or the real backend tool
  container is unavailable.

Demo-stack proof should:

- keep existing demo-stack IMAP, LMTP and ManageSieve proof scripts working;
- add or update POP3 demo-stack services, listeners, backend wiring and proof
  scripts as needed;
- rebuild the director image before proving M7 behavior when code, config or
  packaging changes affect the image;
- prove POP3 through `contrib/demo-stack` after the stack is updated;
- record a stable skip reason when Docker/Compose is unavailable.

Closeout documentation should:

- leave `Status: planned` in this specification until the implementation,
  public-boundary proof, real-server interop, demo-stack proof and guardrails
  are actually complete;
- add `### Completion Evidence` only at closeout time, with concrete dates,
  protocol behavior, proof lanes and validation commands rather than expected
  future work;
- update the M7 roadmap entry in the same closeout change so milestone status
  and detailed evidence cannot drift apart;
- keep the roadmap paragraph short and point to this specification for the
  detailed evidence, following the M6 completion pattern.

### Required Unit Tests

- Fake POP3 backend status scripting is deterministic.
- Fake backend observations hide message numbers, UIDLs, message contents and
  credentials.
- Interop skip messages are stable and explicit.

### Required Integration or E2E Tests

- `make e2e` proves POP3 public listener behavior, auth, routing, hold gate,
  backend-pin scoping, proxy handoff and mailbox-data secrecy.
- `make e2e` proves POP3 and IMAP same-backend-node consistency.
- `make e2e` proves POP3 and ManageSieve same-backend-node consistency.
- `make e2e` proves LMTP delivery-hold-to-POP3 backend-node consistency.
- `make e2e-interop` proves real Dovecot POP3 access through the director on a
  Docker-capable environment.
- `contrib/demo-stack` is updated and proves the M7 operator path on a
  Docker/Compose-capable environment.
- Existing IMAP, LMTP and ManageSieve interop scenarios remain available and
  are not removed or weakened by the POP3 changes.

### Acceptance Criteria

- Deterministic fake-service E2E covers forced POP3 edge cases.
- Real-server POP3 interop passes before M7 is considered complete.
- Existing IMAP, LMTP and ManageSieve interop coverage is preserved.
- Demo-stack topology, config, proof scripts and docs are updated for M7 and
  pass their final proof, or skip with an explicit environment reason.
- Documentation and generated references match supported POP3 behavior.
- The final closeout adds `### Completion Evidence` to this specification and
  a matching `Status: completed` paragraph to the M7 roadmap entry.

### Review Checklist

- Verify fake-service success is not used as a substitute for real POP3
  interop.
- Verify real interop is skipped only with stable environment-related reasons.
- Verify E2E proves cross-protocol active-affinity behavior.
- Verify `contrib/demo-stack` was checked and updated in the same change when
  M7 topology, images, config, backend wiring or proof scripts changed.
- Verify docs/manpages describe protocol value `pop3` and not a second `pop3s`
  config or runtime protocol value.
- Verify the final closeout records completion evidence in this specification
  and updates the M7 roadmap status in the same change.

## Top-Level Acceptance Checklist

M7 is complete only when all items below are true:

- [x] `pop3` and `pop3s` listeners start from typed config through the
      production server binary.
- [x] Listener dispatch supports IMAP, LMTP, ManageSieve and POP3 without
      duplicating transport lifecycle behavior.
- [x] The application handler factory, listener manager, health-runner protocol
      dispatch and route-lookup listener contexts are extended for
      `protocol=pop3` instead of adding parallel POP3 lifecycle code.
- [x] POP3 CAPA advertisement matches implemented behavior and RFC 2449
      framing.
- [x] STLS and implicit TLS behavior are implemented and tested.
- [x] Credential-bearing POP3 methods require frontend TLS before Nauthilus is
      called.
- [x] `USER`/`PASS`, `AUTH XOAUTH2` and `AUTH OAUTHBEARER` are authenticated
      through Nauthilus when configured.
- [x] The Nauthilus auth request uses `protocol: pop3` and does not send a
      forbidden `service` body field.
- [x] A client-supplied `USER` value remains provisional until Nauthilus returns
      canonical account facts and is never used as an authoritative placement
      key.
- [x] Frontend login success is returned only after Nauthilus auth, routing,
      hold gate, backend selection, backend connect and backend auth/trust all
      succeed.
- [x] POP3 checks user placement holds after authoritative auth and routing
      facts, before backend selection or login success.
- [x] Hold timeout returns a generic temporary failure and never falls back to
      the old backend.
- [x] POP3 placement consumes health, maintenance, runtime out, drain, weight,
      max-connection and backend-pin state.
- [x] POP3 placement uses the shared `placement.SessionPlacer` /
      `PlaceSession` boundary and does not directly compose Redis affinity,
      backend-pin reads, backend selectors or backend reservations.
- [x] Backend pins apply only when protocol, backend pool, selected shard and
      backend node match the POP3 placement request.
- [x] An IMAP, LMTP or ManageSieve backend pin never names the concrete POP3
      backend.
- [x] Existing IMAP active or retained affinity influences POP3 placement for
      the same account and backend node.
- [x] Existing ManageSieve active or retained affinity influences POP3
      placement for the same account and backend node.
- [x] Existing LMTP delivery-scoped active or retained affinity influences POP3
      placement for the same account and backend node.
- [x] Active or retained POP3 sessions influence later user-stateful placement
      for the same account and backend node.
- [x] Backend POP3 connect, TLS, CAPA discovery and configured backend auth are
      implemented.
- [x] POP3 backend session and health connects use `backend.ConnectRequest` and
      the shared outbound backend PROXY transport/reason classes.
- [x] Backend deep health proves connect, TLS, greeting, `CAPA`, configured
      backend auth, optional `NOOP` and `QUIT` without mailbox inspection or
      mutation commands.
- [x] Post-auth POP3 traffic is transparent and opaque to the director.
- [x] Message numbers, UIDLs, message sizes, message contents and post-auth
      command bodies are not logged, traced, metric-labeled, stored or used for
      routing.
- [x] Route lookup supports `protocol: pop3` without credential auth, Redis
      mutation, backend connect or mailbox inspection.
- [x] POP3 metrics use only approved low-cardinality labels.
- [x] `make e2e` proves POP3 through public sockets, the production binary and
      cross-protocol active-affinity invariants.
- [x] `make e2e-interop` proves real Dovecot POP3 access through the director
      on a Docker-capable environment while preserving existing IMAP, LMTP and
      ManageSieve lanes.
- [x] `contrib/demo-stack` carries M7 topology/config/proof updates and proves
      the final operator-facing POP3 path on a Docker/Compose-capable
      environment.
- [x] Config docs, generated references, OpenAPI artifacts and manpages are
      updated when behavior changes.
- [x] Final closeout adds `### Completion Evidence` to this specification and a
      matching `Status: completed` paragraph to `docs/ARCHITECTURE_ROADMAP.md`.
- [x] `make guardrails` is the final local gate before any commit or pull
      request that contains M7 implementation work.

### Completion Evidence

Closeout date: 2026-06-05.

Implemented POP3 surface: typed `pop3` STARTTLS and `pop3s` implicit TLS
listeners, TLS-gated `USER`/`PASS`, `AUTH XOAUTH2` and `AUTH OAUTHBEARER`
frontend auth through Nauthilus, provisional `USER` handling, shared placement
hold and backend-pin enforcement, backend-node affinity with IMAP, LMTP and
ManageSieve, runtime health/maintenance/out/max-connection selection, backend
POP3 connect/TLS/CAPA/auth and deep health checks, backend-side PROXY transport
reuse, transparent post-auth proxying, `protocol: pop3` route lookup and
secret-safe POP3 logs, metrics, traces, runtime reads and test observations.

Fake-service E2E proof:

- `make e2e` passed. Result:
  `ok e2e: fake Nauthilus HTTP/gRPC authority, real server binary, fake IMAP,
  LMTP, ManageSieve and POP3 backends, outbound backend PROXY, backend pinning,
  user placement holds, listener drain/resume, DATA/BDAT, TLS, route lookup and
  observability checks passed`.
- The POP3 fake lane covers public `pop3` STLS and `pop3s`, pre-TLS
  credential fail-closed behavior, `USER`/`PASS`, XOAUTH2 and OAUTHBEARER,
  hold wait/release/timeout, backend-pin match/mismatch/fail-closed behavior,
  runtime out and maintenance behavior, route lookup, IMAP/LMTP/ManageSieve to
  POP3 affinity, POP3 to IMAP/ManageSieve affinity and proxy handoff for
  `STAT`, `LIST`, `UIDL`, `RETR`, `DELE`, `RSET` and `QUIT`.

Real-server interoperability proof:

- `make e2e-interop` passed on a Docker-capable environment with
  `dovecot/dovecot:2.4.4`. Result:
  `ok e2e-interop: real server binary, six Dovecot IMAP backends, Dovecot LMTP
  backend, Dovecot ManageSieve and POP3 backends when available,
  swaks-to-Postfix submitter, curl IMAP delivery proof, health ownership,
  cluster affinity and runtime control passed`.
- The interop lane mapped a real Dovecot POP3 backend and proved successful
  POP3 auth plus `CAPA`, `USER`/`PASS`, `STAT`, `LIST`, `UIDL`, `RETR` and
  `QUIT` through the production director binary.
- Existing Dovecot IMAP, Postfix-to-Director-to-Dovecot LMTP and Dovecot
  ManageSieve interop lanes remained present and passed in the same
  `make e2e-interop` run.

Demo-stack proof:

- The demo stack now exposes public POP3 on host port `8110` and POP3S on
  `8995`, enables Dovecot POP3 with `protocols = imap pop3 submission lmtp
  sieve`, includes POP3 backend entries aligned by `backend_node`, includes
  `pop3` in the Nauthilus LDAP search protocol list and provides
  `contrib/demo-stack/scripts/prove-pop3.sh`.
- Rebuilt and recreated only `director-a` and `director-b`; Stalwart containers
  were not rebuilt. Restarted `nauthilus-a`, `nauthilus-b` and
  `nauthilus-haproxy` so the already-mounted `pop3` search-protocol config was
  loaded.
- `contrib/demo-stack/scripts/prove-pop3.sh` passed:
  `proof ok: POP3 STLS, POP3S auth, mailbox read and route lookup crossed
  public demo-stack sockets`.
- Compatibility proofs passed:
  `contrib/demo-stack/scripts/prove-affinity.sh`,
  `contrib/demo-stack/scripts/prove-managesieve.sh`,
  `contrib/demo-stack/scripts/prove-user-hold.sh`,
  `contrib/demo-stack/scripts/prove-user-backend-pin.sh`,
  `contrib/demo-stack/scripts/prove-backend-proxy.sh`,
  `contrib/demo-stack/scripts/send-mail.sh alice@example.test` and
  `contrib/demo-stack/scripts/fetch-mail.sh alice@example.test`.

Validation commands:

- `go test -mod=vendor ./internal/backend` passed.
- `make check-openapi` passed.
- `make check-docs` passed.
- `make test` passed.
- `make race` passed.
- `make e2e` passed.
- `make build-check` passed.
- `make e2e-interop` passed.
- `make guardrails` passed as the final local gate for this closeout.

## Required M7 Review Pass

Before closing M7, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `docs/ARCHITECTURE_ROADMAP.md`, especially sections 8, 9, 10, 11,
   12, 13, 17, 18, 20, 21, 22 and 23.
3. Re-read `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`.
4. Re-read `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`.
5. Re-read `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`.
6. Re-read `docs/specs/implementation/M5_BACKEND_PROXY_PROTOCOL_FOLLOWUP.md`.
7. Re-read `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`.
8. Re-read `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`.
9. Re-read `docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`.
10. Re-read `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`.
11. Re-read `docs/config/nauthilus-director.target.yml`.
12. Re-read `docs/reference/config-paths.md`.
13. Re-read `docs/specs/openapi/nauthilus-director.yaml` if route lookup,
    session listing or REST diagnostics changed.
14. Re-read `contrib/demo-stack` and `contrib/demo-stack/scripts` for required
    M7 topology, config, bootstrap and proof-script updates.
15. Re-read RFC 1939, RFC 2449, RFC 2595, RFC 5034 and RFC 7628 sections for
    authorization state, CAPA, STLS, AUTH and response framing.
16. Compare implementation and docs against this specification and the source
    documents.
17. Fix drift, false capability advertisement, IMAP-only selector assumptions,
    Sieve-only auth assumptions, LMTP-only delivery-hold assumptions,
    protocol-local copies of shared placement, outbound transport, runtime or
    route-lookup behavior, active-affinity misuse, unsafe mailbox logging,
    buffered proxy handoff mistakes and unsupported config documentation.
18. Run `make check-openapi` after any OpenAPI schema or generated-code change.
19. Run `make check-docs` after any typed config, config metadata or generated
    docs change.
20. Run targeted POP3, listener, config, routing, backend, state, runtime,
    observability and REST tests.
21. Run `make e2e` and record the POP3 proof, including IMAP, ManageSieve and
    LMTP active-affinity interaction.
22. Run `make e2e-interop` on a Docker-capable environment and record the real
    POP3 proof plus existing IMAP, LMTP and ManageSieve lane status.
23. Rebuild/update `contrib/demo-stack`, run its M7 proof on a
    Docker/Compose-capable environment and record the existing IMAP, LMTP and
    ManageSieve proof status.
24. Add the M7 `### Completion Evidence` section to this specification with
    concrete proof and validation results.
25. Update `docs/ARCHITECTURE_ROADMAP.md` with a concise M7
    `Status: completed` paragraph that points to this specification.
26. Run `make guardrails` before any commit or pull request.
27. Record `git status --short` and exact validation results in the M7
    closeout.

## Decisions and Open Questions

These decisions are recorded so M7 implementation does not rediscover them in
code.

1. Decision: the canonical protocol value is `pop3`.

   Listener names may be `pop3` and `pop3s`, but config, route lookup, runtime
   state, metrics and backend pools must not also introduce `pop` or `pop3s` as
   protocol values.

2. Decision: the director does not implement mailbox semantics.

   The director terminates only enough POP3 authorization-state protocol to
   authenticate and place the user. After successful backend auth, all
   transaction and update-state semantics are backend-owned.

3. Decision: `USER` is provisional until Nauthilus accepts authentication.

   A client-supplied `USER` value is protocol input, not authoritative identity.
   Holds, affinity, backend pins, Redis keys and route diagnostics use the
   canonical account facts returned by Nauthilus and the shared routing
   resolver.

4. Decision: credential-bearing POP3 commands require frontend TLS.

   `USER`/`PASS`, `AUTH XOAUTH2` and `AUTH OAUTHBEARER` must not call Nauthilus
   until implicit TLS or STLS is active. M7 does not add a plaintext
   compatibility flag.

5. Decision: POP3 login success is delayed until backend access is ready.

   A client-visible `+OK` after `PASS` or `AUTH` implies the backend maildrop is
   ready. M7 must not send it while an operator placement hold is active, while
   backend selection is unresolved or before backend auth/trust has succeeded.

6. Decision: POP3 consumes the shared placement service.

   POP3 sessions are user-stateful sessions like IMAP and ManageSieve. The
   protocol package calls `placement.SessionPlacer` and does not assemble Redis
   affinity, backend pins, backend selectors or capacity reservations itself.

7. Decision: backend pins are protocol/backend-pool scoped.

   A backend pin naming an IMAP, LMTP or ManageSieve backend is not a concrete
   POP3 target. Cross-protocol consistency comes from shared backend-node
   affinity. After the backend node is known, POP3 resolves a
   protocol-specific backend entry.

8. Decision: route lookup for POP3 is user-key diagnostic only.

   POP3 route lookup does not authenticate credentials and does not need
   LMTP-style recipient identity lookup. The caller supplies user identity
   facts or routing attributes, and the director runs the shared dry-run
   resolver and selector without side effects.

9. Decision: APOP is out of scope for M7.

   APOP depends on shared-secret digest behavior that does not fit the
   Nauthilus-backed auth authority boundary. Supporting it would require an
   explicit later security design and must not be added as a POP3 convenience
   path.

10. Decision: multi-step SASL is deferred until Nauthilus exposes a
    challenge/response contract.

    M7 supports only the architecture-required POP3 auth surface. SCRAM,
    GSSAPI, DIGEST-MD5 and similar mechanisms require Nauthilus-owned
    challenge/response state and a separate spec amendment before the director
    may advertise or accept them.

No open question blocks M7 implementation at specification time. If
implementation discovers a necessary POP3 behavior outside this document, add a
decision here before adding code.
