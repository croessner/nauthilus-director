# M5 LMTP Production Specification

Status: implementation-ready M5 specification. Recorded decisions and remaining
blocking open questions are listed at the end. The open questions must be
resolved before broad implementation starts.

This document defines the LMTP milestone for `nauthilus-director`. M5 delivers a
production-ready LMTP delivery-path protocol entrypoint within the explicit
scope below: LMTP and LMTPS listeners, peer authentication, recipient identity
resolution, active-affinity-safe routing, one selected backend per transaction,
backend LMTP connection/authentication, per-recipient status handling,
observability, deterministic E2E coverage and real-server interoperability
proof.

M5 builds on the completed M0 foundation, the completed M1 IMAP MVP, the
completed M2/M3 backend runtime and control implementation, and the completed M4
observability runtime. It is not a proof-of-concept migration and not a partial
or demo-only delivery. M5 is complete only when the LMTP behavior defined here
is production-ready inside its stated boundaries. The archived implementation
under `poc/` may be read only as historical source material, and production code
must not import it, preserve its package layout or use it as a compatibility
target.

## Source Documents

M5 is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
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

If this specification conflicts with those source documents, fix the drift
before implementation continues. In particular, do not silently change stable
config paths, REST behavior, runtime-control semantics, metric-label policy or
security defaults to make LMTP easier to implement.

## M5 Goal

M5 implements the first production LMTP director flow:

```text
submitting LMTP peer
  -> nauthilus-director LMTP or LMTPS listener
      -> optional PROXY protocol
      -> implicit TLS or STARTTLS
      -> optional peer authentication through Nauthilus or mTLS
      -> LMTP transaction state machine
      -> per-recipient routing fact resolution
      -> runtime-aware LMTP backend selection
      -> same-backend-only recipient set
      -> backend LMTP connect, TLS and backend auth
      -> DATA or BDAT forwarding to exactly one selected backend
      -> backend per-recipient final status relay
      -> secret-safe logs, metrics and traces
```

M5 must keep LMTP's delivery semantics distinct from IMAP login semantics. LMTP
does not authenticate mailbox users. The submitting peer may be authenticated,
but recipient routing remains a director-owned routing decision for each
envelope recipient after Nauthilus has resolved the recipient to the canonical
mailbox account. A running delivery still participates in active affinity with a
delivery-scoped hold so concurrent IMAP, ManageSieve or later POP3 sessions for
the same account route to the same backend shard while the delivery is in
progress.

The hard invariant is same-backend-only transaction handling. A single LMTP
transaction may contain multiple accepted recipients only when every accepted
recipient resolves to the same concrete backend target. Recipients that would
route elsewhere must be rejected or temporary-failed before `DATA` or `BDAT`.
The director must not spool one message body for replay to several backend
groups.

## Delivery Shape

Implement M5 as explicit implementation slices:

1. Config stabilization, validation and protocol listener dispatch.
2. Frontend LMTP parser, transaction state machine, TLS and peer auth.
3. Recipient identity, routing resolver integration and LMTP selector support.
4. Backend LMTP connector, backend auth and deep-health checks.
5. Transaction forwarding, DATA/BDAT handling and per-recipient status mapping.
6. Runtime state, maintenance, reload and route-lookup integration.
7. LMTP observability, documentation and generated reference updates.
8. Fake-service E2E, real Postfix/Dovecot interoperability and closeout review.

The slices may be committed separately, but M5 is not complete until the
production `nauthilus-director` binary starts LMTP/LMTPS listeners, handles real
wire transactions through public sockets, keeps recipient and message content out
of unsafe telemetry, proves deterministic edge cases in `make e2e`, proves
delivery-scoped affinity with concurrent user-stateful session placement, and
passes a real-server interoperability lane with a real submitting peer and real
LMTP backend.

## Global Scope

In scope:

- Start configured `lmtp` and `lmtps` listeners from the typed config snapshot.
- Generalize listener dispatch so IMAP and LMTP handlers are selected by
  protocol without duplicating transport lifecycle code.
- Support LMTP greeting, `LHLO`, `STARTTLS`, `AUTH`, `MAIL FROM`, `RCPT TO`,
  `DATA`, `BDAT`, `RSET`, `NOOP` and `QUIT` for the M5 transaction boundary.
- Support implicit TLS for LMTPS and STARTTLS for LMTP when configured.
- Support optional peer authentication through configured LMTP client auth and
  TLS client certificates.
- Treat peer authentication as submitter authentication only. It must not become
  mailbox-user authentication and must not provide concrete backend decisions.
- Resolve each envelope recipient through Nauthilus identity lookup and the
  shared routing model before accepting it into the transaction.
- Add LMTP-aware selector behavior for the existing `recipient_hash` pool
  selector and `lmtp` protocol, preserving runtime health, maintenance, drain,
  weight and max-connection semantics.
- Select and hold exactly one backend target for one transaction.
- Reject or temporary-fail additional recipients that would require a different
  backend target before `DATA` or `BDAT`.
- Connect to LMTP backends with configured plaintext, STARTTLS or implicit TLS
  modes without disabling certificate verification by default.
- Support backend auth modes currently represented by the typed config for LMTP:
  `none`, `mtls`, `sasl` and `oauthbearer`.
- Relay backend recipient acceptance and final per-recipient delivery status in
  a deterministic, secret-safe way.
- Keep message data opaque. Do not parse, inspect, log, metric-label or trace
  DATA or BDAT payload content.
- Integrate LMTP with backend runtime state, maintenance, health, active
  affinity and route lookup without exposing delivery holds as mailbox login
  sessions.
- Extend observability with LMTP transaction and recipient routing events using
  only the approved low-cardinality metric labels.
- Extend deterministic fake-service E2E to cover LMTP public sockets, routing,
  backend selection, DATA/BDAT forwarding, per-recipient status and secret
  safety.
- Extend real-server interoperability so Postfix acts as a real LMTP submitting
  peer and Dovecot acts as a real LMTP backend, while preserving the existing
  Dovecot IMAP lane.

Out of scope:

- Implementing a full SMTP server or queueing MTA.
- Spooling message bodies for retry, fan-out or cross-backend replay.
- Accepting a transaction that requires more than one backend target.
- Mailbox semantics, local delivery, Sieve execution, alias expansion or mailing
  list expansion.
- Treating Nauthilus as the backend selector.
- Calling Nauthilus credential-authentication during route lookup.
- Exposing LMTP delivery holds as user login sessions in the v1 session APIs.
- Logging raw recipients, message bodies, SASL blobs, passwords, bearer tokens,
  private keys or authorization headers.
- Adding recipient, user, session ID, request ID, trace ID, client IP, raw
  backend identifier or raw error text as Prometheus labels.
- POP3 or ManageSieve protocol entrypoints.
- Replacing deterministic fake-service E2E with Docker interoperability tests.

## Stable Config Paths

M5 stabilizes the currently typed and documented LMTP config paths. These paths
must not be renamed, removed or inverted without an explicit breaking-change
decision plus docs, examples, migration notes and tests:

- `director.listeners.lmtp`
- `director.listeners.lmtps`
- common listener fields under those listeners: `protocol`, `service_name`,
  `network`, `address`, `authority`, `backend_pool`, `proxy_protocol` and `tls`
- `director.listeners.lmtp.lmtp.smtputf8`
- `director.listeners.lmtp.lmtp.client_auth.required`
- `director.listeners.lmtp.lmtp.client_auth.authority`
- `director.listeners.lmtp.lmtp.client_auth.mechanisms`
- `director.listeners.lmtp.lmtp.capabilities`
- matching `director.listeners.lmtps.lmtp.*` paths
- `director.routing.lmtp_hash_key`
- `director.backend_pools.lmtp-default`
- `director.backend_pools.lmtp-default.protocol`
- `director.backend_pools.lmtp-default.selector`
- `director.backend_pools.lmtp-default.backends`
- LMTP backend entries under `director.backends.*` where `protocol: lmtp`
- LMTP backend TLS paths: `tls.mode`, `tls.ca_file`, `tls.cert`, `tls.key`,
  `tls.server_name`, `tls.min_tls_version` and `tls.insecure_skip_verify`
- LMTP backend auth paths: `auth.mode`, `auth.sasl.*` and
  `auth.oauthbearer.*`
- LMTP backend health, maintenance, weight, max-connection and HAProxy paths

M5 may validate existing values more strictly when the stricter behavior follows
the architecture and prevents false capability advertisement. LMTP capabilities
remain configurable like IMAP capabilities, but the runtime advertisement is not
blind config echo. The effective capability set is the intersection of
configured capabilities, implemented protocol behavior, transport state and
backend-pool capability policy. If an operator configures `CHUNKING`, M5 must
implement and test `BDAT`/CHUNKING end to end. It must not advertise `CHUNKING`
while accepting only `DATA` or while the selected backend path cannot safely
forward `BDAT`.

Capability omission is also a protocol boundary. If an operator removes
`STARTTLS`, `AUTH`, `SMTPUTF8` or `CHUNKING` from the effective frontend
surface, the session must not accept the associated command, mechanism,
parameter or SMTPUTF8-only envelope syntax merely because the lower-level
transport or parser could handle it.

M5 must keep redaction metadata intact for listener TLS keys, backend TLS keys,
backend SASL password files, backend OAuth bearer token files and all other
protected paths.

## Target Package Boundaries

M5 expands existing production packages and adds a new protocol package:

```text
internal/protocol/lmtp/
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
test/e2e/fakes/lmtp_backend/
test/e2e/interop/
docs/
```

Boundary rules:

- `internal/protocol/lmtp` owns LMTP command parsing, transaction state, peer auth
  orchestration, recipient acceptance, backend LMTP conversation and LMTP-specific
  status mapping.
- `internal/listener` owns listener lifecycle, transport preparation, PROXY
  protocol and frontend TLS wrapping. It must not contain LMTP command logic.
- `internal/app` owns Fx wiring, dependency construction and protocol handler
  dispatch. It must not become a protocol state machine.
- `internal/config` owns typed LMTP config validation, defaults, redaction and
  generated docs inputs. It must not read raw Viper values from protocol code.
- `internal/nauthilus` remains the authority transport boundary for peer auth and
  any later identity lookup. It must not select director backends.
- `internal/routing` owns logical recipient-to-shard facts only. It must not open
  Redis sessions, select backends or log raw recipients.
- `internal/backend` owns LMTP-capable registry and selector behavior, effective
  backend state, health policy and backend runtime constraints.
- `internal/state` owns Redis-backed runtime coordination needed for backend
  active counts, delivery-scoped affinity holds and control actions. LMTP
  delivery holds use the active-affinity key model without being exposed as
  mailbox login sessions.
- `internal/runtime` exposes side-effect-free diagnostics and operator-visible
  runtime state without inventing a second LMTP routing model.
- `internal/proxy` may provide generic stream helpers, but LMTP DATA and BDAT
  forwarding remain controlled by the LMTP transaction state machine because
  per-recipient final status must be read after the message-completion boundary.
- `internal/observability` owns metric instruments, logs, spans and redaction
  policy. Protocol packages record normalized events only.
- `internal/rest` and `internal/rest/adapters` stay generated-contract oriented.
  If M5 changes route-lookup DTOs for LMTP recipient diagnostics, update OpenAPI
  first and regenerate the boundary.

Do not add package-level mutable global state. Use cohesive types and narrow
interfaces so unit tests can exercise parser, recipient routing, backend
conversation and status mapping independently.

## M5.1 Config, Validation and Protocol Listener Dispatch

### Purpose

Turn the existing typed LMTP config surface into real supported behavior and
make listener startup dispatch protocol handlers by configured protocol.

### In Scope

- Start `director.listeners.*` entries whose protocol is `lmtp`.
- Preserve IMAP listener behavior while adding LMTP dispatch.
- Reject unknown protocol values unless a later protocol milestone implements
  them.
- Validate LMTP listener-specific config:
  - `listener.lmtp` is required for `protocol: lmtp`.
  - `client_auth.authority` must reference a configured authority when client
    auth is required.
  - `client_auth.mechanisms` must contain only implemented mechanisms.
  - listener TLS `require_client_cert` may satisfy required peer auth only when
    TLS verifies the client certificate and the implementation can derive a
    secret-safe submitter identity from the certificate.
  - configured capabilities must contain only implemented LMTP capabilities.
  - `STARTTLS` is advertised only when listener TLS mode is `starttls`.
  - implicit TLS listeners must not advertise `STARTTLS`.
  - backend-dependent capabilities such as `CHUNKING` must be mediated by the
    backend-pool capability policy before advertisement.
  - unsupported capabilities must fail validation instead of being advertised.
- Validate LMTP backend config:
  - LMTP pools reference only LMTP backends.
  - `recipient_hash` is accepted for LMTP pools only when selector support lands.
  - backend auth modes are valid for LMTP.
  - SASL/OAuth backend auth requiring TLS must fail if backend TLS cannot be
    verified.
  - backend TLS with IP addresses still requires explicit `tls.server_name` for
    hostname verification.
- Update generated config references when defaults or metadata change.

### Out of Scope

- Adding ManageSieve or POP3 listener support.
- Making unsupported protocol values silently skip.
- Adding feature-specific Redis config subtrees for LMTP.
- Rewriting YAML config through REST or CLI.

### Expected Files or Packages

```text
internal/config/
internal/listener/
internal/app/
docs/config/metadata.yml
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
```

### Implementation Notes

- The current listener manager is IMAP-oriented. M5 should generalize names,
  comments and protocol dispatch without breaking the existing IMAP API surface.
- Use a small protocol-handler factory interface instead of branching deep inside
  the accept loop.
- Keep shared listener transport setup in `internal/listener`; do not duplicate
  TCP, PROXY protocol or frontend TLS handling in `internal/protocol/lmtp`.
- Keep LMTP defaults conservative. Configured capabilities describe the
  operator-intended surface; the protocol session computes the effective
  advertised set from implemented command support, listener transport state and
  backend-pool capability state. The director must not advertise a capability
  until the state machine, backend forwarding and E2E lane prove the command.
- Treat missing effective capabilities as deny rules. `STARTTLS`, `AUTH`
  mechanisms, `BDAT` and SMTPUTF8 envelope forms must be rejected when their
  corresponding capability was not advertised for the current session.

### Required Unit Tests

- LMTP and LMTPS listeners are included in listener snapshots and startup plans.
- IMAP listeners still start after protocol dispatch generalization.
- Missing `listener.lmtp` fails validation for LMTP listeners.
- Unsupported LMTP capabilities fail validation.
- Configured LMTP capabilities are normalized into stable wire forms.
- `STARTTLS` capability validation matches listener TLS mode.
- mTLS-as-peer-auth validation rejects listeners without required verified
  client certificates.
- mTLS identity-source validation rejects unsupported certificate fields.
- `CHUNKING` is accepted only when the M5 `BDAT` implementation is enabled and
  covered by backend-capability mediation.
- LMTP backend auth mode validation rejects incomplete SASL and OAuth config.
- Config dumps redact LMTP listener/backend protected values by default.

### Required Integration or E2E Tests

- The production server binary starts one IMAP listener and one LMTP listener
  from the same config snapshot.
- A config with invalid LMTP capability advertisement fails before sockets bind.
- LMTP `LHLO` advertises only effective capabilities, not every configured
  string blindly.
- Generated config docs remain fresh after any default or metadata change.

### Acceptance Criteria

- LMTP listener paths are real supported config, not draft-only placeholders.
- Unsupported protocol config fails closed before listener startup.
- Existing IMAP startup behavior remains covered.
- `make check-docs` passes after any config reference change.

### Review Checklist

- Verify the listener manager no longer has IMAP-only naming where behavior is
  now protocol-generic.
- Verify LMTP defaults do not advertise commands the implementation rejects.
- Verify no protected LMTP config value appears in dumps without `-P`.

## M5.2 Frontend LMTP State Machine, TLS and Peer Auth

### Purpose

Implement the LMTP frontend state machine needed to authenticate a submitting
peer, accept a safe transaction and route recipients before DATA or BDAT.

### In Scope

Supported frontend commands:

```text
LHLO
STARTTLS
AUTH PLAIN
AUTH LOGIN
AUTH XOAUTH2
AUTH OAUTHBEARER
MAIL FROM
RCPT TO
DATA
BDAT
RSET
NOOP
QUIT
```

M5 state rules:

- Send a valid `220` LMTP greeting after transport setup.
- Require `LHLO` before transaction commands.
- Advertise only configured and implemented capabilities.
- Reject extension use that was not advertised in the current `LHLO` response;
  capability omission disables the feature instead of merely hiding text.
- Advertise `CHUNKING` only when it is configured, implemented, tested and
  allowed by the backend-pool capability policy.
- Accept `STARTTLS` and `AUTH` only when those capabilities are effective for
  the current session.
- Accept the `SMTPUTF8` `MAIL FROM` parameter and non-ASCII envelope paths only
  when `SMTPUTF8` is advertised and the current transaction opted in through
  `MAIL FROM ... SMTPUTF8`.
- Require STARTTLS before SASL AUTH unless the listener is already implicit TLS.
- Reset capability and transaction state after STARTTLS.
- When LMTP client auth is required, reject `MAIL FROM`, `RCPT TO`, `DATA` and
  `BDAT` until peer auth succeeds.
- SASL peer auth verifies the submitting technical LMTP peer account, such as a
  Postfix service account, not a recipient mailbox user account.
- The director parses SASL envelopes only far enough to extract the submitter
  identity, mechanism and secret material, then delegates credential verification
  to the configured Nauthilus authority through the normal authentication path.
- The HTTP/JSON Nauthilus transport must not use `mode=no-auth` for SASL peer
  auth; `mode=no-auth` is only for recipient identity lookup.
- Treat TLS client certificates as peer authentication only when
  listener TLS explicitly requires and verifies client certificates and a
  secret-safe certificate submitter identity can be derived.
- When mTLS does not explicitly satisfy peer auth, verified client certificates
  remain transport hardening and SASL peer auth through Nauthilus is still
  required.
- Support one active transaction at a time per connection.
- Accept `RSET` to clear the active transaction and backend transaction state.
- Accept `NOOP` without mutating recipient state.
- Close cleanly on `QUIT`.
- Enforce configured line limits and pre-auth timeouts.
- Accept `BDAT` only after at least one recipient is accepted and only when
  `CHUNKING` was advertised for the current session.
- Stream `BDAT` chunks to a backend `BDAT` path without buffering the full
  message body.
- Treat `BDAT LAST` as the message completion boundary and map final backend
  replies exactly like DATA completion.

### Out of Scope

- Full SMTP server behavior.
- `VRFY`, `EXPN`, `HELP`, `ETRN`, `XCLIENT`, `XFORWARD` or vendor extensions.
- Queueing, retry scheduling, local delivery or post-accept message storage.
- PIPELINING-specific out-of-order state beyond safe command sequencing.
- `BINARYMIME`, `8BITMIME` or other message-body extensions unless their
  complete semantics are explicitly implemented and tested.
- Translating frontend `BDAT` to backend `DATA` in M5. That path requires
  separate dot-stuffing, line-boundary and binary-safety decisions.

### Expected Files or Packages

```text
internal/protocol/lmtp/
internal/protocol/lmtp/session.go
internal/protocol/lmtp/parser.go
internal/protocol/lmtp/commands.go
internal/protocol/lmtp/auth.go
internal/protocol/lmtp/responses.go
internal/protocol/lmtp/starttls.go
```

### Implementation Notes

- Keep the parser line-oriented and bounded. LMTP command parsing is not allowed
  to read an unbounded body into memory.
- DATA forwarding must use streaming and dot-termination handling. Message
  content must remain opaque.
- `BDAT` forwarding must use exact byte-counted chunk streaming and must never
  reinterpret message content for routing, logging or policy.
- Do not synthesize `CHUNKING` from config alone. The effective advertisement is
  config plus implemented command support plus current listener and backend-pool
  capability policy.
- Reuse shared concepts from IMAP only where the package boundary remains clean.
  If SASL parsing becomes shared, move it into a narrow protocol-independent
  package instead of importing IMAP internals from LMTP.
- Return protocol status codes with stable reason classes internally. Do not use
  raw backend error text in metrics or externally vague diagnostics in logs.
- For SASL peer auth, populate Nauthilus auth context with `protocol=lmtp`,
  normalized mechanism, submitter identity from the SASL exchange and secret
  material wrapped as redacted credential input. Do not use any envelope
  recipient or resolved account as the auth username.
- mTLS peer-auth identity is a submitter identity only. It must not become a
  mailbox account key, recipient-routing key or backend-selection fact.
- Backend LMTP authentication is a separate hop: backend SASL/OAuth/mTLS
  credentials are director-to-backend service credentials and must not reuse the
  frontend peer credentials.
- mTLS peer-auth audit events should record method `mtls`, identity source and a
  bounded safe identity value or hash. They must not log raw certificates,
  private keys or full distinguished-name blobs.

### Required Unit Tests

- Greeting and `LHLO` capability responses are deterministic.
- `STARTTLS` is accepted only before peer auth and transaction state.
- Omitted `STARTTLS`, `AUTH` and `SMTPUTF8` capabilities disable the related
  commands, mechanisms, parameters and SMTPUTF8-only envelope syntax.
- Commands before `LHLO` fail with correct bad-sequence status.
- Required peer auth blocks transaction commands.
- Required peer auth remains blocked by a verified client certificate when
  listener TLS does not explicitly require verified client certificates.
- Verified client certificate satisfies required peer auth only when listener
  TLS requires verification and a safe submitter identity is available.
- Missing, untrusted or identity-less client certificates fail closed when mTLS
  is the selected peer-auth path.
- SASL peer auth calls Nauthilus authentication with the submitter technical
  account identity and never with recipient or resolved mailbox account values.
- HTTP/JSON SASL peer auth uses the credential-auth path without `mode=no-auth`;
  HTTP/JSON recipient lookup uses `mode=no-auth`.
- Backend auth tests prove frontend peer credentials are not replayed to LMTP
  backends.
- AUTH mechanisms parse valid input and reject malformed or oversized SASL
  blobs without logging raw material.
- `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP` and `QUIT` update transaction
  state correctly.
- `BDAT` rejects malformed chunk sizes, missing recipients and use in sessions
  where `CHUNKING` was not advertised.
- `BDAT` streams exact chunk sizes, honors `LAST`, and does not buffer the full
  message body.
- DATA terminator handling does not buffer whole messages unnecessarily.

### Required Integration or E2E Tests

- Public LMTP socket supports `LHLO`, `STARTTLS`, peer AUTH and `QUIT`.
- Public LMTPS socket starts with implicit TLS and does not advertise STARTTLS.
- Public LMTP or LMTPS socket with explicit mTLS peer-auth policy accepts
  transaction commands after verified client-certificate auth without SASL.
- Public LMTP or LMTPS socket without explicit mTLS peer-auth policy still
  requires SASL when `client_auth.required` is true.
- Public LMTP SASL auth succeeds only when fake Nauthilus accepts the technical
  submitter account and fails when the fake rejects that account.
- Public LMTP flow proves submitter peer auth and recipient identity lookup are
  separate Nauthilus operations with different inputs.
- Public LMTP socket advertises `CHUNKING` only when the configured and backend-
  mediated state allows the `BDAT` path.
- Public LMTP socket supports a successful multi-chunk `BDAT ... LAST` delivery
  when `CHUNKING` is advertised.
- Bad command order returns stable status codes.
- Secret-safety assertions cover peer passwords, bearer tokens and SASL blobs.

### Acceptance Criteria

- The frontend LMTP state machine is deterministic, bounded and protocol-safe.
- Peer auth is required or optional exactly as configured.
- mTLS can satisfy required peer auth only through explicit listener TLS policy.
- TLS and AUTH capability advertisement matches actual behavior.
- `CHUNKING` capability advertisement matches actual `BDAT` behavior.

### Review Checklist

- Verify no raw SASL blob or bearer token is logged in parser/auth failures.
- Verify no raw certificate, private key or unsafe distinguished-name value is
  logged in mTLS peer-auth paths.
- Verify STARTTLS resets all pre-TLS state that must not survive TLS upgrade.
- Verify DATA handling cannot be used as an unbounded memory sink.
- Verify `BDAT` handling cannot be used as an unbounded memory sink.

## M5.3 Recipient Identity, Routing and Selector Support

### Purpose

Resolve each envelope recipient to a canonical mailbox account, derive
director-owned routing facts and select an LMTP backend through the same
runtime-aware selector model used by route lookup and IMAP placement. A running
delivery must hold active affinity for the resolved account so parallel
user-stateful protocol sessions route to the same backend shard.

### In Scope

- Parse and normalize envelope recipients into a lookup value and a wire value.
- Preserve the wire recipient for backend commands without exposing it in unsafe
  logs, traces or metrics.
- Use the Nauthilus identity lookup as the default authoritative recipient
  resolution path before accepting `RCPT TO`: gRPC uses `LookupIdentity`;
  HTTP/JSON uses the corresponding authentication endpoint with `mode=no-auth`.
- Map the Nauthilus lookup result into the same canonical account, tenant and
  routing-attribute shape used by IMAP placement.
- Use the resolved tenant and normalized account as the active affinity key.
- Use `director.routing.lmtp_hash_key` only for explicit fallback or test modes
  where operator configuration accepts that recipient hashing is not
  directory-authoritative.
- Build LMTP routing requests with:
  - `Protocol: lmtp`
  - listener name
  - service name
  - backend pool
  - peer context where safe
  - normalized account from recipient lookup
  - safe routing attributes when available
- Extend routing and selection so `protocol: lmtp` is accepted.
- Implement or adapt selector behavior for `recipient_hash`.
- Preserve runtime health, maintenance, runtime out, drain, weight and
  max-connection constraints during LMTP placement.
- If an active affinity already exists for the resolved account, LMTP must use
  that shard before normal initial placement.
- If no active affinity exists, LMTP must select an initial shard/backend and
  open a delivery-scoped affinity hold before accepting the recipient.
- Delivery-scoped holds must be heartbeated while the transaction is active and
  closed after DATA final status, `BDAT ... LAST` final status, `RSET`, `QUIT`,
  connection close or error.
- New IMAP sessions for the same account must observe LMTP delivery holds as
  active affinity and route to the same shard.
- The first accepted recipient establishes the transaction backend target.
- Additional recipients are accepted only when the same resolver and selector
  pipeline selects the same concrete backend target.
- Recipients that route to another backend target are rejected or temporary-
  failed before `DATA` or `BDAT`.
- Route lookup diagnostics must work for LMTP without runtime mutation. Recipient
  diagnostics may use the Nauthilus identity lookup path to resolve aliases to
  canonical accounts before dry-run placement.

### Out of Scope

- Letting Nauthilus return concrete backend identifiers.
- Recipient alias expansion.
- Cross-backend message fan-out.
- Treating recipient hashing as the default production authority for alias or
  mailbox identity.
- Exposing delivery-scoped affinity holds as user login sessions.
- Adding raw recipients as metric labels, trace attributes or log fields.

### Expected Files or Packages

```text
internal/protocol/lmtp/recipient.go
internal/routing/
internal/backend/
internal/runtime/route_lookup.go
internal/rest/adapters/
docs/specs/openapi/nauthilus-director.yaml
```

### Implementation Notes

- The current runtime selector rejects non-IMAP protocols and unsupported
  selectors. M5 must remove that IMAP-only restriction and add explicit LMTP
  selector support without weakening IMAP validation.
- `recipient_hash` may use the same weighted rendezvous scoring primitive as the
  current selector, but after Nauthilus lookup the effective input key must be
  the resolved account/affinity key, not the raw recipient address.
- The HTTP/JSON Nauthilus transport must append `mode=no-auth` for recipient
  identity lookup so the request resolves identity without performing mailbox
  credential authentication. The gRPC transport must use `LookupIdentity`.
- Route lookup should expose operator-facing LMTP recipient input in OpenAPI,
  generated clients and CLI. Recipient lookup uses the same conservative
  normalization as delivery, then the Nauthilus identity lookup path unless the
  caller supplied already-resolved account, tenant and routing facts.
- Recipient normalization must be conservative. Strip LMTP path syntax and
  surrounding whitespace for lookup, lowercase only the ASCII domain part, keep
  the local part unchanged, and perform no Unicode normalization or IDNA
  conversion in M5. Use the lookup form only for Nauthilus identity lookup and
  local fallback/test routing; send the original envelope form to the backend
  unless a later explicit policy says otherwise.

### Required Unit Tests

- LMTP recipient parsing accepts valid path forms and rejects malformed input.
- Recipient normalization is deterministic, preserves the local part, lowercases
  only ASCII domain characters, avoids Unicode/IDNA conversion and does not leak
  raw values in error strings.
- Backend `RCPT TO` uses the original envelope recipient form, not the lookup
  normalization form.
- Nauthilus identity lookup is called before recipient acceptance and maps
  recipient input to normalized account, tenant and routing attributes.
- HTTP/JSON recipient lookup appends `mode=no-auth`; gRPC recipient lookup uses
  `LookupIdentity`.
- Routing requests for LMTP carry protocol, listener, service, pool and resolved
  account key correctly.
- `recipient_hash` produces stable backend selection for identical inputs.
- LMTP selector support preserves health, maintenance, runtime out, drain, weight
  and max-connection behavior.
- Delivery-scoped affinity holds are opened, heartbeated, closed and reaped by
  account key.
- Concurrent IMAP placement observes an active LMTP delivery hold for the same
  account.
- Different-backend recipients are detected before DATA or `BDAT`.
- Route lookup for `protocol=lmtp` remains side-effect-free: it may call
  Nauthilus identity lookup for recipient resolution, but it must not
  authenticate credentials, create delivery holds, refresh leases or mutate
  Redis.

### Required Integration or E2E Tests

- Two recipients that resolve to the same backend are accepted in one
  transaction.
- A second recipient that resolves to a different backend is rejected or
  temporary-failed before DATA or `BDAT`.
- Runtime maintenance or runtime out excludes LMTP backends from new recipient
  placement.
- A new IMAP connection during an accepted LMTP transaction routes to the same
  shard as the delivery hold.
- Route lookup explains an LMTP placement through the hybrid identity path and
  without Redis mutations.

### Acceptance Criteria

- LMTP placement uses the shared resolver and runtime selector domain.
- LMTP delivery holds protect backend shard consistency for concurrent
  user-stateful protocol sessions.
- The same-backend-only invariant is externally observable.
- Route lookup remains side-effect-free for LMTP and reports whether identity
  facts were caller-supplied, read from existing director state or resolved
  through Nauthilus.

### Review Checklist

- Verify selector behavior is protocol-aware without duplicating business rules.
- Verify LMTP opens only delivery-scoped affinity holds and never exposes them as
  mailbox login sessions.
- Verify raw recipients are not used as observability labels or unsafe fields.

## M5.4 Backend LMTP Connector, Auth and Health

### Purpose

Connect to selected LMTP backends using configured transport security and backend
authentication, then make backend health checks protocol-aware.

### In Scope

- Implement LMTP backend connect over TCP.
- Support backend TLS modes:
  - `plaintext` or `disabled`
  - `starttls`
  - `implicit`
- Preserve certificate verification by default.
- Require explicit `tls.server_name` when the TCP address is not the certificate
  hostname.
- Query backend LMTP capabilities with `LHLO`.
- Publish backend `LHLO` capabilities into the backend-pool capability policy
  used for safe frontend advertisement.
- Support backend auth modes:
  - `none`
  - `mtls`
  - `sasl`
  - `oauthbearer`
- Expand backend domain config adapters so LMTP SASL and OAuth bearer fields are
  available to the protocol package.
- Enforce `auth.sasl.require_tls` and `auth.oauthbearer.require_tls`.
- Authenticate to the backend before forwarding envelope commands when backend
  auth is configured.
- Implement LMTP deep health as connect, TLS, greeting, `LHLO`, configured
  backend auth, optional `NOOP`/`RSET` and `QUIT`.
- Keep existing Redis-coordinated health ownership.

### Out of Scope

- Reusing IMAP CAPABILITY/AUTH command code as a protocol substitute.
- Performing health `MAIL FROM`, `RCPT TO`, `DATA` or `BDAT` probes.
- Sending frontend peer credentials to the backend.
- Disabling TLS verification to make test environments pass.

### Expected Files or Packages

```text
internal/protocol/lmtp/backend.go
internal/protocol/lmtp/backend_auth.go
internal/backend/
internal/app/
internal/config/
```

### Implementation Notes

- LMTP backends return SMTP-style status lines, not IMAP tagged completions.
  Implement a dedicated response reader.
- Backend auth credentials are service credentials configured under the backend,
  not mailbox-user credentials and not frontend peer credentials.
- `CHUNKING` is backend-dependent. If the selected backend path does not support
  `CHUNKING`, M5 must not advertise frontend `CHUNKING` for sessions that can
  route there. M5 does not translate frontend `BDAT` to backend `DATA`.
- For `mtls`, TLS client certificate configuration and successful verified TLS
  are the auth proof. Do not send SASL commands in `mtls` mode.
- LMTP deep health must stop before envelope commands. It may authenticate to
  the backend with configured backend service credentials, then issue only
  `NOOP`, `RSET` and `QUIT` as configured.
- Health checks must publish bounded reason classes such as `connect`, `tls`,
  `protocol`, `auth` and `timeout`.

### Required Unit Tests

- Backend connector handles plaintext, STARTTLS and implicit TLS modes.
- TLS verification uses configured server name and rejects missing verification
  prerequisites.
- Backend `LHLO` capabilities are parsed without treating message text as logic.
- Backend capability state drives frontend `CHUNKING` advertisement conservatively
  and fail-closed when capability data is missing, stale or mixed.
- SASL backend auth requires configured credentials and verified TLS when
  configured.
- OAuth bearer backend auth requires token file material and verified TLS when
  configured.
- Deep health executes connect, TLS, greeting, `LHLO`, configured backend auth,
  optional `NOOP`/`RSET` and `QUIT` in order.
- Deep health never sends `MAIL FROM`, `RCPT TO`, `DATA` or `BDAT`.
- Health check reason classes are bounded and secret-safe.

### Required Integration or E2E Tests

- Fake LMTP backend observes backend `LHLO`, optional STARTTLS and backend auth.
- Fake LMTP backend capability variants prove `CHUNKING` is advertised only when
  all eligible backend paths for the listener can accept `BDAT`.
- Backend auth failures cause frontend temporary failure without leaking backend
  credentials.
- Health runner marks LMTP backends healthy/unhealthy through the shared Redis
  health ownership path.
- Fake backend observations prove health checks stop before envelope and message
  commands.

### Acceptance Criteria

- Backend LMTP connection/auth behavior is protocol-correct and secret-safe.
- Backend capability mediation prevents frontend `CHUNKING` advertisement from
  exceeding the selected backend path's `BDAT` support.
- LMTP health checks reuse runtime health coordination rather than a local-only
  shortcut.
- LMTP backend auth config is actually consumed by the protocol path.
- LMTP deep health proves protocol readiness without creating deliveries or
  touching recipient-specific backend state.

### Review Checklist

- Verify no IMAP protocol assumptions remain in LMTP backend code.
- Verify frontend capability decisions are not made from listener config alone.
- Verify backend auth material is cleared or kept short-lived where practical.
- Verify health checks do not deliver test messages.
- Verify health checks do not issue `MAIL FROM`, `RCPT TO`, `DATA` or `BDAT`.

## M5.5 Transaction Forwarding, DATA and Per-Recipient Status

### Purpose

Forward one accepted LMTP transaction to exactly one selected backend and relay
per-recipient status back to the submitting peer.

### In Scope

- After the first accepted recipient selects a backend, establish backend state
  for the transaction.
- Forward `MAIL FROM` and accepted `RCPT TO` commands to the selected backend.
- Accept a frontend recipient only after the director has routed it and the
  backend has accepted the corresponding `RCPT TO`, or after a documented safe
  temporary-failure mapping when the backend is unavailable.
- Preserve the order of accepted recipients for DATA and `BDAT ... LAST` final
  replies.
- Forward DATA streaming or `BDAT` chunk streaming to the backend without
  storing the full message.
- Relay backend final status lines one-for-one for accepted recipients.
- Preserve known per-recipient backend outcomes. A same-backend transaction may
  complete with mixed recipient results, such as `250` for one accepted
  recipient and `4xx` or `5xx` for another.
- If backend DATA or `BDAT` forwarding fails before final replies, temporary-
  fail every accepted recipient whose final status is unknown.
- Clear transaction state after DATA completion, `BDAT ... LAST`, RSET or
  connection close.
- Close backend connections deterministically on protocol failure or shutdown.

### Out of Scope

- Message body inspection.
- Message body logging.
- Cross-backend fan-out.
- Spooling and replay.
- Partial replay after backend failure.
- Accepting recipients that the backend rejected before DATA or `BDAT`.

### Expected Files or Packages

```text
internal/protocol/lmtp/transaction.go
internal/protocol/lmtp/data.go
internal/protocol/lmtp/status.go
internal/protocol/lmtp/backend.go
```

### Implementation Notes

- Same-transaction different-backend recipients must receive a stable 4xx
  temporary failure with a stable enhanced status code and reason class so a
  submitting MTA can retry them in a separate transaction. M5 must not use a
  permanent 5xx for this case.
- The final status mapping must distinguish:
  - recipient accepted before DATA
  - recipient rejected before DATA
  - backend temporary failure
  - backend permanent rejection
  - unknown after stream failure
- Known backend recipient failures must keep their status class and enhanced
  status code where safe. The director must not convert a known backend `5xx`
  permanent recipient result into `4xx`, and must not convert a known `250`
  success into failure just because another same-backend recipient failed.
- Frontend replies should be useful but must not expose raw backend error text
  when it may contain recipient or policy details.
- DATA streaming must handle dot-stuffing and the terminating `.<CRLF>` without
  loading the entire message into memory.
- `BDAT` streaming must handle exact byte counts, multiple chunks and `LAST`
  without loading the entire message into memory.
- `BDAT` forwarding is backend `BDAT` forwarding in M5. Do not translate to
  backend DATA unless a later explicit decision covers dot-stuffing,
  line-boundary and binary-safety semantics.

### Required Unit Tests

- First recipient establishes transaction target.
- Same-target recipient is accepted and forwarded.
- Different-target recipient is rejected or temporary-failed before DATA or
  `BDAT`.
- Different-target recipient returns the configured M5 4xx temporary failure,
  stable enhanced status code and stable reason class.
- Backend RCPT rejection is not included in DATA final status tracking.
- DATA final replies match accepted recipient order.
- `BDAT ... LAST` final replies match accepted recipient order.
- Mixed backend final statuses are relayed per recipient: known `250`, known
  `4xx` and known `5xx` outcomes remain per-recipient outcomes.
- Mid-DATA backend failure maps unknown final recipients to temporary failure.
- Mid-BDAT backend failure maps unknown final recipients to temporary failure.
- RSET clears frontend and backend transaction state.
- Message body content never appears in logs or errors.

### Required Integration or E2E Tests

- Fake backend receives one DATA stream for same-backend multi-recipient
  transactions.
- Fake backend receives ordered `BDAT` chunks for same-backend multi-recipient
  transactions when `CHUNKING` is advertised.
- Different-backend recipient is not forwarded to a second backend in the same
  transaction.
- Different-backend recipient returns the stable 4xx temporary failure before
  DATA or `BDAT`.
- Backend per-recipient success and failure statuses are relayed externally.
- Same-backend multi-recipient delivery can partially succeed when the backend
  returns mixed final recipient statuses.
- Large message body is streamed within configured limits.
- Large `BDAT` payload is streamed within configured limits and exact chunk
  boundaries are honored.

### Acceptance Criteria

- The same-backend-only transaction rule is enforced before DATA or `BDAT`.
- Accepted recipients receive deterministic per-recipient final status.
- The director never spools or replays message bodies across backend groups.
- The director never turns known per-recipient backend outcomes into
  all-or-nothing transaction results.
- `CHUNKING` is production-ready when advertised: frontend `BDAT`, backend
  `BDAT`, status mapping, limits, failures and interop are covered.

### Review Checklist

- Verify unknown delivery outcomes are temporary failures, not silent success.
- Verify known per-recipient backend success and failure outcomes are preserved
  without retrying or rolling back successful recipients.
- Verify backend final replies cannot desynchronize the frontend recipient list.
- Verify message content remains opaque to observability.

## M5.6 Runtime State, Maintenance, Reload and Route Lookup

### Purpose

Integrate LMTP with backend runtime state and operator diagnostics without
treating delivery transactions as active mailbox login sessions.

### In Scope

- Backend selection for LMTP must consume runtime health, maintenance, runtime
  out, drain, weight and max-connection state.
- LMTP transactions must account for backend active usage while a backend
  transaction is open.
- Accounting must be Redis-backed or otherwise consistent with the existing
  cross-process runtime model when it affects placement decisions.
- LMTP must open delivery-scoped active-affinity holds for every accepted
  recipient account while delivery state can affect backend indexes.
- LMTP delivery holds must use the same tenant plus normalized account affinity
  key that IMAP uses after Nauthilus authentication.
- LMTP delivery holds must influence new IMAP, later ManageSieve and later POP3
  placement exactly like active user-stateful sessions influence placement:
  same account, same active shard.
- LMTP delivery holds must not be exposed as mailbox login sessions in the v1
  session APIs.
- Soft maintenance excludes LMTP backends from new initial recipient placement.
- Hard maintenance and runtime out exclude LMTP backends from new recipient
  placement.
- Existing accepted DATA or BDAT transactions may complete during soft
  maintenance and graceful drain unless a hard operation explicitly closes local
  handles after grace.
- Safe reload must add and remove LMTP listeners and backends according to the
  existing reload semantics.
- Route lookup must support LMTP diagnostic placement without session creation,
  delivery-hold creation, lease refresh or Redis mutation. It may call the
  Nauthilus identity lookup path for recipient diagnostics when the caller has
  not supplied already-resolved account, tenant and routing facts.

### Out of Scope

- Listing individual LMTP recipients or message transactions through the v1 REST
  session APIs unless a later explicit API decision adds delivery diagnostics.
- Runtime YAML rewrites.
- Distributed locks in the normal LMTP routing path.

### Expected Files or Packages

```text
internal/state/
internal/runtime/
internal/backend/
internal/app/
internal/rest/adapters/
internal/client/generated/
cmd/nauthilus-directorctl/
```

### Implementation Notes

- The existing active-session store is affinity-keyed. M5 may extend the same
  Redis key group with a holder kind such as `delivery` or add dedicated
  delivery-hold scripts, but the visible domain must distinguish mailbox login
  sessions from delivery holds.
- A delivery hold pins the account to a shard while it is active. Protocol-
  specific backend selection still resolves that shard to an IMAP backend for
  IMAP sessions and an LMTP backend for LMTP delivery.
- If LMTP needs backend active counts for max-connection enforcement, add a small
  transaction lease or backend-use counter in the same Redis runtime model; do
  not implement it as process-local state.
- Any Redis keys introduced for LMTP runtime accounting must stay under the
  existing `storage.redis` namespace model and use repairable indexes or bounded
  leases. Do not add `director.lmtp.redis`.
- If route lookup receives a recipient-specific field, update OpenAPI first and
  keep `nauthilus-directorctl route lookup` generated-client backed. CLI output
  must show the identity-resolution source.
- Runtime operation audit logs may include backend identifiers for diagnostics,
  but not raw recipients or message identifiers.

### Required Unit Tests

- LMTP backend accounting increments and decrements exactly once per active
  backend transaction.
- Delivery-scoped affinity holds use the same normalized account key as IMAP.
- Delivery-scoped affinity holds make concurrent IMAP placement select the same
  active shard.
- Delivery holds are absent from user session listings but present in affinity
  state where placement needs them.
- Crashed or closed transactions are repaired through lease expiry or close
  handling.
- Maintenance, runtime out and drain affect LMTP new placement.
- LMTP route lookup calls Nauthilus identity lookup only for recipient
  resolution and never calls Nauthilus credential-authentication.
- LMTP route lookup does not create delivery holds, refresh leases or mutate
  Redis.
- LMTP route lookup reports identity-resolution source and whether the result is
  authoritative.
- Safe reload starts new LMTP listeners and drains removed LMTP listeners.

### Required Integration or E2E Tests

- Parallel LMTP transactions respect backend max-connection limits.
- A deterministic public-socket E2E flow starts an LMTP delivery, opens a new
  IMAP connection for the same resolved account before DATA or BDAT completion,
  and proves the IMAP placement uses the delivery hold's shard.
- Runtime out or hard maintenance prevents new recipient placement.
- Soft maintenance preserves an already accepted transaction while excluding new
  initial placements.
- Route lookup explains LMTP placement through REST and CLI, including recipient
  identity resolution when needed.

### Acceptance Criteria

- LMTP participates in runtime backend safety and account affinity without
  pretending deliveries are mailbox login sessions.
- Operator control behavior remains consistent with M2/M3 semantics.
- Route lookup remains side-effect-free and operator-useful for recipient input.

### Review Checklist

- Verify any new Redis keys follow the existing prefix/schema/namespace rules.
- Verify active-user APIs do not accidentally list LMTP deliveries as user
  sessions.
- Verify tests prove LMTP-to-IMAP concurrent shard consistency, not only the
  isolated LMTP transaction.
- Verify reload behavior does not strand accepted transactions.

## M5.7 Observability, Metrics, Logs and Traces

### Purpose

Make LMTP behavior observable enough for operators to diagnose routing,
recipient status, backend failures and interop issues without exposing
recipients, credentials or message content.

### In Scope

- Add LMTP transaction span:

```text
nauthilus_director.lmtp.transaction
```

- Reuse existing spans for:
  - `nauthilus_director.nauthilus.auth`
  - `nauthilus_director.routing.resolve`
  - `nauthilus_director.backend.select`
  - `nauthilus_director.backend.connect`
- Add events for:
  - LMTP session start/end
  - `LHLO`
  - STARTTLS result
  - peer auth result
  - MAIL command result
  - recipient route result
  - recipient same-backend rejection or temporary failure
  - backend connect/auth result
  - DATA start/end
  - BDAT chunk and completion result
  - per-recipient final status class
  - transaction reset
- Add Prometheus LMTP recipient and transaction observations using only approved
  labels.
- Use status classes and reason classes, not raw status text, for metrics.
- Allow backend identifiers in logs/traces only where the existing policy permits
  operator diagnostics.
- Keep raw recipients, message IDs, envelope sender, message subject, body
  content, peer passwords, bearer tokens and SASL blobs out of logs, metrics and
  traces.

### Out of Scope

- Recipient labels.
- Message content sampling.
- Full SMTP transcript logging.
- Raw backend status text as a metric label.
- Per-message persistent audit records.

### Expected Files or Packages

```text
internal/observability/
internal/protocol/lmtp/observability.go
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

LMTP metrics should cover:

- transaction count and duration
- recipient route results
- recipient accept/reject/tempfail totals
- same-backend rejection or tempfail totals
- DATA stream result and duration
- BDAT stream result and duration
- backend status class totals

### Required Unit Tests

- LMTP metric registration uses only allowed labels.
- Raw recipients and message body strings are rejected by observability policy.
- Span attributes do not contain raw recipient, sender, client IP, SASL blobs or
  message content.
- Reason classes are bounded for parser, auth, routing, backend, DATA and BDAT
  failures.

### Required Integration or E2E Tests

- `/metrics` exposes LMTP transaction and recipient counters after an LMTP flow.
- Logs for an LMTP flow contain operation/result/reason classes but no raw
  recipients, credentials or message content.
- Tracing captures the LMTP transaction and nested routing/backend boundaries
  when tracing is enabled.

### Acceptance Criteria

- Operators can distinguish routing failures, same-backend policy failures,
  backend failures and DATA/BDAT failures.
- No unsafe recipient, credential or message content appears in observable
  output.

### Review Checklist

- Verify no LMTP metric label violates the allowlist.
- Verify message content is not logged even in test failure paths.
- Verify raw backend error text is not promoted to metrics.

## M5.8 E2E, Interoperability, Documentation and Guardrails

### Purpose

Prove LMTP through public system boundaries and keep fake-service edge coverage
separate from real-server interoperability.

### In Scope

- Extend `test/e2e/fakes/lmtp_backend/` from scaffold to deterministic fake
  backend implementation.
- Extend `make e2e` to prove LMTP through public sockets.
- Keep `make e2e` deterministic and Docker-independent.
- Extend `make e2e-interop` with a real LMTP scenario.
- Keep the existing real IMAP Dovecot interoperability lane intact.
- Prove delivery-scoped active affinity with a concurrent user-stateful session
  during an in-flight delivery.
- Use pinned container images or digests for interop artifacts.
- Use Postfix as a real submitting peer when Postfix behavior is part of the
  externally visible contract.
- Use Dovecot project-provided assets as real LMTP backend where practical.
- Use the same Redis-compatible service policy as the existing interop lane.
- Update docs, manpages and generated config references when LMTP behavior or
  operator commands change.
- Run validation through Makefile targets.

### Out of Scope

- Making Docker interop part of `make guardrails`.
- Replacing fake-service edge cases with real-server happy paths.
- Marking M5 complete after a skipped real-server interop lane.

### Expected Files or Packages

```text
test/e2e/fakes/lmtp_backend/
test/e2e/fake_lane_test.go
test/e2e/interop/run.sh
test/e2e/interop/README.md
docs/man/nauthilus-director.1
docs/man/nauthilus-director.yaml.5
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
Makefile
```

### Implementation Notes

Fake-service guardrail lane:

- Start the production `nauthilus-director` binary for at least one LMTP public
  entrypoint proof.
- Start fake Nauthilus HTTP and gRPC authorities where peer auth scenarios need
  them.
- Assert fake Nauthilus HTTP recipient lookup receives `mode=no-auth`, while
  fake Nauthilus gRPC recipient lookup uses the identity-lookup RPC.
- Start fake LMTP backends on public loopback sockets.
- Exercise LMTP, LMTPS, STARTTLS, peer auth, recipient routing, backend auth,
  same-backend multi-recipient success, different-backend recipient failure,
  DATA forwarding, BDAT forwarding and per-recipient final status.
- Hold an accepted LMTP delivery open long enough to start a concurrent IMAP
  login for the same resolved account and prove both protocols use the same
  active shard.
- Scrape Prometheus metrics when enabled.
- Assert logs and fake-service observations do not contain credentials, SASL
  blobs, bearer tokens, raw recipients or message content.

Real-server interoperability lane:

- `make e2e-interop` remains separate from `make e2e`.
- The existing IMAP Dovecot scenarios must continue to pass or skip with the
  established stable message when Docker is unavailable.
- M5 adds a real LMTP delivery scenario with:
  - production `nauthilus-director` binary
  - real Postfix submitting peer or an equivalent pinned Postfix artifact
  - real Dovecot LMTP backend
  - real or Redis-compatible shared runtime state
  - configured frontend TLS/client-auth behavior where the selected Postfix
    setup supports it
  - backend TLS/auth behavior where the selected Dovecot setup supports it
  - at least one successful delivery through the director to the Dovecot LMTP
    backend
  - successful `BDAT ... LAST` delivery when the selected real backend advertises
    `CHUNKING`; otherwise closeout must record that frontend `CHUNKING` stayed
    suppressed for that topology
  - a concurrent IMAP placement proof for the same account while the delivery is
    still active, using the same shared runtime state
  - a same-backend multi-recipient proof
  - a different-backend recipient retry/failure proof
- If one selected real-server artifact cannot support a required auth or TLS
  mode, closeout must record the limitation and provide an equivalent
  real-server proof before marking M5 complete.

### Required Unit Tests

- Fake LMTP backend status scripting is deterministic.
- Fake Nauthilus recipient lookup fixtures can map multiple recipient forms to
  the same resolved account and to different resolved accounts.
- Test log redaction rejects peer credentials, bearer material, recipients and
  message content.
- Interop skip messages remain stable and explicit.

### Required Integration or E2E Tests

- `make e2e` proves LMTP public listener behavior, same-backend-only routing,
  backend DATA and BDAT forwarding, per-recipient status and observability.
- `make e2e` proves an in-flight LMTP delivery hold makes a concurrent IMAP
  connection for the same resolved account route to the same active shard.
- `make e2e-interop` proves real Postfix-to-Director-to-Dovecot LMTP delivery on
  a Docker-capable environment, including `CHUNKING`/`BDAT` when advertised by
  the selected real topology.
- `make e2e-interop` proves the same delivery-hold-to-IMAP placement invariant
  with real binaries or records an equivalent real-binary proof in closeout.
- Existing IMAP interop scenarios remain available and are not removed or
  weakened by the LMTP changes.
- `make guardrails` passes before any commit or pull request that contains M5
  implementation work.

### Acceptance Criteria

- Deterministic fake-service E2E covers forced LMTP edge cases.
- Deterministic fake-service E2E proves delivery-scoped affinity prevents
  concurrent IMAP placement drift.
- Deterministic fake-service E2E proves configured `CHUNKING` maps to real
  `BDAT` behavior and is suppressed when backend capability mediation forbids it.
- Real-server LMTP interop passes on a Docker-capable environment before M5 is
  marked complete.
- Real-server interoperability proves the same account cannot be split across
  shards by a concurrent LMTP delivery and IMAP login.
- Existing IMAP interop coverage is preserved.
- Documentation and generated references match supported LMTP behavior.

### Review Checklist

- Verify fake-service success is not used as a substitute for real LMTP interop.
- Verify Postfix and Dovecot images/artifacts are pinned.
- Verify real interop proves actual delivery semantics, not only port
  reachability.
- Verify both deterministic E2E and real-binary proof cover LMTP delivery
  affinity influencing concurrent IMAP placement.
- Verify all test logs are secret-safe and content-safe.

## Top-Level Acceptance Checklist

M5 is complete only when all items below are true:

- [ ] `lmtp` and `lmtps` listeners start from typed config through the production
      server binary.
- [ ] Listener dispatch supports IMAP and LMTP without duplicating transport
      lifecycle behavior.
- [ ] LMTP capability advertisement matches implemented behavior.
- [ ] LMTP capabilities remain configurable, but runtime `LHLO` advertises only
      the effective safe capability set.
- [ ] Configured `CHUNKING` is backed by production-ready `BDAT` parsing,
      streaming, backend forwarding, status mapping, tests and interop proof.
- [ ] STARTTLS and implicit TLS behavior are implemented and tested.
- [ ] Peer auth is optional or required exactly as configured.
- [ ] Peer auth authenticates the submitting LMTP peer only, not mailbox users.
- [ ] SASL peer auth is verified by Nauthilus as a technical submitter account,
      not as a recipient mailbox account.
- [ ] mTLS satisfies required peer auth only when an explicit listener policy
      requires verified client certificates and safe identity mapping succeeds.
- [ ] LMTP recipient routing uses the shared director routing model.
- [ ] LMTP preserves the wire recipient for backend commands while using only
      conservative lookup normalization before Nauthilus identity lookup.
- [ ] The runtime selector supports LMTP and `recipient_hash`.
- [ ] LMTP placement consumes health, maintenance, runtime out, drain, weight and
      max-connection state.
- [ ] Accepted LMTP deliveries open and maintain delivery-scoped active-affinity
      holds for resolved account keys.
- [ ] Concurrent IMAP placement for the same resolved account observes the LMTP
      delivery hold and selects the same active shard.
- [ ] Delivery holds are not exposed as mailbox login sessions through the v1
      session APIs.
- [ ] The first accepted recipient establishes exactly one backend target.
- [ ] Additional recipients are accepted only when they select the same backend
      target.
- [ ] Different-backend recipients are rejected or temporary-failed before DATA
      or BDAT.
- [ ] Different-backend recipients use a stable 4xx temporary failure, stable
      enhanced status code and stable reason class, never a permanent 5xx.
- [ ] Backend LMTP connect, TLS, capability discovery and configured backend auth
      are implemented.
- [ ] DATA and BDAT are streamed to one selected backend without message-body
      logging or cross-backend replay.
- [ ] Per-recipient final statuses are relayed for accepted recipients in order.
- [ ] Known mixed per-recipient backend outcomes are preserved; same-backend
      partial success is not converted to all-or-nothing failure.
- [ ] Unknown delivery outcomes temporary-fail rather than silently succeeding.
- [ ] LMTP health checks are protocol-aware and Redis-coordinated.
- [ ] LMTP deep health proves connect, TLS, greeting, `LHLO`, configured backend
      auth, optional `NOOP`/`RSET` and `QUIT` without envelope or message
      commands.
- [ ] Route lookup supports LMTP recipient diagnostics through optional
      Nauthilus identity lookup without credential authentication or Redis
      mutations.
- [ ] LMTP metrics use only the approved low-cardinality labels.
- [ ] Logs and traces do not contain raw recipients, message content, credentials,
      SASL blobs, bearer tokens, private keys or raw authorization headers.
- [ ] `make e2e` proves LMTP through public sockets, the production binary and
      the delivery-hold-to-IMAP shard-consistency invariant.
- [ ] `make e2e-interop` proves real Postfix-to-Director-to-Dovecot LMTP delivery
      on a Docker-capable environment, including the same shard-consistency
      invariant or an equivalent real-binary proof.
- [ ] Existing IMAP interop coverage remains present.
- [ ] Config docs, generated references, OpenAPI artifacts and manpages are
      updated when behavior changes.
- [ ] `make guardrails` is the final local gate before any commit or pull request
      that contains M5 implementation work.

## Required M5 Review Pass

Before closing M5, perform this review:

1. Re-read `AGENTS.md`.
2. Re-read `docs/ARCHITECTURE_ROADMAP.md`, especially sections 8, 9, 12, 17,
   18, 20, 21, 22 and 23.
3. Re-read `docs/specs/implementation/M0_FOUNDATION_SPEC.md`.
4. Re-read `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`.
5. Re-read `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`.
6. Re-read `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`.
7. Re-read `docs/config/nauthilus-director.target.yml`.
8. Re-read `docs/reference/config-paths.md`.
9. Re-read `docs/specs/openapi/nauthilus-director.yaml` if route lookup or REST
   diagnostics changed.
10. Compare implementation and docs against this specification and the source
    documents.
11. Fix drift, false capability advertisement, IMAP-only selector assumptions,
    active-affinity misuse, unsafe recipient logging, DATA/BDAT buffering
    mistakes and unsupported config documentation.
12. Run `make check-openapi` after any OpenAPI schema or generated-code change.
13. Run `make check-docs` after any typed config, config metadata or generated
    docs change.
14. Run targeted LMTP, listener, config, routing, backend, state, runtime,
    observability and REST tests.
15. Run `make e2e` and record the LMTP proof, including delivery-scoped
    affinity influencing concurrent IMAP placement.
16. Run `make e2e-interop` on a Docker-capable environment and record the real
    LMTP proof, the real-binary delivery-affinity proof and the existing IMAP
    lane status.
17. Run `make guardrails` before any commit or pull request.
18. Record `git status --short` and exact validation results in the M5 closeout.

## Decisions and Open Questions

These decisions are recorded so M5 implementation does not rediscover them in
code.

1. Decision: M5 enforces same-backend-only LMTP transactions.

   The director must not spool, split or replay one message body across backend
   groups. The first accepted recipient establishes the concrete backend target.
   Additional recipients may join only when they select that same target.

2. Decision: LMTP peer auth is not mailbox-user auth.

   The authenticated LMTP peer is the submitting service or client, typically a
   technical account for Postfix or another trusted delivery component. SASL peer
   auth credentials are verified by the configured Nauthilus authority through
   the normal credential-authentication path. They are not remote mailbox-user
   credentials and must never be interpreted as recipient account credentials.
   The HTTP/JSON Nauthilus transport uses `mode=no-auth` only for recipient
   identity lookup, not for SASL peer auth. Recipient routing still uses
   recipient identity and director-owned routing facts. Peer credentials must not
   be used as mailbox affinity keys or backend-selection facts. Backend LMTP
   authentication is a separate director-to-backend hop with separately
   configured service credentials.

3. Decision: Nauthilus identity lookup is the recipient identity authority.

   `RCPT TO` acceptance must first resolve the envelope recipient through
   Nauthilus identity lookup into the canonical mailbox account, tenant and
   routing attributes used by the shared director routing model. For the gRPC
   transport this is the `LookupIdentity` RPC. For the HTTP/JSON transport, the
   director must call the matching endpoint with `mode=no-auth`. The recipient
   address is not assumed to be the account key. Nauthilus supplies identity and
   routing facts, not concrete backend identifiers; `nauthilus-director` still
   owns backend selection, maintenance handling and affinity.

4. Decision: LMTP deliveries create delivery-scoped active-affinity holds.

   A running accepted delivery can change mailbox backend indexes, so it must
   participate in active affinity for the resolved account. If no active
   affinity already exists, LMTP opens a delivery-scoped hold on the selected
   shard, heartbeats it while the delivery is active, and closes it after DATA
   final status, `BDAT ... LAST` final status, `RSET`, `QUIT`, connection close
   or error. New IMAP sessions, later ManageSieve sessions and later POP3
   sessions for the same account must route to that same active shard while the
   hold exists. The hold is not a mailbox login session and must not appear as
   one in v1 session APIs. Unit tests, deterministic E2E and real-binary interop
   proof must cover this invariant.

5. Decision: message bodies are opaque.

   DATA payloads and BDAT chunks are streamed to the selected backend and are
   never logged, traced, metric-labeled, parsed for routing, stored for replay or
   inspected for policy by the director.

6. Decision: real LMTP interop is required before M5 completion.

   Fake-service E2E is required for deterministic edge coverage, but M5 closeout
   also requires a Docker-capable real-server proof with a real submitting peer
   and real LMTP backend. The existing IMAP interop lane must remain intact.

7. Decision: LMTP capabilities are configurable but truthfully mediated.

   LMTP listener capabilities follow the IMAP model: operators configure the
   desired frontend surface under `director.listeners.*.lmtp.capabilities`, and
   validation rejects unsupported capability names. Runtime `LHLO` output is the
   effective capability set, not a blind echo of YAML. The session must consider
   configured capabilities, implemented command support, listener TLS/auth state
   and backend-pool capability policy. If `CHUNKING` is configured, M5 includes
   production-ready `BDAT` support. The director may advertise `CHUNKING` only
   when `BDAT` parsing, exact chunk streaming, backend `BDAT` forwarding, status
   mapping, failure handling, deterministic E2E and real interop are all covered.
   M5 does not translate frontend `BDAT` to backend `DATA`.

   Omitted capabilities are deny rules, not cosmetic omissions. A session that
   did not advertise `STARTTLS`, `AUTH`, `SMTPUTF8` or `CHUNKING` must reject the
   related command, mechanism, MAIL parameter, SMTPUTF8 envelope syntax or BDAT
   body path for that session.

8. Decision: LMTP recipient normalization is conservative.

   The director preserves the original `RCPT TO` envelope form for backend LMTP
   commands and unsafe-observability checks. For Nauthilus identity lookup it may
   build a lookup form by removing LMTP path syntax and surrounding whitespace,
   lowercasing only ASCII domain-part characters, and leaving the local part
   unchanged. M5 performs no Unicode normalization, no IDNA conversion and no
   local-part case folding. The lookup form is never treated as the canonical
   account; Nauthilus returns the canonical account, tenant and routing facts
   used for active affinity and backend selection.

9. Decision: Different-backend recipients receive temporary failure.

   If an LMTP transaction already has a concrete backend target and an
   additional recipient resolves to another target, the director must reject that
   recipient before DATA or BDAT with a stable 4xx temporary failure, stable
   enhanced status code and stable reason class. This is not a permanent
   recipient failure: the sender may retry that recipient in a separate
   transaction, where it can route to the correct backend. M5 must not return
   5xx for this policy boundary.

10. Decision: Required peer auth can be SASL or explicitly configured mTLS.

   When `client_auth.required` is true, the default satisfying path is SASL peer
   auth through Nauthilus using technical submitter credentials. Verified mTLS
   may satisfy required peer auth only when listener TLS explicitly requires and
   verifies client certificates and the implementation derives a secret-safe
   submitter identity from the certificate. Without that explicit listener
   policy, a verified client certificate is transport hardening only and SASL
   peer auth remains required. Both paths authenticate the submitting LMTP peer
   only, never the recipient mailbox user.

11. Decision: LMTP deep health stops before envelope commands.

   M5 deep health checks connect to the backend, negotiate configured TLS, read
   the greeting, issue `LHLO`, perform configured backend auth, optionally issue
   `NOOP` and `RSET`, then close with `QUIT`. Health checks must never send
   `MAIL FROM`, `RCPT TO`, `DATA` or `BDAT`; they must not create messages,
   touch recipient-specific policy or mutate mailbox indexes. End-to-end
   delivery proof belongs to deterministic E2E and real interop, not continuous
   health checks.

12. Decision: LMTP route lookup uses hybrid recipient resolution.

   LMTP route lookup remains a diagnostic dry run, not a delivery. It must not
   authenticate credentials, create sessions, open delivery holds, refresh
   leases, mutate Redis, connect to backends or perform backend auth. When the
   caller supplies an already resolved account, tenant and routing facts, route
   lookup uses those facts directly. When the caller supplies an LMTP recipient
   and the director cannot answer from already known active affinity state, route
   lookup may call Nauthilus identity lookup (`LookupIdentity` for gRPC or
   `mode=no-auth` for HTTP/JSON) to resolve the recipient to canonical account,
   tenant and routing facts before running the shared selector in dry-run mode.
   The response must show the identity-resolution source and whether Nauthilus
   was used. Nauthilus credential-authentication is never part of route lookup.

13. Decision: Same-backend LMTP preserves per-recipient outcomes.

   LMTP is allowed to return one final status per accepted recipient after DATA
   or `BDAT ... LAST`. For recipients that were accepted into the same-backend
   transaction, the director must relay known backend outcomes per recipient:
   known `250` successes remain successes, known backend `4xx` temporary
   failures remain temporary failures, and known backend `5xx` permanent
   failures remain permanent failures with safe status text. The director must
   not convert a known backend over-quota or policy result into a blanket 4xx for
   every recipient, and it must not roll back or retry successful recipients.
   Only recipients whose final outcome is unknown, for example after stream
   failure or missing backend final replies, are temporary-failed by the director.

Blocking open questions to discuss before broad implementation:

None.

All previously blocking M5 questions are now recorded as decisions above. If
implementation discovers a new ambiguity, update this specification before
coding around it implicitly.
