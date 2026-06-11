# M8 LMTP SIZE and PIPELINING Follow-up

Status: completed follow-up after M8.

This document defines a compact post-M8 LMTP capability follow-up for explicit
LMTP capability policy, `SIZE` and `PIPELINING`.

`SIZE` is useful for real mail submission and delivery paths because it lets an
upstream MTA avoid sending a message the Director and selected LMTP backend will
not accept. The capability is only safe when the Director owns the advertised
limit, enforces that limit while streaming, and knows that every currently
eligible backend in the listener's pool can accept the extension.

`PIPELINING` is useful for high-throughput LMTP deployments because it lets a
client group commands and reduce round trips. LMTP references ESMTP extension
semantics and requires LMTP server implementations to implement command
pipelining. The Director can support the frontend contract with contained work
because the current session loop already reads commands in order, writes one
response per command and does not discard buffered input after command failure.
The follow-up must still prove the explicit `PIPELINING` contract before
advertising it: replies are sent in command order, DATA/BDAT framing remains
synchronized, STARTTLS/AUTH barriers remain strict and same-backend recipient
failures do not lose queued input.

The implementation may be completed after M8 without reopening the M5 LMTP
production milestone. This follow-up changes LMTP capability and envelope
behavior only; it must not introduce queueing, retry ownership, bounce
generation, durable message storage or backend command batching inside the
Director.

The follow-up also makes the existing deny-by-omission rule explicit:
capabilities omitted from `director.listeners.<name>.lmtp.capabilities` are not
advertised and their extension behavior is not accepted on the frontend. A new
operator-controlled deny filter adds a stronger rule: filtered capabilities are
never advertised and never used by backend delivery optimizations, even when a
backend advertises them during health or selected-backend `LHLO` discovery.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PLAINTEXT_AND_CAPABILITY_FOLLOWUP.md`
- `docs/specs/implementation/M8_PRODUCTION_HARDENING_SPEC.md`
- `docs/specs/implementation/M8_LMTP_BACKEND_CHUNKING_FOLLOWUP.md`
- RFC 1870: SMTP Service Extension for Message Size Declaration
- RFC 2033: Local Mail Transfer Protocol
- RFC 2920: SMTP Service Extension for Command Pipelining
- RFC 3030: SMTP Service Extensions for Transmission of Large and Binary MIME
  Messages
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/man/nauthilus-director.yaml.5`
- `internal/config/config.go`
- `internal/config/normalize.go`
- `internal/config/validate.go`
- `internal/app/server.go`
- `internal/backend/capabilities.go`
- `internal/protocol/lmtp/session.go`
- `internal/protocol/lmtp/parser.go`
- `internal/protocol/lmtp/commands.go`
- `internal/protocol/lmtp/data.go`
- `internal/protocol/lmtp/transaction.go`
- `internal/protocol/lmtp/status.go`
- `internal/protocol/lmtp/backend.go`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues. The M5 plaintext and capability follow-up correctly
kept `SIZE` and `PIPELINING` unsupported at that time; this document supersedes
that older statement for the future work described here.

## Original Gap

The current LMTP implementation has a deliberately small, fail-closed frontend
capability surface:

- `SMTPUTF8` gates `MAIL FROM ... SMTPUTF8` and UTF-8 envelope paths.
- `8BITMIME` gates `MAIL FROM ... BODY=8BITMIME` and forwards that parameter to
  the backend after backend-pool capability proof.
- `CHUNKING` gates frontend `BDAT`, while backend `BDAT` delivery is selected
  separately per chosen backend capability.
- `ENHANCEDSTATUSCODES`, `STARTTLS` and `AUTH ...` are mediated by implemented
  response, TLS and peer-auth behavior.

The current configuration already behaves like a positive allowlist for
frontend advertisement: only configured listener capabilities can appear in
`LHLO`. That rule is real but implicit in code and documentation. It also does
not give operators one explicit place to disable a capability across both
frontend advertisement and backend-side use.

This matters because deep health and selected-backend `LHLO` discovery preserve
backend capability facts. Those facts are useful, but they must not make the
Director use an extension that an operator has explicitly disabled for a
listener. Backend-side `CHUNKING` is the clearest example: after the M8 backend
CHUNKING follow-up, frontend `DATA` may be delivered as backend `BDAT` when the
selected backend supports `CHUNKING`, even when the frontend listener does not
advertise `CHUNKING`. A hard deny filter must be able to suppress that backend
optimization too.

`SIZE` is not part of that surface today:

- config validation rejects unsupported LMTP capabilities;
- `Session.effectiveCapability` does not return `SIZE`;
- `parseMailCommand` rejects `MAIL FROM ... SIZE=<n>` as an unsupported MAIL
  parameter;
- message streaming has line and BDAT chunk bounds, but no transaction-wide
  maximum message-size policy;
- backend `LHLO` parsing recognizes `SIZE` as a known keyword, but the shared
  capability set stores only tokens and does not preserve a backend
  `SIZE <n>` limit.

`PIPELINING` is also unsupported today:

- config validation rejects it as an unsupported LMTP capability;
- `Session.effectiveCapability` does not return it;
- the session loop has not been tested as an advertised pipelining server;
- no fake-lane proof covers queued MAIL, RCPT, DATA, RSET, NOOP or QUIT command
  groups;
- the backend path does not batch outbound LMTP commands even if a backend
  advertises `PIPELINING`.

## Goal

Add truthful, policy-backed LMTP `SIZE` support:

```text
frontend LHLO
  -> Director advertises SIZE <effective-max> only when configured,
     implemented and backend-safe
frontend MAIL FROM:<sender@example.org> SIZE=12345
  -> Director accepts only when SIZE was advertised and 12345 is within the
     effective maximum
frontend DATA or BDAT
  -> Director counts accepted message bytes while streaming and fails closed
     if the actual body exceeds the effective maximum
backend MAIL FROM:<sender@example.org> SIZE=12345
  -> Director forwards the accepted declared size only to a backend that
     advertised SIZE and is safe for the selected transaction
```

The frontend `SIZE` capability is a Director-owned contract. It is not a blind
mirror of backend `LHLO` output. It must combine listener policy, implemented
parser/streaming behavior, and fresh backend-pool capability proof before it is
advertised.

Add truthful frontend LMTP `PIPELINING` support:

```text
frontend LHLO
  -> Director advertises PIPELINING only when configured and implemented
frontend command group
  -> MAIL FROM, RCPT TO and RSET/NOOP groups may arrive without waits
  -> Director processes commands in order and returns one ordered response per
     command
frontend DATA or BDAT group terminator
  -> DATA, BDAT LAST, LHLO, STARTTLS, AUTH, NOOP and QUIT remain synchronization
     boundaries that are never response-buffered
```

`PIPELINING` is a frontend capability only. It does not mean the Director will
pipeline commands to the selected backend. Backend MAIL, RCPT, DATA and BDAT
forwarding remain sequential until a separate backend-optimization spec proves
otherwise.

Add an explicit hard-deny capability filter:

```yaml
director:
  listeners:
    lmtp:
      lmtp:
        capabilities:
          - SMTPUTF8
          - ENHANCEDSTATUSCODES
          - PIPELINING
          - SIZE
        capability_filter:
          deny:
            - CHUNKING
```

The deny filter is listener-scoped and has higher precedence than backend-pool
proof and selected-backend capabilities. It may list capabilities that are
absent from the positive allowlist so operators can also suppress backend-side
extension use. Direct overlap with desired capabilities is a validation error in
the first implementation rather than a second override mechanism. In the
example above, the listener must not advertise frontend `CHUNKING`, must not
accept frontend `BDAT`, and must not use backend `BDAT` for frontend `DATA` or
frontend `BDAT` delivery, even if every backend advertises `CHUNKING`.

## Delivery Shape

Implement this follow-up as seven slices:

1. Explicit listener capability policy, deny filter, normalization and
   validation.
2. Typed listener `SIZE` policy, config normalization and validation.
3. Structured backend `SIZE` capability facts with fresh pool-wide safety.
4. Frontend `MAIL FROM ... SIZE=<n>` parsing and session capability gating.
5. DATA and BDAT byte counting with fail-closed backend cleanup.
6. Frontend `PIPELINING` advertisement, ordered reply proof and state-barrier
   tests.
7. Backend forwarding, observability, tests and documentation reconciliation.

The implementation may be committed as one focused change if the proof remains
small. It is complete only when unit tests, public fake-lane tests and generated
operator documentation agree on the advertised and enforced `SIZE` behavior and
the advertised frontend `PIPELINING` contract.

## Scope

In scope:

- Document and enforce that `director.listeners.<name>.lmtp.capabilities` is a
  positive frontend capability allowlist. If a capability is omitted, related
  frontend extension behavior is not supported in that session.
- Add an explicit listener-scoped hard-deny filter, for example
  `director.listeners.<name>.lmtp.capability_filter.deny`.
- Treat the deny filter as higher precedence than backend-pool capability proof
  and selected-backend capability discovery.
- Apply the deny filter to frontend advertisement, frontend command gates,
  app-level backend capability mediation and selected-backend delivery choices.
- Keep backend health publication as raw protocol discovery facts unless the
  implementation introduces a listener-scoped health view. The filter must be
  applied when consuming those facts for a listener, not by globally erasing
  shared backend health data that another listener may legitimately allow.
- Reject unknown filter entries and base LMTP command names such as `MAIL`,
  `RCPT`, `DATA`, `RSET`, `NOOP` and `QUIT`. Operators disable `BDAT` through
  `CHUNKING`; ordinary LMTP command support is not controlled by the capability
  filter.
- Normalize filter entries with the same canonical spelling used for
  capabilities and reject ambiguous parameterized entries. For `AUTH`, either
  support an explicit whole-capability deny (`AUTH`) or clearly support
  mechanism-specific denies such as `AUTH PLAIN`; do not silently accept a shape
  that is not enforced.
- Reject direct contradictions between desired capabilities and the deny filter.
  The first implementation should fail validation on overlap so operator intent
  is not ambiguous.
- Add an explicit LMTP listener policy for maximum accepted message size, for
  example `director.listeners.<name>.lmtp.size.max_message_bytes`.
- Keep `SIZE` disabled by default unless the implementation deliberately
  chooses a conservative generated default and documents that default.
- Accept `SIZE` in `director.listeners.<name>.lmtp.capabilities` only after the
  parser, session gate, streaming counter, backend forwarding and documentation
  are implemented.
- Advertise `SIZE <effective-max>` only when `SIZE` is configured, the listener
  has a positive maximum, and fresh backend-pool proof says all currently
  eligible LMTP backends support `SIZE`.
- Preserve backend numeric `SIZE <n>` limits from `LHLO` discovery. The
  implementation must not rely on token-only `CapabilitySet.Has("SIZE")` when
  a backend advertises a lower maximum.
- Compute the effective frontend maximum as the minimum of the listener
  configured limit and all fresh backend numeric limits that are lower than the
  listener limit.
- Treat backend `SIZE` without a numeric parameter and backend `SIZE 0` as
  extension support without a backend-declared lower maximum.
- Suppress frontend `SIZE` when backend capability data is missing, stale,
  unhealthy, mixed across the pool or malformed.
- Parse exactly one `SIZE=<non-negative decimal>` MAIL parameter.
- Reject duplicate, malformed, negative or overflowing `SIZE` parameters.
- Reject `MAIL FROM ... SIZE=<n>` when `SIZE` was not advertised in the current
  `LHLO` response.
- Reject a declared size that exceeds the effective maximum before accepting the
  transaction.
- Count actual DATA and BDAT message bytes while streaming, independent of the
  declared MAIL size.
- Fail closed when the actual body exceeds the effective maximum, close or reset
  any open backend transaction, release delivery holds and avoid partial success
  replies.
- Forward `SIZE=<n>` to the selected backend `MAIL FROM` only when the frontend
  accepted the declared size and the selected backend advertised `SIZE`.
- Keep `SMTPUTF8`, `BODY=8BITMIME` and `SIZE=<n>` parameter ordering stable and
  deterministic on backend `MAIL FROM`.
- Add bounded reason classes for size rejection only if they remain compatible
  with the existing metric-label policy.
- Keep raw envelope sender, recipients, subjects, message identifiers and body
  content out of logs, metrics and traces.
- Add `PIPELINING` as a supported LMTP listener capability only after ordered
  frontend command-group behavior is proven.
- Keep `PIPELINING` configurable. Do not force it into generated defaults unless
  the implementation has public proof and the operator docs explain the server
  contract.
- Process queued frontend commands strictly in receive order.
- Preserve one response per command, including multiline responses, so clients
  can correlate replies by count.
- Treat `DATA`, `BDAT ... LAST`, `LHLO`, `STARTTLS`, `AUTH`, `NOOP` and `QUIT`
  as synchronization boundaries whose replies are flushed immediately.
- Allow `PIPELINING` and `CHUNKING` to be advertised together when both
  capabilities are independently configured, implemented and safe.
- Preserve RFC 3030 BDAT behavior when `PIPELINING` and `CHUNKING` are both
  active: after a failed BDAT chunk, additional BDAT chunks already present in
  the frontend pipeline must be accepted and discarded safely instead of being
  parsed as commands or forwarded to the backend.
- Keep STARTTLS strict: no command queued after `STARTTLS` may be processed
  until the TLS handshake has completed and a new `LHLO` is received.
- Keep AUTH strict: commands queued after an AUTH command must not bypass failed
  peer authentication, plaintext AUTH rejection or mechanism gating.
- Preserve same-backend recipient policy for pipelined `RCPT TO` groups.
- Preserve normal DATA and BDAT sequence rules when all pipelined recipients are
  rejected or when only some recipients are accepted.
- Never flush, discard or desynchronize buffered frontend input because one
  command in a pipelined group failed.

Out of scope:

- Backend command pipelining, even if a backend advertises `PIPELINING`.
- Durable queueing, retry scheduling, bounce generation or message spooling
  inside the Director.
- A global message-size policy for IMAP, POP3, ManageSieve or future protocols.
- Per-recipient or per-tenant dynamic message-size limits.
- Inferring the size limit from backend names, backend prose text, message
  content inspection or Dovecot-specific configuration files.
- Accepting `BINARYMIME`, `BODY=BINARYMIME`, `DSN`, `VRFY`, `EXPN` or other
  SMTP/LMTP extensions.

## Protocol Semantics

### Capability Policy

The effective LMTP capability surface is computed in this order:

1. The Director must know the capability and implement the related frontend
   command or parameter semantics.
2. The capability must be present in
   `director.listeners.<name>.lmtp.capabilities`.
3. The capability must be absent from
   `director.listeners.<name>.lmtp.capability_filter.deny`.
4. Session state must permit the capability. For example, `STARTTLS` is only
   available before TLS is active, and `AUTH` is only available when TLS and
   configured peer-auth policy allow it.
5. Backend-pool proof must permit backend-mediated capabilities such as
   `CHUNKING`, `8BITMIME` and `SIZE`.
6. Selected-backend proof must permit backend delivery behavior before the
   Director uses the extension on that backend connection.

Any missing allowlist entry, deny-filter entry, unsupported capability, unsafe
session state, missing backend-pool proof or selected-backend mismatch disables
the related behavior. The Director must not infer support from backend health
alone.

This rule applies to existing capabilities as well as this follow-up:

- If `SMTPUTF8` is omitted or denied, `MAIL FROM ... SMTPUTF8` and UTF-8-only
  envelope paths fail closed.
- If `8BITMIME` is omitted or denied, `MAIL FROM ... BODY=8BITMIME` fails
  closed and the backend `MAIL FROM` must not include `BODY=8BITMIME`.
- If `CHUNKING` is omitted or denied, frontend `BDAT` is unavailable. If it is
  denied, backend `BDAT` delivery is also unavailable even when selected
  backends advertise `CHUNKING`.
- If `PIPELINING` is omitted or denied, the Director must not advertise it.
  Clients that send commands early still receive ordered replies, but the
  Director does not claim the explicit pipelining extension.
- If `SIZE` is omitted or denied, `MAIL FROM ... SIZE=<n>` fails closed and the
  backend `MAIL FROM` must not include `SIZE=<n>`.

### LHLO Advertisement

When `SIZE` is enabled and safe, the frontend `LHLO` response includes one
capability line with the effective maximum:

```text
250-SIZE 52428800
```

The effective maximum must be recomputed for each `LHLO` from current listener
policy, the deny filter and backend-pool capability proof. If the proof is
stale or mixed, or if `SIZE` is filtered, omit `SIZE`. Omission is a deny rule:
the same session must reject a `SIZE=` MAIL parameter until a later `LHLO`
advertises `SIZE`.

### MAIL FROM

`MAIL FROM` accepts `SIZE=<n>` only after current-session `SIZE` advertisement:

```text
MAIL FROM:<sender@example.org> SIZE=12345
250 2.0.0 Sender accepted
```

If `SIZE` was not advertised, `SIZE=<n>` is an unsupported MAIL parameter and
must fail closed without calling Nauthilus, opening a backend connection or
creating delivery holds.

If `n` exceeds the effective maximum, reject the MAIL command before any
recipient is accepted. The preferred response is a permanent size failure such
as `552 5.3.4 Message size exceeds fixed maximum message size`. The exact text
must remain secret-safe and bounded.

`SIZE=0` is valid and means the sender declares an empty message body. The
actual streamed body must still be counted and rejected if it exceeds the
effective maximum.

### DATA

For frontend `DATA`, the counter measures message content bytes after DATA
transfer decoding:

- the DATA terminator line is not counted;
- dot-stuffed content is counted after one leading dot is removed;
- CRLF bytes preserved as message content are counted;
- oversized messages fail after the Director has consumed enough frontend input
  to maintain protocol framing.

When backend forwarding has already started and the body exceeds the limit, the
Director must close or reset the backend transaction and return safe permanent
size failures for the accepted recipients. It must not emit partial success for
any accepted recipient in that transaction.

### BDAT

For frontend `BDAT`, the counter measures exact byte-counted payload bytes.
Each chunk contributes its announced size after the chunk is successfully read
or discarded. If the cumulative size exceeds the effective maximum, the
Director must stop forwarding further backend payload bytes, drain enough
frontend payload to keep framing safe, reset the transaction and return a
permanent size failure.

If the oversized chunk is not `LAST`, later frontend body commands must see a
clean transaction state and fail by normal sequence rules unless the client
starts a new transaction.

### Backend Forwarding

Backend `MAIL FROM` forwarding must include `SIZE=<n>` only when the frontend
sent a valid declared size:

```text
MAIL FROM:<sender@example.org> SMTPUTF8 BODY=8BITMIME SIZE=12345
```

The selected backend must have advertised `SIZE` in its `LHLO` response. If the
selected backend lacks `SIZE` despite pool proof, fail closed before accepting
or forwarding recipients. This protects reload, health-publication and stale
snapshot races.

When the frontend omitted `SIZE=<n>`, do not synthesize a backend `SIZE`
parameter from bytes observed later in DATA or BDAT. Backend MAIL happens before
the body is known in the current transaction shape.

### PIPELINING

When `PIPELINING` is configured and supported, the frontend `LHLO` response may
include:

```text
250-PIPELINING
```

The Director must process a pipelined command group as ordinary commands that
arrived early. It does not need a separate asynchronous scheduler for the first
implementation. The safe shape is to keep the current sequential dispatch loop,
but add tests and small guardrails that prove it already satisfies the advertised
server requirements:

- command responses are emitted in receive order;
- multiline `LHLO` responses remain one response for correlation purposes;
- a failed `RCPT TO` does not discard following queued commands;
- `DATA` receives `354` only when at least one recipient was accepted;
- `BDAT LAST` returns one reply for each accepted recipient;
- `RSET` resets transaction state and does not discard later queued commands;
- `NOOP` and `QUIT` remain synchronization commands and are flushed immediately;
- `STARTTLS` stops plaintext command processing before the TLS handshake;
- `AUTH` failures do not let queued transaction commands run as authenticated.

The implementation may choose not to buffer positive replies for MAIL and RCPT
groups. RFC 2920 recommends response buffering for some grouped commands, but
the essential server contract is ordered replies and no input loss. Immediate
flushes are acceptable for correctness and preserve the existing LMTP behavior
that sends replies as soon as possible.

Frontend `PIPELINING` must not change backend forwarding. The Director may
receive frontend MAIL and RCPT commands in one TCP read, but backend MAIL and
RCPT forwarding still happens only after the normal recipient placement and
selected-backend checks complete.

### CHUNKING and PIPELINING

`CHUNKING` and `PIPELINING` are compatible and may be advertised in the same
`LHLO` response when each capability is independently safe:

```text
250-PIPELINING
250 CHUNKING
```

The implementation must treat their interaction as a byte-framing problem, not
as a reason to suppress either capability.

Required combined behavior:

- `BDAT` remains available only when `CHUNKING` was advertised in the current
  session.
- The compliant client shape is MAIL/RCPT command grouping first, then
  processing those replies, then sending one or more BDAT chunks. The Director
  must still fail closed if a client sends `BDAT` before server-side MAIL and at
  least one accepted recipient establish a valid transaction.
- `PIPELINING` may be used for BDAT chunk groups once the transaction is valid;
  the Director must keep exact byte counts for every chunk in that group.
- `DATA` and `BDAT` must not be mixed in the same transaction.
- Each non-final `BDAT` chunk returns exactly one reply.
- `BDAT ... LAST` returns one reply per accepted recipient in original accepted
  recipient order, as required by LMTP.
- If a BDAT command declares `LAST`, any later BDAT command in the same
  transaction is a bad-sequence error and the transaction must be reset before
  continuing.
- If a BDAT chunk fails after its command was received, the Director must read
  and discard that chunk's announced payload before sending the failure reply.
- If `PIPELINING` is advertised and additional BDAT chunks are already queued
  after a failed BDAT, the Director must parse their command lines, discard their
  announced payload bytes and reject them without forwarding further backend
  payload. This prevents payload bytes from being interpreted as LMTP commands.
- After a failed BDAT chunk, the transaction state is unsafe for further
  delivery. The client must use `RSET` before starting another transaction; the
  Director may keep rejecting queued body commands until that reset or
  connection close.

Combined `CHUNKING` plus `PIPELINING` support must be proven with frontend
transcripts and fake-backend transcripts. A final status code alone is not
enough proof because the bug class here is stream desynchronization.

## Backend Capability Facts

The existing backend capability set is sufficient for token-only extensions
such as `CHUNKING` and `8BITMIME`, but `SIZE` is parameterized. The
implementation must preserve enough structured state to answer both questions:

- Did this backend advertise the `SIZE` extension?
- Did it advertise a numeric maximum, and if so, what is that maximum?

Acceptable implementation shapes include:

- extend backend LMTP capability parsing to publish a structured
  `SIZE` maximum next to the existing token set;
- or canonicalize size facts in a deterministic Redis-safe form while still
  allowing code to distinguish `SIZE` from `SIZE=<n>` without string scraping at
  every call site.

The parser must ignore banner prose. A line such as
`mailstore says SIZE 10485760` must not create `SIZE` support. A valid backend
capability line must start with `SIZE` and may have exactly one non-negative
decimal parameter. Per RFC 1870, `SIZE 0` means no fixed maximum is advertised;
it must not be interpreted as a backend limit of zero bytes.

Pool-wide `SIZE` safety should follow the existing fail-closed capability
pattern used for `CHUNKING` and `8BITMIME`: all eligible backends in the pool
must have fresh healthy proof before the frontend advertises `SIZE`.

Backend health checks may continue to publish all normalized backend-advertised
capability facts. That raw health state is not the same as listener permission.
The listener capability policy must build an effective view by applying the
positive allowlist and deny filter before any frontend advertisement or backend
delivery optimization consumes the health state.

The selected backend connection must apply the same deny filter to its own
`LHLO` result. For example, when `CHUNKING` is denied, `supportsChunking()` or
its successor must report false for delivery selection even if the selected
backend advertised `CHUNKING`. When `SIZE` is denied, backend `MAIL FROM` must
not include `SIZE=<n>` even if the selected backend advertised `SIZE`.

## PIPELINING Compatibility

`PIPELINING` should be implemented with the smallest clean server-side change.
The current code path is close to the desired shape because it already reads one
command, dispatches it, writes the response and then continues reading any bytes
already present in the buffered reader.

The follow-up must not optimize ahead of proof:

- Do not add goroutines that process one LMTP session concurrently.
- Do not issue backend MAIL, RCPT, DATA or BDAT commands before the frontend
  command that owns them has passed current validation.
- Do not process commands queued after `STARTTLS` on the plaintext reader.
- Do not process commands queued after failed `AUTH` as authenticated commands.
- Do not accept DATA when no recipient in the current transaction was accepted.
- Do not hide same-backend failures by delaying all RCPT replies until DATA.
- Do not add backend command batching under this frontend capability.

If tests show the current flush-after-each-command behavior creates unacceptable
performance for high-load clients, response buffering may be added only for the
safe command subset that RFC 2920 allows to appear before a group terminator.
That buffering must be bounded per session and must flush on DATA, BDAT, LHLO,
STARTTLS, AUTH, NOOP, QUIT, unknown commands, read timeout, context cancellation
or when the local input buffer is empty.

## Error Handling

- Unknown, malformed or contradictory capability filter entries fail config
  validation before listeners bind.
- A denied capability is treated as unavailable even when it appears in
  `lmtp.capabilities`, backend-pool health proof or selected-backend `LHLO`
  output.
- Missing, stale or mixed backend `SIZE` proof suppresses frontend `SIZE`.
- A `SIZE=` parameter without current-session advertisement fails as an invalid
  MAIL parameter.
- Duplicate, malformed, overflowing or negative `SIZE=` values fail as invalid
  MAIL parameters.
- Declared size above the effective maximum fails before recipient placement.
- Actual DATA or BDAT body bytes above the effective maximum fail the delivery
  transaction with permanent size status for all accepted recipients.
- Backend rejection of the forwarded `MAIL FROM ... SIZE=<n>` fails closed
  before accepting the recipient that triggered backend transaction setup.
- Backend write, flush or final-status errors after a size failure must not
  override the frontend size result with partial success.
- Cleanup must close backend streams and release delivery holds exactly once.
- Pipelined command failures must not flush, discard or lose subsequent bytes
  already read from the frontend stream.
- Commands queued across STARTTLS must fail closed by handshake sequencing:
  plaintext commands after the STARTTLS response must not be interpreted as
  post-TLS commands.
- Commands queued after failed AUTH must use the normal unauthenticated state
  and fail by existing peer-auth or bad-sequence rules.
- DATA in a pipelined group with no accepted recipients must fail with the
  existing bad-sequence response and must not consume message content as a
  successful body transfer.
- Failed pipelined BDAT chunks must drain their own payload and any queued BDAT
  payloads that the protocol parser can safely identify before returning to
  command mode.
- After a failed pipelined BDAT chunk, backend forwarding must stop and no later
  queued BDAT payload may be written to the backend.

## Observability

Observability must help operators diagnose size-policy outcomes without leaking
message content or identities.

Allowed observations:

- bounded result/reason classes such as `size_policy`, `size_declared_too_large`
  or `size_body_too_large`;
- whether frontend `SIZE` was advertised or suppressed, as a low-cardinality
  event or trace attribute;
- whether backend `SIZE` proof was absent, stale, mixed or malformed, using
  bounded reason classes;
- whether a capability was suppressed by the deny filter, as a capability token
  and bounded reason class without backend identity or message data;
- whether `PIPELINING` was advertised, as a low-cardinality capability fact;
- pipelined command-group failures only through existing command/result/reason
  dimensions unless a new bounded reason class is necessary.

Forbidden observations:

- raw sender addresses;
- raw recipients;
- message IDs;
- subjects;
- body bytes;
- exact per-user or per-recipient policy data;
- unbounded backend error text.

Avoid adding exact message sizes as metric labels. Exact numeric sizes may be
used in histograms or trace attributes only if they are not identifying and the
existing observability policy allows that shape.

## Tests

Required unit tests:

1. Config validation accepts a safe `lmtp.capability_filter.deny` list.
2. Config validation rejects unknown deny-filter entries.
3. Config validation rejects base LMTP command names such as `DATA`, `MAIL`,
   `RCPT`, `RSET`, `NOOP` and `QUIT` in the deny filter.
4. Config validation rejects direct overlap between `lmtp.capabilities` and
   `lmtp.capability_filter.deny`.
5. Normalization preserves stable capability and deny-filter spelling and
   de-duplicates entries.
6. LHLO omits every capability that is not present in `lmtp.capabilities`.
7. Frontend extension commands or parameters fail closed when their capability
   is omitted from `lmtp.capabilities`.
8. LHLO omits every capability listed in the deny filter even when the backend
   pool has fresh proof.
9. Frontend extension commands or parameters fail closed when their capability
   is denied.
10. Backend mediation excludes denied capabilities from the session
    `BackendCapabilities` input.
11. Selected-backend delivery choices treat denied selected-backend capabilities
    as unavailable.
12. Denying `CHUNKING` disables frontend `BDAT` and backend DATA-to-BDAT
    conversion.
13. Denying `8BITMIME` rejects `MAIL FROM ... BODY=8BITMIME` and prevents
    backend `BODY=8BITMIME` forwarding.
14. Denying `SMTPUTF8` rejects `MAIL FROM ... SMTPUTF8` and UTF-8 envelope
    paths.
15. Denying `SIZE` suppresses frontend `SIZE`, rejects `MAIL FROM ... SIZE=<n>`
    and prevents backend `SIZE=<n>` forwarding.
16. Denying `PIPELINING` suppresses frontend `PIPELINING`.
17. Config validation rejects `SIZE` until typed size policy and runtime support
    are implemented in the same change.
18. Config validation accepts `SIZE` with a positive
    `lmtp.size.max_message_bytes`.
19. Config validation rejects `SIZE` with zero, negative or missing effective
    listener maximum.
20. Config validation accepts `PIPELINING` only after the ordered frontend
    behavior is implemented.
21. Backend LHLO parsing recognizes `SIZE` and `SIZE <n>` capability lines,
    including `SIZE 0` as support without a backend-declared lower maximum.
22. Backend LHLO parsing ignores prose that merely contains the word `SIZE`.
23. Pool capability mediation suppresses `SIZE` on missing, stale, unhealthy,
    mixed or malformed backend proof.
24. LHLO advertises `SIZE <effective-max>` only when configured, implemented,
    not denied and backend-safe.
25. `MAIL FROM ... SIZE=<n>` fails before LHLO advertisement.
26. `MAIL FROM ... SIZE=<n>` succeeds when advertised and within the effective
    maximum.
27. Duplicate, malformed, overflowing and too-large `SIZE=` parameters fail
    closed.
28. Backend `MAIL FROM` receives `SIZE=<n>` when the frontend accepted it and
    the selected backend advertised `SIZE`.
29. Backend `MAIL FROM` does not receive synthesized `SIZE=` when the frontend
    omitted it.
30. DATA exactly at the effective maximum succeeds.
31. DATA exceeding the effective maximum fails closed and closes the backend
    transaction.
32. BDAT exactly at the effective maximum succeeds.
33. BDAT exceeding the effective maximum drains or closes safely without backend
    payload leakage after the limit.
34. `SIZE`, `SMTPUTF8` and `BODY=8BITMIME` coexist and preserve deterministic
    backend MAIL parameter forwarding.
35. LHLO advertises `PIPELINING` only when configured and not denied.
36. A pipelined `MAIL FROM`, multiple `RCPT TO` commands and `DATA` return
    replies in command order.
37. A pipelined `RCPT TO` same-backend failure does not discard following
    queued commands.
38. Pipelined `DATA` with no accepted recipients fails without accepting a body.
39. Pipelined `RSET`, `MAIL FROM` and `RCPT TO` preserve transaction reset
    semantics.
40. Queued plaintext commands after `STARTTLS` are not processed as post-TLS
    commands.
41. Queued transaction commands after failed `AUTH` do not bypass peer auth.
42. Pipelined `BDAT` chunks keep exact byte framing and final per-recipient
    replies.
43. `CHUNKING` and `PIPELINING` can be advertised together when both are
    configured, not denied and independently safe.
44. A pipelined non-final `BDAT` failure drains the failed payload, rejects
    already queued BDAT chunks and does not forward later payload bytes to the
    backend.
45. Pipelined `BDAT` after `BDAT ... LAST` fails with bad sequence and requires
    transaction reset before further delivery.
46. Observability tests prove filter, size and pipelining reason classes are
    bounded and no message content or raw envelope values are emitted.

Required E2E or fake-lane tests:

- Production binary suppresses omitted capabilities and rejects their extension
  commands or parameters through public LMTP sockets.
- Production binary suppresses deny-filtered capabilities even with fresh
  backend health proof.
- Public deny-filtered `CHUNKING` flow proves frontend `BDAT` is unavailable and
  backend DATA-to-BDAT conversion is not used.
- Public deny-filtered `8BITMIME`, `SMTPUTF8`, `SIZE` and `PIPELINING` flows
  prove the matching frontend extension behavior is unavailable.
- Production binary advertises `SIZE <effective-max>` on a public LMTP socket
  only with fresh backend proof.
- Production binary suppresses `SIZE` when one backend in the pool omits the
  extension or publishes stale health.
- Public LMTP transaction with declared size within the limit reaches the fake
  backend with `MAIL FROM ... SIZE=<n>`.
- Public LMTP transaction with declared size above the limit is rejected before
  backend connection or recipient placement.
- Public DATA body exceeding the limit returns a permanent size failure and the
  fake backend transcript proves no partial delivery success.
- Public BDAT body exceeding the limit returns a permanent size failure and the
  fake backend transcript proves no extra backend BDAT payload is sent.
- Production binary advertises `PIPELINING` only when configured.
- Public pipelined `MAIL FROM` plus multiple `RCPT TO` commands plus `DATA`
  returns ordered replies and delivers only accepted recipients.
- Public pipelined all-recipient-failure followed by `DATA` returns the bad
  sequence or no-valid-recipient response without backend body delivery.
- Public pipelined STARTTLS and AUTH barrier tests prove queued plaintext or
  unauthenticated transaction commands do not cross security state.
- Public pipelined CHUNKING test sends multiple BDAT chunks without waiting for
  every intermediate reply and proves exact payload framing plus final LMTP
  recipient-status ordering.
- Public failed-BDAT pipeline test proves queued BDAT payloads are discarded and
  no later backend BDAT payload is forwarded after the failure.
- Fake backend transcript proves frontend `PIPELINING` does not create backend
  command batching.

## Documentation Updates

Update operator-facing documentation where behavior changes:

- Target config comments should explain that `lmtp.capabilities` is a positive
  frontend allowlist and that `lmtp.capability_filter.deny` is a higher-priority
  hard deny for frontend advertisement and backend-side extension use.
- Target config comments should explain that `SIZE` is a desired frontend
  capability mediated by Director size policy and backend-pool proof.
- Generated config defaults and paths must include the new typed LMTP size
  policy and deny filter when config fields are added.
- The YAML manpage must document `SIZE` advertisement, `MAIL FROM SIZE=`,
  actual body enforcement, the frontend-only `PIPELINING` server contract and
  the deny filter's precedence over backend health capabilities.
- The architecture roadmap should mention the completed follow-up only after
  implementation and public proof exist.
- The older M5 capability follow-up should not be rewritten as if `SIZE` had
  existed during M5; later docs may point to this M8 follow-up as the newer
  source of truth.

Generated config references must be refreshed through the normal Makefile
targets when typed config changes are introduced.

## Acceptance Criteria

This follow-up is complete when:

- `lmtp.capabilities` is documented and enforced as a positive frontend
  allowlist;
- omitted capabilities are not advertised and their frontend extension behavior
  fails closed;
- `lmtp.capability_filter.deny` exists as a listener-scoped hard deny with
  validation, normalization and generated docs;
- denied capabilities are not advertised, not accepted as frontend extensions
  and not used for backend delivery optimizations;
- backend health can publish raw capability facts without bypassing the
  listener-scoped effective capability policy;
- `SIZE` has an explicit listener policy and is disabled unless that policy is
  valid;
- backend `SIZE` capability discovery preserves numeric limits safely;
- frontend `LHLO` advertises `SIZE <effective-max>` only when configured,
  implemented and fresh backend-pool proof is safe;
- `MAIL FROM ... SIZE=<n>` is parsed, bounded and rejected unless current-session
  `SIZE` was advertised;
- declared size above the effective maximum fails before recipient placement;
- actual DATA and BDAT bytes above the effective maximum fail closed without
  partial delivery success;
- accepted declared size is forwarded to selected backends that advertised
  `SIZE`;
- backend `SIZE` races fail closed for the selected transaction;
- `PIPELINING` is advertised only when configured and proven through ordered
  frontend command-group tests;
- `CHUNKING` and `PIPELINING` work together without suppressing either
  capability when both are independently safe;
- pipelined BDAT failures discard queued BDAT payload safely and stop backend
  forwarding before later payload bytes;
- frontend `PIPELINING` does not introduce backend command batching;
- queued input is never discarded or reinterpreted across STARTTLS, AUTH,
  same-backend failures or DATA/BDAT body framing;
- observability remains bounded and secret-safe;
- generated docs, manpages and examples match the implemented config surface;
- focused tests plus `make guardrails` or documented deterministic equivalent
  proof pass.

## Completion Evidence

Completed on 2026-06-11.

Implemented behavior:

- `lmtp.capabilities` is enforced as a positive frontend allowlist, with omitted
  and deny-filtered capabilities failing closed for frontend extension behavior.
- `lmtp.capability_filter.deny` has listener-scoped validation, normalization,
  generated config references and runtime precedence over backend-pool proof and
  selected-backend `LHLO` discovery.
- Backend health and selected-backend discovery preserve structured `SIZE` facts,
  including numeric backend maxima, without making backend health the frontend
  capability policy.
- Frontend `LHLO` advertises `SIZE <effective-max>` only when `SIZE` is
  configured, `size.max_message_bytes` is positive, the deny filter permits it
  and fresh backend-pool proof says all eligible LMTP backends support `SIZE`.
- `MAIL FROM ... SIZE=<n>` is parsed, bounded by the current session's advertised
  effective maximum and forwarded as backend `SIZE=<n>` only when the selected
  backend advertised `SIZE` and the frontend supplied an accepted declaration.
- DATA and BDAT bodies are counted against the effective maximum and oversize
  bodies fail permanently without partial delivery success.
- `PIPELINING` is a frontend ordered-reply capability only. Public fake-lane
  proof confirms it does not introduce backend command batching.
- `CHUNKING` and `PIPELINING` coexist when independently safe, and pipelined
  BDAT failures drain queued payloads without forwarding later backend payload
  bytes.
- Observability uses bounded capability, size and pipelining reason classes and
  continues to exclude body bytes, raw recipients, credentials and unsafe backend
  detail.

Public proof added or refreshed:

- `TestServerBinaryPublicLMTPSIZEForwardingTranscript` proves public `LHLO`
  `SIZE <effective-max>`, accepted frontend `MAIL FROM SIZE=<n>` forwarding to
  backend `MAIL FROM ... SIZE=<n>` and no synthesized backend `SIZE=` when the
  frontend omitted it.
- `TestServerBinaryPublicLMTPSIZESuppressedByMixedHealth` proves mixed backend
  pool proof suppresses public `SIZE` and rejects `MAIL FROM SIZE=<n>` before
  backend delivery.
- `TestServerBinaryPublicLMTPSIZEOversizeRejectsBeforeBackend` proves declared
  oversize is rejected before recipient placement or backend observation.
- `TestServerBinaryPublicLMTPSIZESelectedBackendRaceFailsClosed` proves stale
  pool proof or selected-backend `LHLO` mismatch fails closed before backend
  `MAIL`.
- `TestServerBinaryPublicLMTPPipeliningDoesNotBatchBackend` proves frontend
  command grouping returns ordered replies without backend command batching.
- Existing public fake-lane coverage continues to prove omitted capabilities,
  deny-filtered `CHUNKING`, `8BITMIME`, `SMTPUTF8`, `SIZE` and `PIPELINING`,
  DATA/BDAT oversize handling, STARTTLS/AUTH barriers, all-recipient-failure
  pipelining, `CHUNKING` plus `PIPELINING` BDAT framing and failed pipelined BDAT
  payload discard.

Closeout commands:

| Command | Status | Notes |
| --- | --- | --- |
| `make generate-docs` | passed | Regenerated config defaults and path references from the typed config model. |
| `make check-docs` | passed | Generated docs are current after metadata and target-config reconciliation. |
| `make test` | passed | Package tests pass; direct package E2E keeps real-binary cases skipped unless the E2E harness sets `NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY`. |
| `make race` | passed | Race tests pass across production packages and deterministic test packages. |
| `make e2e` | passed | Deterministic public fake-service lane starts the real server binary and covers LMTP SIZE, DATA/BDAT, PIPELINING, TLS, auth, route lookup and observability paths. |
| `make build-check` | passed | Production binaries build successfully. |
| `make lint` | passed | `golangci-lint` reports 0 issues. |
| `make e2e-interop` | passed | Docker-capable run passed with real Dovecot IMAP/LMTP/ManageSieve/POP3 backends, Postfix/swaks submission, curl IMAP delivery proof, runtime controls and health ownership. |
| `make guardrails` | passed | Aggregate docs, packaging, headers, OpenAPI, fix, vet, lint, test, race, E2E and build-check gate passed. |
| `git diff --check` | passed | Whitespace check passed after this closeout update. |
