# M8 LMTP Backend CHUNKING Follow-up

Status: proposed follow-up after M8. This document records a post-M8 LMTP
transport optimization for `nauthilus-director`. It is intentionally specified
as a follow-up because M8 production hardening is already complete and because
this work changes mail-protocol forwarding behavior rather than production
packaging, control-plane authentication or deployment hardening.

The implementation may be completed after M8 without reopening the M5 LMTP
production milestone. The goal is to make backend LMTP delivery more efficient
when a selected backend advertises `CHUNKING`, while keeping frontend protocol
compatibility and preserving LMTP recipient-status semantics.

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
- `docs/specs/implementation/M8_LISTENER_AUTHORITY_CONTEXT_FOLLOWUP.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/man/nauthilus-director.yaml.5`
- `internal/protocol/lmtp/session.go`
- `internal/protocol/lmtp/commands.go`
- `internal/protocol/lmtp/data.go`
- `internal/protocol/lmtp/transaction.go`
- `internal/protocol/lmtp/backend.go`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues. The director remains a protocol proxy and placement
boundary. It must not become a durable mail queue and must not take ownership of
message retry semantics that belong to the upstream MTA.

## Original Gap

The LMTP implementation already has two separate body paths:

- frontend `DATA`, which is streamed line by line and dot-terminated;
- frontend `BDAT`, which is streamed as byte-counted chunks when `CHUNKING` is
  accepted on the listener.

When backend forwarding is enabled, the current backend paths mirror the
frontend body command shape:

- frontend `DATA` is forwarded as backend `DATA`;
- frontend `BDAT` is forwarded as backend `BDAT`.

That behavior is correct for protocol transparency, but it misses a useful
optimization: frontend `DATA` can be accepted from clients that do not support
or were not offered `CHUNKING`, while the director may still deliver the same
message to a selected backend using backend `BDAT` when that backend advertised
`CHUNKING` in its `LHLO` response.

This follow-up also closes the safety gap that backend `BDAT` must be gated by
the selected backend capability set. Backend capabilities are already collected
by `BackendConnection.queryCapabilities`; the body forwarding path must use
that information before choosing `BDAT`.

## Goal

Add backend-side LMTP CHUNKING selection for message delivery:

```text
frontend client
  -> DATA body accepted by listener
  -> director removes DATA transfer encoding
  -> backend BDAT chunks when selected backend advertises CHUNKING
  -> final LMTP per-recipient statuses returned to frontend
```

The feature is independent of frontend `CHUNKING` advertisement. A listener may
choose not to advertise `CHUNKING` to Postfix or another frontend client and the
director may still use backend `BDAT` for delivery to a capable backend. The
frontend capability surface and the backend delivery transport are separate
negotiation boundaries.

## Delivery Shape

Implement this follow-up as five slices:

1. Backend capability gate and body-transport selection helper.
2. DATA-to-BDAT streaming writer for backend forwarding.
3. Backend BDAT payload helpers that do not depend on the frontend reader.
4. Observability, error mapping and transaction cleanup reconciliation.
5. Unit, fake-backend and E2E proof plus documentation updates.

The implementation may reuse the existing frontend `BDAT` parser and backend
final-status reader, but it must not couple DATA-to-BDAT conversion to the
frontend `BDAT` command path. DATA-to-BDAT has different input semantics:
`DATA` is line-oriented and dot-stuffed; backend `BDAT` is byte-counted raw
message content.

## Scope

In scope:

- Detect whether the selected backend advertised `CHUNKING` after backend
  `LHLO` discovery.
- Add a small helper on the backend transaction or backend connection boundary,
  for example `supportsChunking()`.
- Use backend `BDAT` only when the selected backend capability set contains
  `CHUNKING`.
- Keep the existing backend `DATA` path as the fallback when the backend does
  not advertise `CHUNKING`.
- Convert frontend `DATA` body lines into raw message bytes before sending
  backend `BDAT` payloads.
- Preserve CRLF message line endings exactly as accepted by the frontend `DATA`
  reader.
- Remove SMTP/LMTP DATA dot-stuffing before bytes are written into backend
  `BDAT` chunks.
- Never forward the frontend DATA terminator line as backend message content.
- Send one or more backend `BDAT <size>` chunks followed by a final backend
  `BDAT <size> LAST` or `BDAT 0 LAST`.
- Read intermediate backend replies after non-final `BDAT` chunks and fail
  closed if a non-final chunk is rejected.
- Read final backend LMTP delivery replies after the `LAST` chunk, preserving
  one reply per accepted recipient in original recipient order.
- Keep upstream frontend responses compatible with ordinary LMTP `DATA`:
  frontend receives `354` before body transfer and final per-recipient statuses
  only after the DATA terminator has been consumed.
- Keep frontend `CHUNKING` advertisement independent from backend `CHUNKING`
  usage. Backend `BDAT` may be used even when the frontend listener does not
  advertise `CHUNKING`.
- Add deterministic tests for dot-unstuffing, CRLF preservation, empty bodies,
  multi-chunk bodies, backend chunk rejection and final per-recipient status
  mapping.
- Add observability labels or reason classes only when they remain bounded and
  compatible with the existing metric-label policy.

Out of scope:

- Requiring frontend clients to use `BDAT`.
- Advertising frontend `CHUNKING` merely because one backend supports
  `CHUNKING`.
- Advertising frontend `CHUNKING` unless listener configuration and frontend
  protocol policy allow it.
- DATA-to-BDAT conversion for non-LMTP protocols.
- Durable queueing, retry scheduling or bounce generation inside the director.
- Rewriting backend placement, active affinity, user placement holds or backend
  pin semantics.
- Adding a new global mail-size policy. Existing size and line limits remain
  authoritative unless a later spec changes them.
- Converting frontend `BDAT` to backend `DATA` in this follow-up.

## Protocol Semantics

### Frontend DATA, backend DATA fallback

When the selected backend does not advertise `CHUNKING`, behavior must remain
unchanged:

```text
LHLO frontend.example
MAIL FROM:<sender@example.org>
RCPT TO:<user@example.org>
DATA
354 2.0.0 Continue
...
.
250 2.1.5 user@example.org delivered
```

The director forwards backend `DATA`, preserves DATA dot-stuffing on the backend
DATA stream and terminates the backend DATA body with `.<CRLF>` before reading
final recipient statuses.

### Frontend DATA, backend BDAT

When the selected backend advertises `CHUNKING`, the director may deliver the
same frontend DATA body as backend BDAT:

```text
frontend: DATA
frontend: 354 2.0.0 Continue
frontend: <dot-stuffed DATA lines>
frontend: .

backend:  BDAT 65536
backend:  <raw message bytes>
backend:  250 2.0.0 chunk accepted
backend:  BDAT 123 LAST
backend:  <raw message bytes>
backend:  250 2.1.5 user@example.org delivered
```

The director must not expose the backend body transport choice to the frontend
client. From the frontend perspective this remains a normal LMTP DATA
transaction.

### Frontend BDAT, backend BDAT

Existing frontend `BDAT` forwarding remains valid only when the selected backend
advertises `CHUNKING`. If the backend does not advertise `CHUNKING`, the
director must not send backend `BDAT`. The implementation may reject the
transaction with a temporary failure. A future follow-up may define
BDAT-to-DATA conversion.

## Conversion Rules

The DATA-to-BDAT converter must treat the frontend DATA transfer encoding as a
wire encoding, not as message content.

Required rules:

- The DATA terminator line `.<CRLF>` ends the frontend body and is not forwarded.
- A DATA line beginning with two dots represents message content beginning with
  one dot.
- A DATA line beginning with one dot and no additional content is the terminator,
  not message content.
- All other bytes after DATA unstuffing are message content.
- The bytes written to backend BDAT are raw RFC 5322 message bytes as accepted by
  the director after DATA transfer decoding.
- CRLF preservation must be tested explicitly. The converter must not normalize
  line endings differently from the existing DATA sink behavior.

Examples:

```text
frontend DATA line:  hello<CRLF>
backend BDAT bytes:  hello<CRLF>

frontend DATA line:  ..hello<CRLF>
backend BDAT bytes:  .hello<CRLF>

frontend DATA line:  ..<CRLF>
backend BDAT bytes:  .<CRLF>
```

## Implementation Notes

The expected low-risk shape is to split the current backend DATA path into two
body writers:

```text
handleBackendDATA
  -> if backend supports CHUNKING: stream frontend DATA into backend BDAT writer
  -> else: existing backend DATA writer
```

The existing `backendDATABody` remains the fallback implementation. Add a new
backend BDAT body writer that implements the same DATA-line writing boundary
used by `streamDATA`:

```go
type backendBDATBody struct {
    transaction    *backendTransaction
    recipientCount int
    chunkSize      int
    buffer         []byte
}
```

The writer should accept DATA lines, unstuff them, append them to an internal
bounded buffer and flush backend BDAT payloads when the configured chunk size is
reached. The chunk size must be deterministic and bounded. A constant is enough
for the first implementation, for example 64 KiB or 256 KiB, unless an existing
configuration surface already defines an appropriate transfer chunk size.

Do not reuse `sendBDATChunk(reader io.Reader, chunk bdatCommand, ...)` for
DATA-to-BDAT payload writes. That helper is coupled to the frontend BDAT command
path and copies directly from the frontend reader. Add payload-oriented helpers
instead, for example:

```go
func (t *backendTransaction) sendBDATPayload(payload []byte) error
func (t *backendTransaction) finishBDATPayload(payload []byte, recipientCount int) MessageResult
```

or a single helper that accepts `last bool` and returns the appropriate
intermediate or final result. The helper must write:

```text
BDAT <len(payload)>[ LAST]<CRLF>
<payload bytes>
```

and flush before reading the expected backend reply.

## Error Handling

- If backend `CHUNKING` support is absent, fall back to backend DATA for frontend
  DATA transactions.
- If backend `CHUNKING` support is absent for frontend BDAT transactions, do not
  send backend BDAT. Return a temporary failure for the accepted recipients
  unless a future BDAT-to-DATA converter exists.
- If a non-final backend BDAT chunk returns a non-2xx status, abort/reset the
  backend transaction and return a temporary frontend delivery result for the
  accepted recipients.
- If the final backend BDAT reply set is incomplete, synthesize unknown temporary
  delivery statuses for the missing recipients, consistent with existing LMTP
  final-status handling.
- If frontend DATA reading fails after backend BDAT has begun, close the backend
  stream and reset the director transaction.
- If backend write or flush fails, close the backend stream and return unknown
  temporary delivery statuses.
- Do not emit partial success to the frontend until the frontend DATA terminator
  has been consumed and final backend statuses are available.

## Observability

The follow-up should preserve existing DATA and BDAT metric dimensions and avoid
unbounded labels.

Minimum useful observations:

- record that backend body transport was `data` or `bdat`;
- distinguish frontend operation `DATA` from backend transfer `BDAT` in logs or
  trace attributes without creating high-cardinality metric labels;
- keep existing result labels and reason classes for parser, protocol, backend
  connect, backend status and stream failures;
- never log message body bytes, bearer tokens, credentials or full recipient
  lists.

If no safe metric label shape exists, prefer trace/log annotations over new
metrics.

## Tests

Required tests:

1. Frontend DATA to backend DATA when backend does not advertise `CHUNKING`.
2. Frontend DATA to backend BDAT when backend advertises `CHUNKING`.
3. Frontend DATA to backend BDAT while frontend listener does not advertise
   `CHUNKING`.
4. Dot-stuffed line `..hello<CRLF>` becomes `.hello<CRLF>` in backend BDAT
   payload.
5. Dot-stuffed single-dot content `..<CRLF>` becomes `.<CRLF>` in backend BDAT
   payload.
6. DATA terminator `.<CRLF>` is not included in backend BDAT payload.
7. Empty DATA body sends a valid final `BDAT 0 LAST` or equivalent final empty
   payload.
8. Large DATA body is split into multiple backend BDAT chunks.
9. Non-final backend BDAT rejection resets the backend transaction and returns a
   safe temporary frontend result.
10. Final backend BDAT replies map one-to-one to accepted recipients in original
    recipient order.
11. Backend without `CHUNKING` never receives `BDAT` for frontend DATA.
12. Frontend BDAT is not forwarded as backend BDAT when backend `CHUNKING` is
    absent.

E2E or fake-lane tests should assert the actual backend wire transcript, not
only final frontend status codes.

## Documentation Updates

Update operator-facing documentation only where the behavior matters:

- LMTP feature notes should explain that frontend `CHUNKING` advertisement is a
  listener policy, while backend `CHUNKING` usage is selected per backend
  capability.
- Backend capability documentation should note that `CHUNKING` enables backend
  BDAT delivery for both frontend BDAT and frontend DATA transactions.
- The manpage should not expose a new configuration option unless the
  implementation adds one.
- Generated config references must be regenerated only if typed config changes
  are introduced.

## Acceptance Criteria

This follow-up is complete when:

- backend capability discovery gates all backend BDAT usage;
- frontend DATA can be delivered to CHUNKING-capable backends using backend
  BDAT;
- frontend DATA still falls back to backend DATA for non-CHUNKING backends;
- frontend CHUNKING advertisement is not required for backend BDAT usage;
- DATA dot-stuffing and CRLF preservation are covered by tests;
- final LMTP per-recipient status mapping is unchanged from the frontend
  client's perspective;
- backend BDAT failures fail closed with safe temporary delivery statuses;
- observability remains bounded and secret-safe;
- `make guardrails` or the documented deterministic proof target passes.
