# M5 LMTP Plaintext and Capability Follow-up

Status: completed. Auth-free plaintext LMTP frontend listeners, plaintext
`auth.mode: none` LMTP backend hops, frontend `ENHANCEDSTATUSCODES`,
backend-mediated `8BITMIME`, `BODY=8BITMIME` parsing, current-session gating
and backend `MAIL FROM` forwarding are implemented and publicly proven. The
default generated LMTP listeners remain TLS-authenticated and conservative.

This follow-up closes two LMTP gaps found after the M5 production rollout:

1. LMTP must support common deployment topologies where the frontend or backend
   LMTP hop is plaintext because no credential-bearing authentication happens on
   that hop.
2. LMTP capability advertisement must cover the Director's implemented behavior
   more truthfully without becoming a blind mirror of Dovecot or any other
   backend.

The goal is not to weaken the default security posture. Credential-bearing
frontend `AUTH` and backend service credentials still require an encrypted and
verified transport before secrets leave the Director process.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M5_BACKEND_PROXY_PROTOCOL_FOLLOWUP.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `test/e2e/README.md`
- `test/e2e/interop/README.md`
- `Makefile`

If this document conflicts with older LMTP wording, this follow-up is the
specific source of truth for plaintext LMTP without auth and the additional
capability work.

## Starting State

Before this follow-up, the implementation already had several pieces of the
desired behavior:

- LMTP backend connections support `disabled`, `plaintext`, `starttls` and
  `implicit` TLS modes in `internal/protocol/lmtp/backend.go`.
- Backend auth is fail-closed in `internal/protocol/lmtp/backend_auth.go`:
  `sasl` and `oauthbearer` can require verified TLS, while `auth.mode: none`
  sends no backend credentials.
- Frontend credential auth is already protected in
  `internal/protocol/lmtp/auth.go`: `AUTH` is not advertised until TLS is active,
  and plaintext AUTH fails locally before Nauthilus is called.
- Frontend listener TLS validation accepted only `starttls` and `implicit` in
  `internal/config/validate.go` and `internal/listener/tcp.go`.
  That blocks intentionally plaintext LMTP listeners even when
  `lmtp.client_auth.required` is false and no `AUTH` capability is configured.
- `CHUNKING` and `BDAT` are implemented, but `CHUNKING` is advertised only when
  it is configured on the listener and fresh backend-pool capability proof says
  the selected pool supports it.
- `ENHANCEDSTATUSCODES` is parsed as a known backend LHLO keyword, and frontend
  responses already use enhanced status codes, but the listener config
  validation does not currently allow the frontend capability.
- `8BITMIME` is parsed as a known backend LHLO keyword, but the frontend parser
  rejected `MAIL FROM ... BODY=8BITMIME` as an unsupported MAIL parameter.

## Target Behavior

### Plaintext LMTP Without Auth

The Director must allow plaintext LMTP only when the configured hop does not
send or accept credential-bearing authentication on that hop.

Frontend listener rules:

- Extend listener TLS mode validation and listener startup to accept
  `plaintext`, `disabled` and `none` as non-TLS frontend modes.
- Normalize those aliases to one runtime meaning: no implicit TLS wrapping, no
  STARTTLS command, and `ssl=false` in the Nauthilus context if a request is
  ever made.
- For plaintext LMTP listeners, validation must reject `STARTTLS` in
  `director.listeners.<name>.lmtp.capabilities`.
- For plaintext LMTP listeners, validation must reject `AUTH ...` capability
  lines, non-empty `lmtp.client_auth.mechanisms`, and
  `lmtp.client_auth.required: true` unless a later spec introduces a
  non-credential, non-TLS peer-auth mechanism.
- For plaintext LMTP listeners, `MAIL FROM`, `RCPT TO`, `DATA`, `BDAT`, `RSET`,
  `NOOP`, `QUIT` and recipient identity lookup remain available according to
  the normal LMTP transaction rules.
- If an invalid plaintext config nevertheless reaches runtime, `AUTH` must stay
  hidden and rejected before any Nauthilus credential or bearer path is called.

Backend rules:

- Keep the existing backend TLS modes `disabled`, `none`, `plaintext`,
  `starttls` and `implicit`.
- `director.backends.<backend>.tls.mode: plaintext` is valid for LMTP when
  `auth.mode: none`.
- `auth.mode: sasl` or `oauthbearer` may use plaintext only when the matching
  explicit `require_tls` field is false. The safer default remains true.
- `auth.mode: mtls` always requires verified backend TLS and configured backend
  client certificate material.
- Health checks must exercise the same plaintext/TLS/auth combination as real
  sessions.

Defaults:

- Keep generated defaults secure and conservative: public LMTP defaults may stay
  `starttls`/`implicit` with auth enabled.
- Documentation and examples may show an explicit auth-free plaintext LMTP
  profile for trusted internal delivery networks.

### Capability Policy

The Director must advertise only capabilities that are configured, implemented,
and safe for the current session. It must not mirror backend capabilities
blindly.

Supported frontend LMTP capabilities after this follow-up:

- `STARTTLS`: only on `tls.mode: starttls` before TLS is active.
- `AUTH ...`: only after frontend TLS is active and only for configured
  mechanisms.
- `SMTPUTF8`: as implemented by M5.
- `CHUNKING`: only when configured, `BDAT` is implemented, and fresh backend
  pool capability proof includes `CHUNKING`.
- `ENHANCEDSTATUSCODES`: allowed in listener config and advertised when
  configured. Because the Director already emits enhanced status codes, the
  generated default LMTP capabilities should include it to make the wire surface
  truthful.
- `8BITMIME`: allowed only after the frontend parser and backend forwarding
  support `BODY=8BITMIME`; advertise it only when configured and fresh backend
  pool capability proof includes `8BITMIME`.

Capabilities that remain unsupported must still fail validation. In particular,
do not advertise `BINARYMIME`, `PIPELINING`, `SIZE`, `DSN`, `VRFY`, `EXPN` or
other SMTP/LMTP extensions until the Director owns the exact frontend parsing,
backend forwarding, failure behavior, tests and documentation.

## Implementation Plan

### 1. Frontend Plaintext TLS Mode

- Extend shared listener TLS validation to accept `plaintext`, `disabled` and
  `none`.
- Adjust the TCP listener lifecycle so those modes skip TLS wrapping and do not
  require certificate/key material.
- Keep `starttls` and `implicit` behavior unchanged for IMAP, LMTP, POP3 and
  ManageSieve unless protocol-specific validation forbids plaintext.
- Add LMTP-specific validation that plaintext is allowed only without frontend
  auth requirements or AUTH advertisement.
- Keep credential-bearing auth fail-closed at runtime even if validation is
  bypassed.

Expected files:

```text
internal/config/validate.go
internal/listener/tcp.go
internal/protocol/lmtp/auth.go
internal/protocol/lmtp/session.go
internal/config/config_test.go
internal/listener/tcp_test.go
internal/protocol/lmtp/session_test.go
```

### 2. Backend Plaintext No-Auth Documentation

- Preserve the existing LMTP backend connector behavior for plaintext and
  disabled modes.
- Add or tighten validation tests that prove plaintext LMTP backend config is
  accepted with `auth.mode: none`.
- Add validation tests that prove plaintext backend config is rejected when
  configured backend auth still requires verified TLS.
- Document the operational distinction between plaintext without auth and
  plaintext with credentials.

Expected files:

```text
internal/config/config_test.go
docs/config/nauthilus-director.target.yml
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
docs/man/nauthilus-director.yaml.5
```

### 3. ENHANCEDSTATUSCODES

- Add an LMTP capability constant for `ENHANCEDSTATUSCODES`.
- Allow and normalize `ENHANCEDSTATUSCODES` in
  `director.listeners.<name>.lmtp.capabilities`.
- Return `ENHANCEDSTATUSCODES` from `Session.effectiveCapability` when it is
  configured.
- Add it to the generated default LMTP and LMTPS capability lists so the
  current enhanced response format is truthfully advertised.
- Add unit tests for config acceptance, LHLO rendering and duplicate
  normalization.

Expected files:

```text
internal/protocol/lmtp/session.go
internal/config/validate.go
internal/config/defaults.go
internal/config/config_test.go
internal/protocol/lmtp/session_test.go
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
```

### 4. 8BITMIME

- Add an LMTP capability constant for `8BITMIME`.
- Generalize backend-pool capability mediation so LMTP can check fresh support
  for both `CHUNKING` and `8BITMIME` without duplicating one helper per
  capability.
- Extend `mailCommand` parsing to accept a normalized `BODY=8BITMIME` MAIL
  parameter.
- Reject `BODY=8BITMIME` unless `8BITMIME` was advertised in the current LHLO
  response.
- Preserve opaque message-body handling. The Director must not inspect, rewrite
  or downgrade message content.
- Forward `BODY=8BITMIME` to the selected backend only when the frontend
  accepted the parameter and the backend path is proven to support `8BITMIME`.
- Keep `BODY=BINARYMIME`, `BODY=7BIT` without advertised `8BITMIME`, duplicate
  `BODY` parameters and unknown MAIL parameters fail-closed unless a later
  explicit compatibility decision says otherwise.
- Add tests that prove `8BITMIME` is not advertised on stale, missing or mixed
  backend capability data.

Expected files:

```text
internal/app/server.go
internal/protocol/lmtp/parser.go
internal/protocol/lmtp/commands.go
internal/protocol/lmtp/transaction.go
internal/protocol/lmtp/session.go
internal/protocol/lmtp/session_test.go
internal/protocol/lmtp/backend_test.go
internal/config/validate.go
internal/config/config_test.go
test/e2e/lmtp_fake_lane_test.go
test/e2e/interop_lmtp_test.go
```

### 5. CHUNKING Configuration Reconciliation

- Do not reimplement `BDAT`; M5 already owns the parser, streaming path and
  backend forwarding.
- Ensure deployment examples that are meant to expose `BDAT` include
  `CHUNKING` in listener capabilities.
- Keep runtime advertisement mediated by fresh backend-pool capability proof.
- Do not add `CHUNKING` solely because a backend transcript contains it.

Expected files:

```text
docs/config/nauthilus-director.target.yml
docs/reference/config-defaults.yaml
docs/reference/config-paths.md
test/e2e/interop/README.md
```

## Acceptance Criteria

- A plaintext LMTP listener with `client_auth.required: false`, no AUTH
  capability and no client-auth mechanisms starts successfully and accepts
  unauthenticated LMTP delivery transactions.
- The same plaintext listener rejects `AUTH` locally and does not call
  Nauthilus credential or bearer auth.
- A plaintext LMTP listener config that enables AUTH or required client auth
  fails validation.
- A plaintext LMTP backend with `auth.mode: none` validates and can be used by
  LMTP delivery and health checks.
- A plaintext LMTP backend with SASL, OAuth bearer or mTLS requirements fails
  validation unless the explicit auth policy allows it and no secret-bearing
  material is sent against policy.
- `ENHANCEDSTATUSCODES` is accepted in LMTP listener capabilities and appears in
  LHLO when configured.
- `8BITMIME` is accepted in LMTP listener capabilities only after the parser,
  session gate, backend forwarding and backend capability mediation are in
  place.
- `MAIL FROM ... BODY=8BITMIME` succeeds only when `8BITMIME` was advertised and
  the selected backend path is proven to support it.
- `MAIL FROM ... BODY=8BITMIME` fails closed without leaking sender, recipient
  or message content when `8BITMIME` is omitted, stale or backend-unsafe.
- `CHUNKING` remains advertised only when configured and backed by fresh backend
  capability proof.
- No new metric label includes username, user hash, recipient, session ID, trace
  ID, request ID, client IP, raw backend identifier, raw error text or
  secret-bearing values.

## Required Validation

Run the focused package tests during development:

```text
go test ./internal/config ./internal/listener ./internal/app ./internal/protocol/lmtp
```

Before closeout or PR, run the project gate:

```text
make generate-docs
make check-docs
make test
make race
make e2e
make build-check
make guardrails
```

If generated OpenAPI surfaces are not touched, `make generate-openapi` and
`make check-openapi` are not required for this follow-up. If route lookup,
REST/CLI diagnostics or generated DTOs change, add them back to the validation
set.

## Completion Evidence

Follow-up closeout completed on 2026-06-10 after implementation, public proof,
generated-doc reconciliation and the final review pass. The implementation adds
the safe frontend plaintext TLS-mode normalization, LMTP-specific validation
that keeps plaintext listeners auth-free, backend plaintext/no-auth validation,
frontend capability normalization for `ENHANCEDSTATUSCODES` and `8BITMIME`,
`BODY=8BITMIME` MAIL parsing, current-session advertisement gating and
deterministic backend forwarding of accepted `BODY=8BITMIME`.

The deterministic fake-service E2E lane now proves the follow-up through the
production `nauthilus-director` binary, public LMTP sockets, fake Nauthilus
HTTP authority sockets, fake LMTP backend sockets and Redis-compatible runtime
state. The public tests cover an auth-free plaintext LMTP listener that omits
`STARTTLS` and `AUTH`, rejects plaintext `AUTH` locally without a Nauthilus
credential or bearer call, performs normal no-auth recipient identity lookup,
delivers through a plaintext `auth.mode: none` backend, advertises
`ENHANCEDSTATUSCODES` when configured, suppresses `CHUNKING` and `8BITMIME`
without fresh backend proof, advertises `8BITMIME` only with configured and
fresh backend support, accepts `MAIL FROM ... BODY=8BITMIME` only after current
session advertisement and forwards that parameter to the backend.

Existing `CHUNKING` and `BDAT` proof remains intact in the same public E2E
lane. The Docker-capable interop lane passed with real Dovecot LMTP backends,
real Postfix submission, `CHUNKING`/`BDAT` and `BODY=8BITMIME` on the LMTP
delivery path, plus IMAP retrieval of the delivered marker.

Validation run for this closeout:

```text
go test -mod=vendor ./internal/config ./internal/listener ./internal/app ./internal/protocol/lmtp ./test/e2e/fakes/lmtp_backend
make generate-docs
make check-docs
make test
make race
make e2e
make build-check
make e2e-interop
make guardrails
```

OpenAPI generation/checks were not run for this follow-up because no REST,
CLI diagnostic, route-lookup or generated DTO contract changed.

## Non-Goals

- Do not make plaintext the generated default for public LMTP listeners.
- Do not allow plaintext credential auth by accident.
- Do not call Nauthilus credential auth before TLS for LMTP.
- Do not treat backend capabilities as frontend truth without Director-owned
  parser, forwarding and tests.
- Do not implement `BINARYMIME`, `PIPELINING`, `SIZE`, DSN, queueing, message
  content inspection, downgrading or re-encoding.
- Do not translate frontend `BDAT` to backend `DATA`.
- Do not use Dovecot-specific behavior as a generic product contract.
