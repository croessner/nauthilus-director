# M8 Listener Authority Context Follow-up

Status: completed.

This document defines a small post-M8 follow-up for listener-scoped authority
context forwarding. The feature lets one configured Director listener attach
explicit static request facts to its Nauthilus authority calls without changing
the public Nauthilus auth DTO, moving routing decisions into Nauthilus, or
forwarding arbitrary client-controlled data.

The follow-up is intentionally compact. The listener-to-authority binding
already exists, the HTTP and gRPC authority clients already have single transport
injection points, and the sibling Nauthilus repository already supports
allowlisted HTTP request headers and gRPC request metadata as policy facts.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/specs/implementation/M7_POP3_PROXY_SPEC.md`
- `docs/specs/implementation/M8_PRODUCTION_HARDENING_SPEC.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/man/nauthilus-director.yaml.5`
- sibling Nauthilus policy request-header and request-metadata contracts
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues. Nauthilus remains the authentication and identity
authority only. Backend selection, routing, affinity, session placement and
runtime mutation remain owned by `nauthilus-director`.

## Original Gap

Each listener currently selects its authority through `listener.authority`, and
the listener manager constructs one Nauthilus client for that selected authority.
That gives deployments a clean listener or realm boundary for authority
selection.

What is missing is a safe way for the listener to attach static deployment facts
to the authority request:

- HTTP authority calls currently send only the strict JSON auth body, content
  negotiation headers and configured caller authentication.
- gRPC authority calls currently attach only configured caller authentication
  metadata such as `authorization`.
- Operators cannot express a listener-specific realm, company, product tier,
  policy context or other non-secret deployment fact without either creating a
  separate Nauthilus authority endpoint or overloading an auth DTO field.
- Nauthilus can already expose allowlisted HTTP headers and gRPC metadata as
  normalized policy attributes, but Director does not yet have a matching
  static sender-side surface.

## Goal

Add listener-scoped static authority context forwarding for both Director
authority transports:

```yaml
director:
  listeners:
    imaps:
      protocol: imap
      authority: default
      authority_context:
        http_headers:
          X-Company-Domain: companyde
        grpc_metadata:
          x-company-domain: companyde
```

For HTTP authorities, the configured `http_headers` are added to the outbound
`/api/v1/auth/json` request after transport-owned headers are set and before the
request is sent.

For gRPC authorities, the configured `grpc_metadata` values are added to the
outgoing RPC context for `Authenticate`, `LookupIdentity` and `ListAccounts`
alongside caller authentication metadata.

Nauthilus can then opt in to those facts through its own policy allowlists, for
example:

```yaml
auth:
  policy:
    request_headers:
      - header: X-Company-Domain
        attribute: request.header.company_domain
        visibility: public
        normalize:
          trim: true
          case: lower
          max_length: 64
    request_metadata:
      - key: x-company-domain
        attribute: request.metadata.company_domain
        visibility: public
        normalize:
          trim: true
          case: lower
          max_length: 64
```

The values are deployment facts, not user credentials, routing authority, backend
selectors or secret-bearing fields.

## Delivery Shape

Implement this as a small M8 follow-up with four slices:

1. Typed listener config, defaults and validation for `authority_context`.
2. Shared authority-context propagation from listener setup into the HTTP and
   gRPC Nauthilus client adapters.
3. Focused unit and integration tests that prove HTTP headers and gRPC metadata
   are sent and that unsafe names fail closed.
4. Generated config reference, target config, manpage and architecture/spec
   reconciliation.

The implementation may be committed as one small change if the proof remains
focused. It is complete only when both HTTP and gRPC authority transports have
coverage and generated config documentation is fresh.

## Scope

In scope:

- Add `director.listeners.<name>.authority_context.http_headers`.
- Add `director.listeners.<name>.authority_context.grpc_metadata`.
- Keep the feature listener-scoped, not dynamically selected per username,
  tenant, SASL identity, client IP or routing result.
- Support scalar string values only for the first implementation.
- Expand environment placeholders in values through the normal scalar config
  expansion path; do not expand map keys.
- Trim names and values during normalization.
- Canonicalize HTTP header names for validation and sending.
- Require gRPC metadata keys to be lowercase ASCII keys accepted by gRPC
  metadata rules.
- Reject empty names and empty values.
- Reject credential, session and transport-owned names, including
  `authorization`, `proxy-authorization`, `cookie`, `set-cookie`,
  `content-type`, `accept`, `host`, `te` and `grpc-*`.
- Keep caller authentication authoritative for `Authorization` and
  `authorization`; listener context must never override or add caller
  credentials.
- Apply configured context to `Authenticate`, `LookupIdentity` and
  `ListAccounts`.
- Keep logs, metrics and traces from recording raw configured values.
- Add a bounded observability counter or reason only if it remains
  low-cardinality and does not expose values.
- Update generated config references and manpages when typed config changes.

Out of scope:

- Forwarding arbitrary inbound client headers or inbound gRPC metadata.
- Per-user, per-tenant, per-auth-result or per-route dynamic authority context.
- Secret-bearing context values, protected redaction metadata or `-P` exposure
  for these values.
- Extending the Nauthilus HTTP JSON body or gRPC protobuf request schema.
- Treating listener context as routing authority or backend selection input
  inside Director.
- Making Nauthilus policy automatically trust all received headers or metadata.
- Runtime REST or CLI mutation of `authority_context`.
- Supporting multi-value headers or metadata in the first implementation.

## Transport Semantics

HTTP authority calls:

- Use the existing strict JSON body unchanged.
- Set `Content-Type`, `Accept` and configured caller authentication exactly as
  today.
- Add safe listener `http_headers` without overriding transport-owned or
  caller-auth headers.
- Send the same context headers for authentication, identity lookup and
  list-accounts operations.

gRPC authority calls:

- Use the existing protobuf request messages unchanged.
- Preserve existing caller-auth metadata behavior.
- Append safe listener `grpc_metadata` to the outgoing RPC context before
  invoking the generated AuthService client.
- Send the same context metadata for `Authenticate`, `LookupIdentity` and
  `ListAccounts`.

When validation rejects any configured header or metadata key, startup must fail
closed with a path-specific config error. Partial forwarding is not allowed.

## Nauthilus Compatibility

The sibling Nauthilus implementation already has the receiving side needed for
this feature:

- `auth.policy.request_headers` maps allowlisted HTTP request headers to
  `request.header.*` policy attributes.
- `auth.policy.request_metadata` maps allowlisted gRPC metadata keys to
  `request.metadata.*` policy attributes.
- Nauthilus rejects unsafe names such as authorization, proxy-authorization,
  cookie and set-cookie in those policy allowlists.
- gRPC AuthService handlers copy incoming metadata into auth input context
  before policy evaluation.

Director tests should still use fake authorities for deterministic proof, but
the implementation review must re-check these sibling Nauthilus contracts before
closing the follow-up.

## Required Tests

Unit tests:

- Config validation accepts safe HTTP header and gRPC metadata names.
- Config validation rejects unsafe, empty, uppercase gRPC metadata and
  transport-owned names.
- Normalization trims names and values and canonicalizes HTTP header names.
- HTTP authority client sends configured context headers on auth, lookup and
  list-accounts requests.
- HTTP authority client does not override `Authorization`, `Content-Type` or
  `Accept`.
- gRPC authority client sends configured metadata on auth, lookup and
  list-accounts requests.
- gRPC authority client preserves caller-auth metadata and rejects any attempt to
  replace it through listener context.

Integration or E2E tests:

- A fake HTTP Nauthilus authority records a configured listener context header
  during public protocol authentication.
- A fake gRPC Nauthilus authority records configured listener metadata during
  public protocol authentication.
- Secret sentinel values are absent from logs, metrics and traces.

Documentation checks:

- Run `make generate-docs` after typed config/default changes.
- Run `make check-docs`.
- Run focused package tests while iterating.
- Run `make guardrails` before commit or pull request.

## Acceptance Criteria

- Operators can configure safe static listener authority context for HTTP and
  gRPC authority transports.
- HTTP headers and gRPC metadata reach the selected listener's configured
  authority for all authority operations.
- Caller-auth headers and metadata cannot be configured, overridden or leaked
  through this feature.
- Nauthilus can consume the values through explicit policy allowlists without a
  Director-side DTO or protobuf change.
- Existing configs without `authority_context` keep current behavior.
- Generated config references, target config and manpage text are aligned with
  the typed config model.
- Focused tests plus final guardrails prove the change.

## Completion Evidence

Closeout date: 2026-06-08.

Implemented surface:

- Typed listener config exposes `authority_context.http_headers` and
  `authority_context.grpc_metadata` as empty default maps for every supported
  listener.
- Config loading expands scalar context values only, leaves map keys literal,
  trims and normalizes configured values, canonicalizes HTTP header names and
  rejects invalid, empty, credential, session and transport-owned names.
- Listener setup passes the selected listener context into the Nauthilus client
  factory, keeping the feature listener-scoped even when listeners share the
  same configured authority.
- HTTP authority calls add safe configured context headers without overriding
  caller authentication, `Content-Type` or `Accept`.
- gRPC authority calls add safe configured context metadata to `Authenticate`,
  `LookupIdentity` and `ListAccounts` while preserving caller-auth metadata.
- Public fake-authority E2E proves configured HTTP headers and gRPC metadata
  arrive through protocol authentication boundaries and that context sentinel
  values stay out of process output, route lookup output and CLI output.

Nauthilus compatibility recheck:

- `/Users/croessner/GoLandProjects/nauthilus/server/policy/compiler/request_attributes.go`
  still defines `auth.policy.request_headers` and
  `auth.policy.request_metadata`, maps them to `request.header.*` and
  `request.metadata.*`, and rejects unsafe source names such as
  `authorization`, `proxy-authorization`, `cookie` and `set-cookie`.
- `/Users/croessner/GoLandProjects/nauthilus/server/core/policy_request_attributes.go`
  still records only explicitly configured request header and request metadata
  attributes into the policy decision context after normalization.
- `/Users/croessner/GoLandProjects/nauthilus/server/handler/grpcauthority/handler.go`
  still copies incoming gRPC metadata into auth input context for
  `Authenticate`, `LookupIdentity` and `ListAccounts` before policy
  evaluation.
- `/Users/croessner/GoLandProjects/nauthilus/server/docs/policy-layer/nauthilus_policy_decision_layer_cr_response_message_i18n.md`
  still documents that non-standard HTTP headers and gRPC metadata are exposed
  to policy only through explicit allowlists.

Validation evidence:

- `make generate-docs`: passed and refreshed generated config references.
- `make check-docs`: passed.
- `make test`: passed.
- `make race`: passed.
- `make e2e`: passed.
- `make build-check`: passed.
- `make guardrails`: passed.
- `git diff --check`: passed.

## Review und Ist/Soll-Abgleich

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Config docs | Defaults, paths, target config and manpage are current | Generated defaults and paths include empty authority-context maps, target YAML carries a safe static example and the YAML manpage documents allowlisted Nauthilus consumption | OK | Context values are documented as deployment facts, not secrets or routing input |
| Spec closeout | Follow-up status/evidence matches implemented proof | This spec is marked completed with implementation, Nauthilus compatibility and validation evidence | OK | Completion relies on public HTTP and gRPC fake-authority E2E plus final guardrails |
| Architecture | Roadmap updated only if supported and expected | The M8 roadmap entry mirrors this completed follow-up and points back to this spec | OK | Matches the repo style used for comparable completed follow-ups |
| Nauthilus contract | HTTP headers and gRPC metadata compatibility re-verified | Sibling Nauthilus files still require explicit `auth.policy.request_headers` and `auth.policy.request_metadata` allowlists and copy gRPC metadata into auth input | OK | Director does not extend Nauthilus DTOs or protobuf messages |
| Public proof | HTTP and gRPC context proven through public boundaries | Fake-service E2E proves HTTP header and gRPC metadata arrival during public protocol authentication | OK | Secret sentinels are asserted absent from relevant outputs |
| Security | No caller-auth override, no raw values exposed | Validation rejects reserved names; client code does not override caller auth or transport headers; tests assert secret-safe errors and output | OK | No inbound client header forwarding is implemented or documented |
| Guardrails | Final repository gate run or blocker documented | `make guardrails` passed after docs generation and focused gates | OK | `git diff --check` also passed |
