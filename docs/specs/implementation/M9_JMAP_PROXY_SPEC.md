# M9 JMAP Proxy Specification

Status: completed.

This document records the JMAP milestone for `nauthilus-director`. M9 adds a
production JMAP-to-JMAP HTTPS reverse proxy: a `protocol: jmap` listener that
authenticates every HTTP request through Nauthilus, routes it strictly by the
authenticated account with fail-closed shard resolution, holds shared
placement state for the request or event-stream lifetime and forwards it
unchanged to the selected JMAP backend over a connection that belongs to one
frontend client and carries that client's address in a PROXY v2 header.

M9 builds on the completed M0–M8 baseline, in particular the shared placement
service, backend-node affinity, user placement holds, protocol-scoped backend
pins, the outbound backend PROXY transport and the SASL bearer introspection
client. It replaces the former future design note, whose rules it keeps: no
protocol translation, no mailbox semantics, no JMAP method interpretation and
no cross-shard aggregation in the director.

## Source Documents

M9 is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`, sections 13a and M9
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_BACKEND_PROXY_PROTOCOL_FOLLOWUP.md`
- `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`
- `docs/specs/implementation/M8_MULTI_PROTOCOL_BACKEND_PINNING_FOLLOWUP.md`
- `docs/specs/implementation/M8_SASL_BEARER_INTROSPECTION_FOLLOWUP.md`
- `docs/specs/implementation/M8_RUNTIME_SESSION_HOLDER_CONTROL_FOLLOWUP.md`
- RFC 8620 (JMAP core), RFC 8621 (JMAP mail), RFC 6750 (Bearer), RFC 7662
  (introspection), RFC 8707 (resource indicators)

Operator documentation: `docs/operations/jmap.md` and the section "JMAP
LISTENERS AND BACKENDS" in `docs/man/nauthilus-director.yaml.5`.

## M9 Goal

A JMAP client that reaches the director's public name is served by the backend
that owns its mailbox, with the same placement guarantees the mail protocols
have, while the backend keeps full authority over JMAP semantics and verifies
every request itself.

## Scope

In scope:

- `protocol: jmap` listeners, backend pools and backends in the typed config,
  with fail-closed validation.
- An HTTP/1.1 server per JMAP listener fed by the existing accept path
  (inbound PROXY from trusted CIDRs, implicit TLS, drain, resume, stop).
- The proxied surface `/.well-known/jmap`, `/jmap/api/`, `/jmap/upload/…`,
  `/jmap/download/…` and `/jmap/eventsource/`.
- Per-request Basic and Bearer authentication and a bounded success cache.
- Fail-closed routing by the authenticated account.
- Request holds and event-stream session leases through the shared placement
  service, including kick, drain and move handling.
- Per-frontend-connection backend transports with PROXY v2 and verified TLS.
- HTTPS backend health probes, bounded metrics and secret-safe events.

Out of scope:

- JMAP over WebSocket (RFC 8887); upgrade requests are refused.
- CORS handling for cross-origin browser clients.
- JMAP session resource rewriting.
- Push subscription delivery, JMAP method inspection, protocol translation.
- A JMAP trace span; JMAP is observable through events and metrics.
- A default JMAP listener.

## Stable Config Paths

```text
director.listeners.<name>.protocol: jmap
director.listeners.<name>.jmap.public_base_url
director.listeners.<name>.jmap.health_path
director.listeners.<name>.jmap.auth.realm
director.listeners.<name>.jmap.auth.basic.enabled
director.listeners.<name>.jmap.auth.bearer.enabled
director.listeners.<name>.jmap.auth.bearer.required_audience
director.listeners.<name>.jmap.auth.bearer.required_resource
director.listeners.<name>.jmap.auth.bearer.required_scope
director.listeners.<name>.jmap.auth.bearer.account_claim
director.listeners.<name>.jmap.auth.bearer.introspection_client.client_id
director.listeners.<name>.jmap.auth.bearer.introspection_client.auth_method
director.listeners.<name>.jmap.auth.bearer.introspection_client.client_secret_file
director.listeners.<name>.jmap.auth.bearer.introspection_client.client_private_key_file
director.listeners.<name>.jmap.auth.bearer.introspection_client.client_key_id
director.listeners.<name>.jmap.auth.bearer.introspection_client.client_assertion_alg
director.listeners.<name>.jmap.auth.cache.ttl
director.listeners.<name>.jmap.auth.cache.max_entries
director.listeners.<name>.jmap.routing.missing_shard
director.listeners.<name>.jmap.limits.max_header_bytes
director.listeners.<name>.jmap.limits.max_request_body_bytes
director.listeners.<name>.jmap.limits.max_upload_body_bytes
director.listeners.<name>.jmap.timeouts.read_header
director.listeners.<name>.jmap.timeouts.read
director.listeners.<name>.jmap.timeouts.idle
director.listeners.<name>.jmap.timeouts.backend_response_header
director.listeners.<name>.jmap.placement.request_lease_ttl
director.listeners.<name>.jmap.event_source.heartbeat_interval
director.backend_pools.<name>.protocol: jmap
director.backends.<name>.protocol: jmap
```

Defaults are applied by normalization, so `jmap: {}` is valid: Basic on,
Bearer off, realm `jmap`, cache 30s/10000, `missing_shard: forbidden`, limits
64 KiB/10 MiB/50 MiB, timeouts 10s/10m/2m/2m, request lease 2m, heartbeat 30s.
Because no default JMAP listener exists, these paths are not rows of the
generated `docs/reference/config-paths.md`; the generated file points to the
manual page instead.

Validation refuses: a JMAP listener without implicit TLS, without any enabled
scheme, with Basic on an authority without the password mechanism, with Bearer
on an authority without introspection, with Bearer but without a token binding
or scope, with a secret-bearing account claim, with a dedicated introspection
client whose credentials do not match its `auth_method` or with client
credentials but no `client_id`; a cache TTL above 10m; non-positive limits or
timeouts; a `health_path` overlapping the proxied paths; a non-HTTPS
`public_base_url`; JMAP subtrees on other listeners; JMAP pools with a selector
other than `rendezvous_hash`; JMAP backends without implicit TLS, with an auth
mode other than `none` or with `deep_check`.

## Package Boundaries

- `internal/protocol/jmap`: handler and HTTP server lifecycle, endpoint
  policy, authentication and cache, routing and placement, reverse proxy,
  backend transports, event-stream supervision, health checker, observability.
- `internal/listener`: `protocol: jmap` dispatch, ALPN `http/1.1`, bounded TLS
  handshake for JMAP listeners, the optional `AcceptStateObserver` and
  `ClosingHandler` handler interfaces, the listener-owned bearer policy.
- `internal/config`: typed JMAP config, normalization, validation and the
  startup readability check for introspection client material.
- `internal/placement`: `PlaceRequestHold` for request-scoped holders.
- `internal/backend`: `jmap` in selector and health allowlists, the outbound
  PROXY version field (v2 for JMAP, v1 unchanged for mail protocols) and the
  shared backend client TLS builder.
- `internal/observability`: `jmap.request` and `jmap.session_url` events and
  the JMAP request metric families.
- `internal/app`: handler wiring and the JMAP health checker.

## Behaviour

### Listener and Transport

The generic listener accepts, applies inbound PROXY and implicit TLS, then
hands the `*tls.Conn` to the JMAP handler, which delivers it to an in-process
`http.Server` and blocks until the server closes it, so session accounting,
drain and hard drain stay exact. The TLS handshake is bounded by
`timeouts.read_header` (mail listeners keep their previous behavior). There is
no write timeout. When the listener stops accepting, keep-alive is disabled and
idle connections close; when it stops or a reload removes it, the handler's
HTTP server and accept loop are closed. A later start creates a fresh server.

### Request Admission

Paths must be canonical and match the allowlist, and upload and download paths
need a segment after their prefix. Methods are endpoint-specific (GET/HEAD for
session and download, POST for API and upload, GET for the event source);
others, including `OPTIONS`, get 405 with `Allow`. Requests carrying `Upgrade`
get 400. A declared body above the endpoint limit gets 413 before
authentication; a streamed body is cut at the limit and answered 413. A
configured `health_path` answers 200 locally.

### Authentication

Exactly one `Authorization` header with scheme Basic or Bearer is accepted.
Basic credentials go to `Authenticate` with protocol `jmap`, method `plain`.
Bearer tokens must match the RFC 6750 b64token syntax and the authority token
size bound; they are introspected with the listener policy and then resolved
with `LookupIdentity` (protocol `jmap`, method `recipient_lookup`). The
canonical account and routing attributes come from the authority result.
Missing, malformed or rejected credentials get 401 with Basic and/or Bearer
challenges (`error="invalid_token"` only for a refused Bearer token);
authority failures get 503 with `Retry-After`. Successful principals are cached
under `HMAC-SHA-256(per-process key, scheme ‖ username ‖ secret ‖ client IP)`,
bounded by TTL and LRU size; failures are never cached.

### Routing

The shared resolver chain is used. A result whose source is the hash fallback
is treated as a missing shard unless `missing_shard: hash_fallback`; missing
shards get 403 (default) or 503, ambiguous routing facts and routing errors get
503. Account identifiers in request paths are never routing input.

### Placement

The placement key is the tenant plus the lower-cased canonical account.
Ordinary requests call `PlaceRequestHold` (non-session holder kind, no
capacity reservation) with `request_lease_ttl`; a request running longer than
half the TTL refreshes the hold every half TTL until it ends. Event streams
call `PlaceSession` with the session lease TTL, register a local session
handle and heartbeat at `heartbeat_interval` (at most half the lease TTL);
a non-`none` control action, a failed heartbeat or a local close ends the
stream. Holds are closed with a detached bounded context after the response.

### Forwarding

`httputil.ReverseProxy` with `Rewrite` points the request at the backend,
keeps `Host`, path, raw path and query as sent, removes `Connection`,
`Upgrade`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `X-Client-IP` and
`True-Client-IP`, and forwards `Authorization` unchanged. The transport is
chosen from the frontend connection's own set; each backend connection writes
the PROXY v2 header for that client and completes verified TLS. HTTP/2,
response decompression and environment proxies are disabled. Event streams are
flushed immediately. Backend errors map to 502, timeouts to 504 and body limit
violations to 413.

### Health and Observability

JMAP backends are probed with `GET /jmap/healthz` over a health-purpose
connection (PROXY header from the director's own socket addresses when
enabled). Each request emits one `jmap.request` event and the metric families
`nauthilus_director_jmap_requests_total` and
`nauthilus_director_jmap_request_duration_seconds` with bounded labels.

## Security

- Every request is authenticated; the backend verifies it again.
- Credentials, tokens, `Authorization` headers, account names and request
  paths never appear in logs, metrics or error bodies.
- The cache stores no credential or reusable digest and never stores failures.
- Routing fails closed on a missing shard by default.
- Client address headers cannot be forged towards the backend; the address
  travels only in the PROXY header of a connection owned by that client.
- Introspection client secrets are file paths only, redacted in dumps and
  checked for readability at listener start with path-free errors.
- Protocol upgrades are refused and never forwarded.

## Tests and Evidence

Unit and package tests (all run under `make test` and `make race`):

- `internal/config/jmap_test.go`: defaults, unsafe policy table, backend
  rules, YAML decoding, bearer policy replacement, dedicated introspection
  client override, validation and startup material check, target config.
- `internal/listener/jmap_test.go`: listener bearer policy and dedicated
  client (IMAP keeps the authority client), ALPN `http/1.1`, accept-state
  notifications, handler close on stop and reload removal, bounded TLS
  handshake, unreadable secret failing startup without the path.
- `internal/protocol/jmap/handler_test.go`: Basic proxying with header
  stripping, authentication failures and challenges, Bearer introspection plus
  lookup routing, missing-shard policies, path and method allowlist, body
  limits, download ranges and security headers, two clients never sharing a
  backend connection, event-stream kick and heartbeat control action, streams
  outliving the read timeout, cache behavior, session URL mismatch, drain
  closing idle connections, upgrade refusal, upgrade header stripping in the
  rewrite, request-hold heartbeat on slow requests, handler close and restart.
- `internal/protocol/jmap/unit_test.go`: endpoint classification, body limits,
  cache expiry/eviction/key separation, credential parsing and b64token
  syntax, Bearer-only `invalid_token`, session origin comparison, health
  checker against a PROXY-only backend.
- `internal/backend`: PROXY v2 rendering and version validation, client TLS
  builder. `internal/placement`: request holds reuse active bindings without
  capacity. `internal/observability`: bounded JMAP metrics. `internal/app`:
  dispatch and health-checker routing.

E2E (`make e2e`, real server binary, Valkey, fake Nauthilus HTTP authority
with password, no-auth lookup and introspection endpoints, two fake JMAP
backends under `test/e2e/fakes/jmap_backend/` requiring PROXY):

- `TestServerBinaryPublicJMAPProxyFlow`: inbound PROXY v2 client addresses
  reaching the backend through outbound PROXY v2, Basic session and API
  requests, connection isolation between two clients, Bearer routing through
  lookup attributes with the dedicated introspection client, a foreign
  resource token refused, missing-shard 403, missing and wrong credentials,
  path allowlist and local health path, an event stream ended by
  `nauthilus-directorctl users kick` and removed from the session inventory,
  HTTPS health probes on both backends, bounded metrics and no credential or
  secret in the process output.

Final validation: `make guardrails` passed on the tree of each implementation commit (for `c1e0a98` before a whitespace-only `go fix` follow-up, re-checked with lint and the JMAP race tests).
Commits: `bbd56bc`, `e28fb64`, `5d56189`, `c1e0a98`; released as `v1.1.0`.

## Review Fixes

An external review of the first implementation found no blocker. The follow-up
commit `5d56189` fixed:

- Upgrade passthrough: `ReverseProxy` re-adds `Connection`/`Upgrade` before
  `Rewrite`; requests with `Upgrade` are now refused and both headers are
  stripped when forwarding.
- Leaked HTTP servers: the per-listener server and accept loop are now closed
  through `ClosingHandler` on stop and reload removal.
- Request holds on long requests: holds are heartbeated every half TTL instead
  of lapsing under long uploads or downloads.
- Documentation: `OPTIONS` answers 405, upload paths need an account segment,
  operating costs (about three Redis round trips per request).
- Nits: exact b64token syntax, `invalid_token` only for Bearer, sub-second
  histogram buckets, a comment on the raw path passthrough.

## Introspection Client Follow-up

Commit `c1e0a98` lets a JMAP listener carry its own introspection client
(`jmap.auth.bearer.introspection_client`) so JMAP tokens are not introspected
with the credentials of another application's client. The client replaces the
authority's introspection client credentials for that listener only, keeps the
authority's endpoint and leaves IMAP, POP3 and ManageSieve on the authority
client; an empty `client_id` inherits. Secrets are file paths, checked at
listener start and re-read per introspection.

## Rollout Notes

- Add the listener, pool and backends explicitly; share `shard_tag` and
  `backend_node` with the mailstore's other protocol endpoints.
- Backends must advertise the director's public URL, verify every request
  against the same Nauthilus with the same token binding, trust PROXY v2 from
  the director and serve an unauthenticated `/jmap/healthz`.
- The TCP proxy in front sends PROXY to the director and must not terminate
  TLS, or the director loses the client identity it needs.
- Keep director body limits at or above the backend's.
- Nauthilus must accept protocol `jmap` and return the shard attribute from the
  no-auth identity lookup; tokens meant for JMAP carry the configured resource
  or audience.

## Decisions and Open Questions

1. Decision: the canonical protocol value is `jmap`; there is no default
   listener.
2. Decision: every request is authenticated; the director keeps no HTTP
   session state beyond the bounded success cache.
3. Decision: missing shard attributes fail closed for JMAP by default.
4. Decision: request holds use the existing non-session holder kind instead of
   a new Redis holder kind, avoiding Lua script changes during rolling
   upgrades.
5. Decision: JMAP backend connections always write PROXY v2; mail protocols
   keep v1.
6. Decision: HTTP/1.1 only towards clients and backends.
7. Open: IMAP, POP3 and ManageSieve bearer logins without a shard claim fall
   back to the hash (see roadmap section 23).
8. Open: whether JMAP route lookup should apply the listener's `missing_shard`
   policy.
