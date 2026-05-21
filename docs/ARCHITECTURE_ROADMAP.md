# nauthilus-director Architecture and Roadmap

Status: production target design document

This document describes the intended production architecture for `nauthilus-director`: a mail protocol director/proxy that authenticates through Nauthilus, owns backend selection itself and keeps runtime state observable and controllable.

This is not a POC model. The previous proof-of-concept may be useful as source material, but this document defines the real production target. Requirements in this document are implementation constraints, especially for protocol lifecycle, backend selection, session stickiness, security defaults and operational behavior.

Read this document as the target model for the new codebase. Sections 1 through 22 describe architectural decisions and implementation direction. Section 23 collects the remaining decisions that still need explicit product or engineering choices before implementation reaches those areas.

## 1. Purpose

`nauthilus-director` is intended to become a lightweight, observable and authentication-aware mail protocol director for stateful mail backend deployments.

It should not become a full IMAP, POP3, LMTP, ManageSieve or Sieve implementation. Its job is to terminate or pass through the minimum protocol surface required for authentication, routing, health-aware backend selection and observability, and then proxy traffic to the selected backend service.

The core idea:

```text
client
  -> nauthilus-director
      -> optional TLS / STARTTLS / HAProxy PROXY protocol
      -> protocol-specific pre-auth state machine
      -> Nauthilus authentication / identity lookup
      -> director-owned routing fact resolution
      -> Redis-backed active affinity or deterministic initial backend selection
      -> transparent bidirectional proxying
          -> IMAP / LMTP / ManageSieve / POP3 backend
```

The director should be operationally boring: predictable, inspectable, reloadable, measurable and safe under failure.

## 2. Non-goals

The project should deliberately avoid the following traps:

- Do not implement a complete IMAP server.
- Do not implement mailbox semantics.
- Do not parse every post-auth command unless required for safe proxy operation.
- Do not ask Nauthilus for concrete director backend-selection decisions.
- Do not make the director a general-purpose load balancer.
- Do not introduce distributed consensus before the single-node semantics are correct.
- Do not hide backend failure behind vague errors. Failures must be observable and explainable.

Nauthilus may provide identity or directory-derived routing facts such as normalized account names, tenant identifiers, security-domain names, mailbox home attributes or shard tags. Those values are inputs to the director's own routing resolver and selector pipeline. They are not concrete backend-selection decisions.

## 3. Target protocols

The director should ultimately support these frontend protocol families:

- IMAP / IMAPS
- POP3 / POP3S
- LMTP / LMTPS
- ManageSieve / Sieve service proxying
- REST control API for management, inspection and automation

The protocol support should be layered so that shared pieces are reused:

- listener lifecycle
- TLS configuration
- STARTTLS handling
- HAProxy PROXY protocol
- connection limits
- backend selection
- Nauthilus authentication requests
- logging
- metrics
- tracing
- graceful shutdown

## 4. Repository foundation

The previous implementation has been moved to `poc/`. That directory is a historical proof-of-concept archive, not the target architecture and not the package layout for the new implementation.

The old proof-of-concept configuration is still available as `poc/nauthilus-director.yml`. It is useful source material, but it is not the production schema. The current target draft lives in `docs/config/nauthilus-director.target.yml` and must be kept aligned with this architecture document until a formal config schema exists.

Useful ideas in `poc/`:

- configuration model for listeners
- listener kind separation, currently including IMAP and LMTP
- capability and authentication mechanism configuration
- backend server model with protocol, identifier, weight, max connections, maintenance, deep check and TLS settings
- Nauthilus HTTP endpoint configuration
- validation via `go-playground/validator`
- Viper-based configuration handling

The new codebase starts cleanly from the root package layout described below. `poc/` may be read for behavior, experiments and examples, but production code must not import it, depend on it, preserve its package structure or justify behavior only because the POC behaved that way.

Known Nauthilus integration constraint learned from the proof-of-concept: the director-side auth request model must be aligned with the real structured auth DTO before relying on `/api/v1/auth/json` in production. In particular, `service` is not a valid JSON body field for that endpoint; the mail protocol belongs in `protocol`.

## 5. High-level components

The implementation should be organized around explicit ownership boundaries: process lifecycle, typed configuration, listener management, protocol pre-auth state machines, Nauthilus transport clients, backend/runtime state, REST management, observability and the raw proxy pipe. The package layout can evolve, but those boundaries should remain visible in code and tests.

Target package layout:

```text
cmd/nauthilus-director/
  main.go

internal/app/
  app.go
  lifecycle.go
  reload.go

internal/config/
  config.go
  validate.go

internal/listener/
  listener.go
  tcp.go
  unix.go
  tls.go
  proxyproto.go

internal/protocol/imap/
  session.go
  parser.go
  commands.go
  auth.go
  capability.go
  proxy.go

internal/protocol/pop3/
  session.go
  parser.go
  auth.go
  proxy.go

internal/protocol/lmtp/
  session.go
  parser.go
  envelope.go
  proxy.go

internal/protocol/sieve/
  session.go
  parser.go
  auth.go
  proxy.go

internal/backend/
  registry.go
  selector.go
  health.go
  connection_limits.go
  maintenance.go

internal/nauthilus/
  client.go
  request.go
  response.go
  errors.go

internal/routing/
  resolver.go
  auth_attribute.go
  static.go
  hash.go

internal/rest/
  server.go
  routes.go
  auth.go
  models.go

internal/observability/
  logging.go
  metrics.go
  tracing.go

internal/proxy/
  pipe.go
  deadlines.go
  accounting.go

internal/state/
  affinity.go
  sessions.go
  snapshots.go
```

The important point is separation of concerns: protocol handling must not become mixed with routing fact resolution, backend registry, Nauthilus client code and REST management.

## 7. Nauthilus integration

Nauthilus should be the authentication authority only. The director may ask Nauthilus to authenticate a user or to perform an identity lookup, but Nauthilus must not make concrete director backend-selection decisions. Backend selection is owned entirely by `nauthilus-director`.

Nauthilus may return authentication status, account fields, attributes and session/correlation metadata. Those values may include directory-derived routing facts, for example a normalized account name, tenant, security domain, mailbox home value or logical shard tag. They remain facts about the authenticated identity. They must not be treated as a command to use a concrete backend identifier.

Both transports must map into the same director-internal auth result:

```go
type AuthResult struct {
    Decision      string // authenticated, rejected, tempfail
    Account       string
    SessionID     string
    StatusMessage string
    Attributes    map[string][]string
}
```

Routing facts may be derived from `Account` and `Attributes`, but backend selection still runs after authentication through the director-owned routing resolver, active affinity and backend selector pipeline.

### 7.4 Backend selection boundary

There is one routing model for this project: Nauthilus authenticates; the director resolves routing facts and selects the backend.

Nauthilus may provide identity facts and directory-derived routing facts. It must not return, choose or require concrete director backend identifiers such as `mailstore-a-imap`. If a legacy Nauthilus response contains an internal `backend` value, the director must treat it as opaque metadata unless an explicit resolver mapping converts that value into a logical `shard_tag`.

The director's routing pipeline is:

```text
auth result + listener context
  -> RoutingResolver resolves tenant, normalized account and shard_tag
  -> active affinity may pin or override shard_tag while sessions are open
  -> backend selector resolves shard_tag + protocol + backend pool
  -> health, maintenance, limits and runtime overrides are applied
  -> concrete backend_identifier is selected
```

Director-owned routing inputs include:

- normalized account key
- authentication attributes returned by Nauthilus
- frontend protocol
- listener/service identity
- configured tenant or security-domain mapping
- configured routing resolver chain
- backend pool configuration
- backend health and maintenance state
- max connection limits and weights
- Redis-backed active affinity and runtime override state

The v1 model keeps the Nauthilus client interface transport-neutral and selects the concrete HTTP or gRPC client from configuration. Both transports must return the same director-level auth outcome: authenticated, rejected or temporary failure, plus safe metadata for logging and correlation.

## 8. Backend selection

Backend selection must be deterministic, observable and safe.

The director has two separate routing responsibilities:

1. Resolve a logical routing target, normally `tenant + normalized_account -> shard_tag`.
2. Resolve the concrete protocol backend, normally `shard_tag + protocol + backend_pool -> backend_identifier`.

The first step is owned by a routing resolver. The second step is owned by the backend selector and registry.

Routing resolver interface sketch:

```go
type RoutingResolver interface {
    Resolve(ctx context.Context, req RoutingRequest) (*RoutingResult, error)
}

type RoutingRequest struct {
    Tenant            string
    Protocol          string
    ListenerName      string
    ServiceName       string
    LoginName         string
    NormalizedAccount string
    AuthAttributes    map[string][]string
    ClientIP          string
}

type RoutingResult struct {
    AccountKey        string
    Tenant            string
    ShardTag          string
    RoutingSource     string
    RoutingGeneration string
    Sticky            bool
    TTL               time.Duration
    Attributes        map[string][]string
}
```

The resolver returns routing facts only. It must not return a concrete backend identifier for normal user-stateful protocol routing. Concrete backend selection remains in the backend selector so health, maintenance, protocol mapping, weights, connection limits, active affinity and runtime overrides are enforced uniformly.

Initial resolver strategy candidates:

- `auth_attribute`: read the normalized account and `shard_tag` from the authenticated `AuthResult`.
- `static_map`: map configured account or domain patterns to shard tags.
- `hash`: compute an initial shard tag by consistent or rendezvous hashing.
- `http`: call a side-effect-free routing service that returns routing facts.
- `grpc`: call a side-effect-free routing service that returns routing facts.
- `chain`: try multiple resolvers in order and stop at the first complete result.

The first production implementation should support `auth_attribute` and deterministic hash fallback. This gives deployments a clean migration path from existing directory attributes while preserving deterministic placement for accounts without explicit shard metadata.

Example resolver configuration:

```yaml
director:
  routing:
    resolver:
      type: auth_attribute
      auth_attribute:
        account_key: account
        shard_tag: mailShard
        tenant: tenant
      fallback:
        type: rendezvous_hash
        hash_key: account_key
    failover:
      enabled: true
      strategy: same_shard_then_any_healthy
```

Example Nauthilus authentication attributes consumed by the resolver:

```json
{
  "ok": true,
  "account_field": "account",
  "attributes": {
    "account": ["user@example.org"],
    "mailShard": ["mailstore-a"],
    "tenant": ["default"]
  }
}
```

The director then maps the logical shard to the protocol backend:

```yaml
director:
  backend_pools:
    imap-default:
      protocol: imap
      selector: rendezvous_hash
      backends:
        - mailstore-a-imap

  backends:
    mailstore-a-imap:
      protocol: imap
      shard_tag: mailstore-a
      address: "10.0.0.11:143"

    mailstore-a-sieve:
      protocol: sieve
      shard_tag: mailstore-a
      address: "10.0.0.11:4190"

    mailstore-a-lmtp:
      protocol: lmtp
      shard_tag: mailstore-a
      address: "10.0.0.11:24"
```

This separation lets the same account route to the same logical mailstore while still using protocol-specific backend entries, ports, TLS settings and health checks.

Supported selector strategy candidates:

- consistent hash by normalized account or shard tag
- rendezvous hashing
- weighted round-robin for stateless flows
- least connections within shard
- fixed shard tag mapping

Backend connection addressing and TLS identity are separate concerns. A backend
`address` may be an IP address or another routable endpoint, while
`tls.server_name` is the DNS name used for TLS SNI and certificate hostname
verification. When backend TLS is enabled and the TCP address is not the
certificate name, `tls.server_name` must be configured explicitly. The
implementation must not silently disable verification to make IP-address
backends work; `insecure_skip_verify` remains false by default.

For IMAP/POP3/ManageSieve the default is active-user sticky routing, not merely deterministic hashing.

For LMTP the default should be recipient-based and should use the same resolver model for recipient mailbox identity where practical.

## 9. Session affinity

Session affinity is mandatory production behavior for user-stateful protocols.

Hard invariant:

- Once a user has an authenticated active frontend session, the director must keep an active affinity record.
- Any new frontend session with the same affinity key must be routed to the same backend shard while that active affinity record exists.
- The initial placement strategy, for example rendezvous hashing, is used only when no active affinity record exists.
- Active affinity takes precedence over normal hashing, weights and least-connection style balancing.
- If backend entries are protocol-specific, the active pin binds to `shard_tag` first and then resolves to the protocol-specific backend identifier for the requested protocol.
- The affinity record is released only after the last matching frontend session closes, plus an optional short grace period.
- Failover away from an active pin is allowed only for hard-down backends, hard maintenance, explicit administrative kill/drain, or a documented fail-closed condition. Such movement must be logged, traced and counted.

Production affinity key:

```text
tenant + normalized_username -> shard_tag + active_session_count + expiry_after_last_close
```

Protocol-specific backend resolution:

```text
tenant + normalized_username -> shard_tag
shard_tag + protocol -> backend_identifier
```

The affinity hash is derived from tenant and normalized user identity. Raw usernames should not be required in Redis keys; any human-readable user details stored for diagnostics must be optional, redaction-aware and never required for routing correctness.

Redis is the central production state store for active affinity and session coordination. Local in-process state may be used as a cache or fast path, but it must not be the source of truth for production active-user stickiness when multiple director instances exist.

The v1 foundation includes Redis-backed active affinity. Deterministic hashing remains the stateless initial placement fallback and the recovery mechanism when no active pin exists.

## 10. IMAP design

The IMAP implementation should support only the pre-auth subset needed to authenticate and route.

Required frontend commands before proxy mode:

- CAPABILITY
- NOOP
- LOGOUT
- STARTTLS
- AUTHENTICATE PLAIN
- AUTHENTICATE XOAUTH2
- AUTHENTICATE OAUTHBEARER
- LOGIN
- ID, optional

After successful authentication, the director resolves routing facts, selects the backend, performs the configured backend authentication step and transitions to transparent proxy mode.

Backend authentication is explicit and configurable. Nauthilus remains the preferred frontend authentication authority, but operators may decide whether the backend receives a master-user login or the original user credential material.

Supported backend auth modes for user-stateful protocols:

- `master_user`: the director authenticates to the backend with a configured master credential and opens the session as the authenticated user. This is the preferred production mode when the backend supports it.
- `credential_replay`: the director forwards the original authentication material to the backend after Nauthilus has accepted it.

## 12. LMTP design

LMTP is not a login protocol. Routing happens per envelope recipient.

The director uses a same-backend-only recipient routing strategy.

- Accept one transaction.
- Resolve each `RCPT TO` recipient through the same routing resolver model, using a recipient lookup API or Nauthilus-provided recipient facts where configured, before accepting it into the transaction.
- The first accepted recipient establishes the transaction backend target.
- Additional recipients are accepted only if they resolve to the same backend target.
- Recipients that resolve to another backend are rejected or temporary-failed before `DATA`, so the sending side can retry them in a separate transaction.
- `DATA` is forwarded only to the single selected backend for the accepted recipient set.
- The director must not spool one message body for replay to multiple backend groups.

## 13. Sieve / ManageSieve design

Sieve itself is the mail filtering language, but clients usually talk to a ManageSieve service to upload and manage Sieve scripts. For this project, `nauthilus-director` should not execute Sieve scripts. It should proxy ManageSieve to the correct backend.

The useful feature is routing a user to the same mailstore for IMAP and ManageSieve.

After authentication:

```text
ManageSieve client
  -> director authenticates via Nauthilus
  -> director resolves the same shard_tag as IMAP for the user
  -> director selects the protocol-specific ManageSieve backend
  -> director connects to backend ManageSieve service
  -> director establishes backend auth/trust
  -> transparent proxy mode
```

Decision: use separate backend entries per protocol and connect them through the same `shard_tag`. This avoids assuming IMAP, LMTP and ManageSieve ports live on identical host/port definitions while preserving user affinity.

## 14. REST control API

Routing debug:

```text
POST /api/v1/route/lookup
```

Route lookup decision: this endpoint is a director-only routing diagnostic. It does not authenticate credentials, does not call Nauthilus and does not ask Nauthilus for identity or routing input. The caller supplies an already known or operator-provided identity key, protocol and listener context; the director then explains how its own configured resolver inputs, Redis affinity, runtime overrides, health and maintenance state would select a backend.

The endpoint must be side-effect free. It may read Redis-backed affinity and runtime state, but it must not create sessions, refresh leases, mutate affinity, perform backend auth or trigger Nauthilus auth/lookup calls. If a future diagnostic needs to test Nauthilus authentication or identity normalization, it must be a separate auth diagnostic surface, not part of `route/lookup`.

Example request:

```json
{
  "protocol": "imap",
  "username": "user@example.org",
  "client_ip": "203.0.113.10",
  "listener": "imaps",
  "attributes": {
    "mailShard": ["mailstore-a"],
    "tenant": ["default"]
  }
}
```

Example response:

```json
{
  "selected_backend": "mailstore-a-imap",
  "reason": "auth_attribute",
  "healthy": true,
  "maintenance": false,
  "shard_tag": "mailstore-a"
}
```

## 21. Testing strategy

Unit tests:

- routing resolver behavior, including `auth_attribute`, missing attribute handling and deterministic hash fallback
- backend selector determinism
- Redis-backed active affinity, user moves and user kicks
- Nauthilus client error mapping
- Nauthilus structured request mapping, including rejection of unknown JSON fields such as `service`
- route lookup staying director-only and side-effect-free

Integration tests:

- fake Nauthilus auth endpoint returning account and routing attributes
- fake IMAP backend
- fake LMTP backend
- fake ManageSieve backend
- backend down / maintenance / max connections
- user move/kick flows across active sessions

E2E tests:

- authenticate through the public protocol listener, then assert backend routing externally
- verify `auth_attribute` routing from Nauthilus-provided attributes
- verify active-user stickiness across parallel connections and reconnects
- verify route lookup does not call Nauthilus, create sessions or mutate Redis

## 22. Implementation milestones

### M0: Repository hygiene

- keep the old implementation isolated under `poc/` as reference material only
- finalize package layout
- add CI
- add basic test structure
- document architecture
- define public config schema from `docs/config/nauthilus-director.target.yml`
- align the director-side Nauthilus request/response models with the real HTTP JSON and gRPC contracts
- add the approved foundation dependencies to the production module only when the new root module is created
- create the initial routing resolver abstraction and document `auth_attribute` plus hash fallback semantics

### M1: IMAP MVP

- listener lifecycle
- IMAP greeting/CAPABILITY/STARTTLS/LOGIN/AUTH PLAIN
- Nauthilus auth call over the configured HTTP or gRPC transport
- routing resolver support for authenticated account attributes
- backend selection by active Redis-backed affinity or initial deterministic placement
- backend connect
- transparent proxy loop
- basic metrics/logging
- E2E proof for successful IMAP auth, routing resolver behavior, backend selection, active stickiness and secret-safe observable output

## 24. Immediate next steps

1. Create the new production Go module skeleton under the root package layout.
2. Add the approved foundation dependencies and tool pins to the production module.
3. Implement typed config loading, canonical defaults, redacted/non-redacted dumps and validator-based validation against `docs/config/nauthilus-director.target.yml`.
4. Add the routing resolver package with `auth_attribute` and deterministic hash fallback support.
5. Add the initial OpenAPI specification under `docs/specs/openapi/nauthilus-director.yaml` and wire reproducible generation/check targets.
6. Build the E2E harness with fake Nauthilus and fake backend test servers before expanding production protocol code.
7. Implement the IMAP MVP end-to-end with Redis-backed active affinity, basic metrics, structured logs, trace boundaries and externally observable E2E coverage.

The project should evolve as a small, sharp director: protocol-aware only where necessary, authenticated through Nauthilus, routed through director-owned facts and selectors, observable by default, and operationally safe enough to sit in front of real mail backends.
