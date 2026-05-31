# nauthilus-director Architecture and Roadmap

Status: production target design document

This document describes the intended production architecture for `nauthilus-director`: a mail protocol director/proxy that authenticates through Nauthilus, resolves routing facts through director-owned logic, selects concrete backends itself and keeps runtime state observable and controllable.

This is not a POC model. The previous proof-of-concept may be useful as source material, but this document defines the real production target. Requirements in this document are implementation constraints, especially for protocol lifecycle, Nauthilus integration, routing fact resolution, backend selection, session stickiness, security defaults and operational behavior.

Read this document as the target model for the new codebase. The document is both architecture and roadmap: it defines boundaries and invariants, then breaks the target into implementation milestones. It is not yet a line-by-line implementation specification; milestone-specific implementation specs may be added under `docs/specs/implementation/` when a phase becomes active.

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
      -> Redis-backed active affinity or deterministic initial placement
      -> director-owned backend selection
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
- Nauthilus authentication requests
- routing fact resolution
- backend selection
- logging
- metrics
- tracing
- graceful shutdown

## 4. Repository foundation

The previous implementation lives under `poc/`. That directory is a historical proof-of-concept archive and source of ideas only. Production code must start from the root package layout and must not import from `poc/`, depend on its package structure, or preserve POC behavior as a compatibility constraint.

The old proof-of-concept configuration is still useful as source material, but it is not the production schema. The current target draft lives in `docs/config/nauthilus-director.target.yml` and must be kept aligned with this architecture document until a formal config schema exists.

Known Nauthilus integration constraint learned from the proof-of-concept: the director-side auth request model must be aligned with the real structured auth DTO before relying on `/api/v1/auth/json` in production. In particular, `service` is not a valid JSON body field for that endpoint; the mail protocol belongs in `protocol`.

## 5. High-level components

The implementation should be organized around explicit ownership boundaries: process lifecycle, typed configuration, listener management, protocol pre-auth state machines, Nauthilus transport clients, routing fact resolution, backend/runtime state, REST management, observability and the raw proxy pipe.

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
  chain.go

internal/backend/
  registry.go
  selector.go
  health.go
  connection_limits.go
  maintenance.go

internal/state/
  affinity.go
  sessions.go
  snapshots.go

internal/rest/
  server.go
  routes.go
  auth.go
  adapters.go
  generated/

internal/observability/
  logging.go
  metrics.go
  tracing.go

internal/proxy/
  pipe.go
  deadlines.go
  accounting.go
```

The important point is separation of concerns: protocol handling must not become mixed with routing fact resolution, backend registry, Nauthilus client code, REST management or observability plumbing.

### 5.1 Technical foundation

The engineering baseline is security-by-design, security-by-default, strict object-oriented boundaries in Go, intentional DRY and conservative dependency choices. Domain objects own their invariants; shared helpers are extracted when they remove real duplication without hiding protocol-specific behavior.

Approved foundation dependencies:

- Uber Fx (`go.uber.org/fx`) for application composition, lifecycle wiring and dependency injection.
- Viper for configuration loading and environment binding, including its `mapstructure`-based decode path.
- go-playground/validator (`github.com/go-playground/validator/v10`) for mandatory typed configuration validation after Viper/mapstructure decoding.
- `github.com/redis/go-redis/v9` pinned initially to `v9.19.0` for central production state: active user affinity, session coordination, operational caches and future distributed coordination needs.
- jsoniter for JSON paths where the project intentionally chooses it over the standard library.

These packages are accepted as architectural building blocks, not as blanket permission to add convenience dependencies. Additional vendor packages still need a concrete justification and should be avoided when a small local implementation is clearer, safer and cheaper to maintain.

OpenAPI is part of the foundation for the REST control API from the beginning. The REST contract, generated REST server boundary, generated REST DTOs and generated client code should originate from the OpenAPI specification before hand-written REST handlers expand. Generated REST code must stay at the REST boundary and adapt into explicit domain objects.

### 5.2 Configuration target

The initial target configuration is documented as YAML in `docs/config/nauthilus-director.target.yml`.

It intentionally follows the same broad grouping style as Nauthilus config v2:

- `runtime`: process lifecycle, control server, shared timeouts and generic clients
- `observability`: logs, metrics, tracing and profiling
- `storage`: full Redis connection, security and topology configuration
- `auth`: Nauthilus authority definitions and transport selection
- `director`: mail listeners, routing, affinity, health, maintenance, backend pools and backends

This split keeps operational runtime concerns separate from the mail director domain. Nauthilus is still only an authentication authority; routing fact resolution and backend selection remain under `director`.

Redis configuration lives in exactly one place: `storage.redis`. That includes connection topology, TLS, credentials and Redis key namespaces for affinity, sessions, user runtime state and backend runtime state. Active affinity uses Redis implicitly because Redis is the only production state backend for this project; no feature-specific Redis config subtree is part of the target schema.

Stable for M0/M1:

- `runtime.process`, `runtime.servers.control`, `runtime.timeouts` and `runtime.clients`
- `observability`
- `storage.redis`, including topology, TLS, auth, pool, retry, health, key-prefix and namespace shape
- `auth.authorities`, including the HTTP-or-gRPC transport switch and OIDC delegation to Nauthilus
- `director.security`
- common listener fields: `protocol`, `service_name`, `network`, `address`, `authority`, `backend_pool`, `proxy_protocol` and `tls`
- `director.listeners.imap` and `director.listeners.imaps`
- `director.routing`, including resolver configuration, failover and selector defaults
- `director.affinity`, `director.health`, `director.maintenance` and `director.runtime_overrides`
- `director.backend_pools` and `director.backends` for the IMAP MVP, including backend TLS/SNI and backend authentication shape

Draft until their implementation phases:

- LMTP listener/backend details until M5
- ManageSieve listener/backend details until M6
- POP3 listener/backend details until M7
- protocol-specific config fields added for later capability negotiation, delivery semantics, script handling or backend protocol quirks

Config handling rules:

- YAML is the project default for examples, generated defaults and operator documentation.
- The Viper loader must support the common Viper configuration formats where practical.
- Scalar config values must support Nauthilus-style environment expansion with `${NAME}` placeholders.
- Ordinary `$` characters remain literal and `$${NAME}` escapes a placeholder.
- Expansion happens after file/include/patch merging and before Viper/mapstructure decoding, typed validation and Viper environment overrides.
- Map keys are not expanded.
- Missing placeholders fail closed with a path-specific, secret-safe diagnostic.
- Secret-bearing fields must use explicit secret metadata so redaction and `-P` behavior are deterministic.

Config inspection commands:

```text
nauthilus-director config dump -d --format yaml
nauthilus-director config dump -n --format yaml
nauthilus-director config dump -n -P --format yaml
```

Required semantics:

- `-d` prints canonical defaults only.
- `-n` prints non-default effective configuration after config value expansion and environment overrides, redacted by default.
- `-P` includes protected credential values in config output. It must be explicit and must not affect logs, metrics or REST responses.
- Config dump output is inspection output only. It must not include Redis runtime overrides unless a separate runtime-state command explicitly asks for them.

## 6. Runtime model

Each incoming connection becomes a session with a stable session ID.

A session should carry:

```go
type SessionContext struct {
    SessionID        string
    ListenerName     string
    Protocol         string
    ServiceName      string
    LocalAddr        string
    RemoteAddr       string
    ClientIP         string
    HAProxyInfo      *ProxyInfo
    TLSState         *tls.ConnectionState
    Username         string
    Authenticated    bool
    AccountKey       string
    Tenant           string
    ShardTag         string
    SelectedBackend  string
    NauthilusTraceID string
    StartedAt        time.Time
}
```

The session lifecycle:

```text
accept
  -> create session
  -> apply listener-level limits
  -> optional PROXY protocol read
  -> optional implicit TLS
  -> protocol greeting
  -> pre-auth protocol handling
  -> Nauthilus auth / lookup
  -> routing fact resolution
  -> active affinity lookup or initial placement
  -> backend selection
  -> connect backend
  -> optional backend TLS / STARTTLS
  -> optional backend authentication / login replay
  -> proxy until EOF/error/timeout
  -> cleanup counters/session registry
```

## 7. Nauthilus integration

Nauthilus should be the authentication authority only. The director may ask Nauthilus to authenticate a user or to perform an identity lookup, but Nauthilus must not make concrete director backend-selection decisions. Backend selection is owned entirely by `nauthilus-director`.

The Nauthilus auth transport is configurable. A deployment uses either HTTP or gRPC for the director-to-Nauthilus auth call:

- HTTP structured auth endpoint: `/api/v1/auth/json` with `application/json`
- gRPC AuthService endpoint: `nauthilus.auth.v1.AuthService`

OIDC-backed authentication belongs to Nauthilus. The director may receive OAuth/OIDC bearer material through mail SASL mechanisms or through the control API, but it should not become a local OIDC validation authority. It extracts the mechanism payload, preserves the mechanism identity, applies size and secrecy rules, and asks Nauthilus to validate the credential over the configured HTTP or gRPC authority.

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

### 7.1 SASL mechanisms and OIDC-backed credentials

Required frontend mechanisms for user-stateful protocols:

- `PLAIN`
- `LOGIN`, where the frontend protocol commonly exposes it
- `XOAUTH2`
- `OAUTHBEARER`

Mechanism handling rules:

- `PLAIN` and `LOGIN` provide username/password credentials.
- `XOAUTH2` and `OAUTHBEARER` provide bearer-token credentials.
- Tokens, passwords and SASL blobs must never be logged, traced or exposed in metrics.
- The director may parse the SASL envelope enough to extract the authorization identity, authentication identity, bearer token and optional client metadata.
- The request sent to Nauthilus must include the original mechanism name so Nauthilus can apply mechanism-specific policy.
- The director owns the transport privacy gate. Credential-bearing frontend mechanisms, including password and bearer mechanisms, must be rejected before Nauthilus is called unless the client has already crossed an implicit TLS or STARTTLS boundary with the director.
- When frontend TLS is active, every protocol handler must populate the flat Nauthilus SSL DTO fields it can derive from the connection state, including `ssl`, TLS protocol, cipher, client-certificate verification status and bounded peer-certificate metadata. Missing TLS metadata must not be invented, but `ssl` must still truthfully report whether the frontend connection was encrypted.
- SASL-IR is allowed where the frontend protocol supports it, but size limits and pre-auth timeouts still apply.

### 7.2 HTTP JSON authentication request

The director uses only the HTTP JSON endpoint when `auth.authorities.<name>.transport` is `http`. The request body is the real structured Nauthilus auth DTO encoded as `application/json`. JSON is strict: unknown top-level fields are rejected.

The director must not send fields such as `service`, nested `tls`, nested `proxy`, `listener`, `session_id`, `backend_identifier` or `routing_hint` in the JSON body unless Nauthilus adds those fields explicitly. The protocol identity belongs in `protocol`, not in a top-level `service` body field.

Identity lookup uses the same endpoint and request body without a password:

```text
POST /api/v1/auth/json?mode=no-auth
```

List-accounts uses:

```text
GET  /api/v1/auth/json?mode=list-accounts
POST /api/v1/auth/json?mode=list-accounts
```

Nauthilus may return an internal `backend` value for its own purposes. The director must treat it as opaque metadata unless an explicit routing resolver mapping converts that value into a logical `shard_tag`.

Example successful response with routing facts in attributes:

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

### 7.3 gRPC AuthService

Nauthilus also exposes a typed gRPC AuthService:

```text
nauthilus.auth.v1.AuthService
  Authenticate(AuthRequest) returns (AuthResponse)
  LookupIdentity(LookupIdentityRequest) returns (AuthResponse)
  ListAccounts(ListAccountsRequest) returns (ListAccountsResponse)
```

`AuthRequest` is the protobuf equivalent of the shared structured auth DTO plus `password` and `auth_login_attempt`. `LookupIdentityRequest` is a dedicated no-password request. `ListAccountsRequest` is a dedicated account-listing request. The director's gRPC client must translate these protobuf responses into the same `AuthResult` shape as the HTTP client.

### 7.4 Backend selection boundary

There is one routing model for this project: Nauthilus authenticates; the director resolves routing facts and selects the backend.

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

## 8. Routing and backend selection

Backend selection must be deterministic, observable and safe.

The director has two separate responsibilities:

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

The director then maps the logical shard to protocol-specific backend entries:

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

Backend connection addressing and TLS identity are separate concerns. A backend `address` may be an IP address or another routable endpoint, while `tls.server_name` is the DNS name used for TLS SNI and certificate hostname verification. When backend TLS is enabled and the TCP address is not the certificate name, `tls.server_name` must be configured explicitly. The implementation must not silently disable verification to make IP-address backends work; `insecure_skip_verify` remains false by default.

For IMAP/POP3/ManageSieve the default is active-user sticky routing, not merely deterministic hashing. For LMTP the default should be recipient-based and should use the same resolver model for recipient mailbox identity where practical.

## 9. Session affinity and Redis state

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

Redis is the central production state store for active affinity and session coordination. Local in-process state may be used as a cache or fast path, but it must not be the source of truth for production active-user stickiness when multiple director instances exist.

Redis integration is a production subsystem, not a best-effort cache. It must support ACL/auth, TLS, standalone, Sentinel and Cluster modes, explicit timeouts, pooling, key namespacing, script execution and fail-closed behavior for required state.

Redis state model decision:

- Active affinity and session coordination use per-affinity Redis key groups.
- Keys that must be touched atomically share a Redis Cluster hash tag derived from the normalized affinity key, for example `{aff:<affinity_hash>}`.
- The normal routing path uses small atomic Redis Lua scripts, not distributed locks.
- Scripts cover session open, heartbeat, close, expired-session reaping, user move, user kick, affinity clear and administrative pin changes.
- Scripts use Redis server time, update a generation counter and fail closed on ambiguous state.
- Session liveness is lease-based. A crashed director instance must not leave permanent active sessions.
- Backend runtime overrides live in separate Redis hashes keyed by backend identifier.
- Secondary indexes for REST/CLI listing are repairable convenience indexes.

Initial key shape:

```text
<prefix>:v<schema>:{aff:<affinity_hash>}:state
<prefix>:v<schema>:{aff:<affinity_hash>}:sessions
<prefix>:v<schema>:{aff:<affinity_hash>}:session:<session_id>
<prefix>:v<schema>:{aff:<affinity_hash>}:override
<prefix>:v<schema>:runtime:backend:<backend_id>
<prefix>:v<schema>:idx:sessions
<prefix>:v<schema>:idx:backends
```

The affinity hash is derived from tenant and normalized user identity. Raw usernames should not be required in Redis keys; any human-readable user details stored for diagnostics must be optional, redaction-aware and never required for routing correctness.

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

IMAP `CAPABILITY` output is the effective configured pre-auth extension
surface, not a blind list of parser code paths. Omitting `ID`, `STARTTLS`,
`SASL-IR` or an `AUTH=<mechanism>` capability disables the related extension
behavior for that listener; unsupported capabilities fail validation instead of
being hidden at runtime. `LOGIN` remains an explicit pre-auth command rather
than an advertised SASL mechanism.

Optional later:

- AUTHENTICATE LOGIN
- literal handling for LOGIN/AUTHENTICATE edge cases

After successful authentication, the director resolves routing facts, applies active affinity, selects the backend, performs the configured backend authentication step and transitions to transparent proxy mode.

Backend authentication is explicit and configurable. Supported backend auth modes for user-stateful protocols:

- `master_user`: the director authenticates to the backend with a configured master credential and opens the session as the authenticated user.
- `credential_replay`: the director forwards the original authentication material to the backend after Nauthilus has accepted it.

`credential_replay` must be opt-in because it extends the lifetime and blast radius of user passwords or bearer tokens inside the director. Both modes must avoid logging passwords, master credentials, SASL blobs and bearer tokens.

## 11. POP3 design

POP3 support should come after IMAP MVP.

Required commands before proxy mode:

- CAPA
- STLS
- USER
- PASS
- AUTH XOAUTH2
- AUTH OAUTHBEARER
- QUIT
- NOOP

After Nauthilus accepts authentication, POP3 placement must use the same
canonical tenant and normalized account key as IMAP active affinity, user
movement, backend pins and user placement holds. A client-supplied `USER` value
is only protocol input until authentication succeeds; it must not be used as an
authoritative hold or affinity key.

POP3 must check a user placement hold after successful authentication and
routing fact resolution, but before returning a login success response, backend
selection, backend capacity reservation, backend connect, backend
authentication or proxy mode. If the hold clears or expires within the bounded
wait budget, POP3 must re-read active affinity, movement overrides, backend-pin
state, backend health and capacity before selecting. If the hold remains active
past the wait budget, POP3 must return a generic temporary failure and must not
fall back to the old backend.

Backend pins apply to POP3 only when the pin's protocol and backend pool match
the POP3 placement request. A pin for an IMAP, LMTP or ManageSieve backend must
not name the concrete POP3 backend. Cross-protocol consistency comes from the
shared shard tag and active affinity; after the shard is known, POP3 resolves a
protocol-specific backend entry.

After placement succeeds, proxy transparently.

## 12. LMTP design

LMTP is not a login protocol. Routing happens per envelope recipient.

The frontend LMTP listener still needs transport security and optional client authentication. This authenticates the submitting LMTP peer, not the mailbox user and not the backend routing decision.

The director uses a same-backend-only recipient routing strategy:

- Accept one transaction.
- Resolve each `RCPT TO` recipient through the same routing resolver model, using a recipient lookup API or Nauthilus-provided recipient facts where configured, before accepting it into the transaction.
- The first accepted recipient establishes the transaction backend target.
- Additional recipients are accepted only if they resolve to the same backend target.
- Recipients that resolve to another backend are rejected or temporary-failed before `DATA`, so the sending side can retry them in a separate transaction.
- `DATA` is forwarded only to the single selected backend for the accepted recipient set.
- The director must not spool one message body for replay to multiple backend groups.

LMTP must return per-recipient status. Multi-recipient routing must be safe, explicit and observable.

LMTP `LHLO` output is the effective configured frontend surface. Omitted
capabilities disable the related extension behavior for that session:
`STARTTLS` is not accepted when not advertised, `AUTH` mechanisms are not
inferred from peer-auth config, `CHUNKING` is required for `BDAT`, and
`SMTPUTF8` is required before accepting the `MAIL FROM` `SMTPUTF8` parameter or
SMTPUTF8-only envelope paths. Unsupported or backend-unsafe capabilities fail
closed before sockets bind or before they are advertised.

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

ManageSieve must check a user placement hold after Nauthilus has authenticated
the user and produced canonical tenant plus account facts, but before backend
selection, backend capacity reservation, backend connect, backend auth/trust or
proxy mode. The director must not return an authentication success response that
implies script-management access is ready while the user's placement is held. If
the hold clears or expires within the bounded wait budget, ManageSieve must
re-read active affinity, movement overrides, backend-pin state, backend health
and capacity before selecting. If the hold remains active past the wait budget,
ManageSieve must return a generic temporary failure and must not fall back to
the old backend.

Backend pins apply to ManageSieve only when the pin's protocol and backend pool
match the ManageSieve placement request. A pin for an IMAP, LMTP or POP3 backend
must not name the concrete ManageSieve backend. Cross-protocol consistency comes
from the shared shard tag and active affinity; after the shard is known,
ManageSieve resolves a protocol-specific backend entry.

Sieve script contents, script names and command bodies should not be logged or used as high-cardinality metrics labels.

## 14. REST control API

The director should expose an administrative REST API for introspection, controlled automation and eventually a CLI/client.

It must not be part of the mail protocol data path. It should be optional and bind to localhost or a protected management interface by default.

Deployment decision for v1: the REST control API runs inside the main `nauthilus-director` process on its own `runtime.servers.control` listener. It shares the same typed config snapshot, Redis-backed runtime state, lifecycle and observability wiring as the mail protocol listeners, but remains isolated from the mail data path by listener, authentication, authorization and handler boundaries.

Supported authentication modes:

- disabled
- static bearer token
- mTLS
- reverse-proxy authenticated headers
- OIDC/JWT via Nauthilus

The control API must never write the YAML configuration file. Mutating operations change runtime state only. Runtime state lives in Redis and is reflected into in-process snapshots; configuration remains the immutable baseline until an operator changes and reloads it outside the API.

Initial endpoint groups:

```text
GET  /healthz
GET  /readyz
GET  /api/v1/version
GET  /api/v1/config/effective
GET  /api/v1/config/defaults
GET  /api/v1/config/non-default
POST /api/v1/reload
GET  /api/v1/backends
GET  /api/v1/backends/{identifier}
POST /api/v1/backends/{identifier}/maintenance
DELETE /api/v1/backends/{identifier}/maintenance
POST /api/v1/backends/{identifier}/runtime/in
POST /api/v1/backends/{identifier}/runtime/out
POST /api/v1/backends/{identifier}/runtime/drain
DELETE /api/v1/backends/{identifier}/runtime
GET  /api/v1/sessions
GET  /api/v1/sessions/{session_id}
DELETE /api/v1/sessions/{session_id}
GET  /api/v1/users
GET  /api/v1/users/{user_key}
GET  /api/v1/users/{user_key}/sessions
GET  /api/v1/users/{user_key}/affinity
PUT  /api/v1/users/{user_key}/affinity
DELETE /api/v1/users/{user_key}/affinity
POST /api/v1/users/{user_key}/move
POST /api/v1/users/{user_key}/kick
POST /api/v1/route/lookup
GET  /metrics
```

Route lookup is a director-owned routing diagnostic. It does not authenticate credentials. For protocols where the caller supplies an already known identity key, protocol, listener context and optional attributes, the director explains how its configured resolver inputs, Redis affinity, runtime overrides, health and maintenance state would select a backend. For LMTP recipient diagnostics, the director may resolve a supplied recipient through the Nauthilus identity lookup path (`LookupIdentity` for gRPC or `mode=no-auth` for HTTP/JSON) before running the dry-run route explanation.

The endpoint must be side-effect free. It may read Redis-backed affinity and runtime state and may perform the explicit LMTP no-auth identity lookup described above, but it must not authenticate credentials, create sessions, refresh leases, open delivery holds, mutate affinity, perform backend auth, connect to backends or trigger Nauthilus credential-authentication calls. Responses must state whether identity input was caller-supplied, read from existing director state or resolved through Nauthilus.

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

## 15. CLI client

A small CLI client should make operations scriptable.

Initial binary name:

```text
nauthilus-directorctl
```

The client command grammar must use clean nested subcommands. The CLI must use the generated OpenAPI REST client SDK as its HTTP transport boundary. Hand-written CLI code may provide command structure, configuration, output formatting and operator-friendly error messages, but it must not maintain a parallel REST client model or duplicate request/response DTOs.

Example commands:

```text
nauthilus-director --version
nauthilus-directorctl --version
nauthilus-directorctl status
nauthilus-directorctl backends list
nauthilus-directorctl backends show <identifier>
nauthilus-directorctl backends maintenance enable <identifier> --reason "storage migration"
nauthilus-directorctl backends out <identifier> --reason "host maintenance"
nauthilus-directorctl backends in <identifier>
nauthilus-directorctl backends drain <identifier> --mode soft --reason "host replacement"
nauthilus-directorctl sessions list --protocol imap
nauthilus-directorctl sessions kill <session-id>
nauthilus-directorctl users move user@example.org --to-shard mailstore-b --strategy kick-existing
nauthilus-directorctl users kick user@example.org --reason "operator requested reconnect"
nauthilus-directorctl users affinity clear user@example.org
nauthilus-directorctl route lookup --protocol imap --user user@example.org --attribute mailShard=mailstore-a
nauthilus-directorctl reload
```

CLI mutating commands must state whether they change runtime state or request a reload. Runtime operations write Redis-backed state only; they must not patch, rewrite or persist changes into YAML configuration.

## 16. OpenAPI workflow

The REST API and `nauthilus-directorctl` should use an OpenAPI-first workflow from hour zero.

Generator decision: use `oapi-codegen` `v2.7.0` from `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen`. The initial generated surface should use Go's standard `net/http` server style, strict server interfaces, generated models and a generated client-with-responses SDK for `nauthilus-directorctl`.

Repository layout:

```text
docs/specs/openapi/nauthilus-director.yaml
docs/specs/implementation/
docs/man/
docs/config/metadata.yml
docs/reference/
internal/rest/generated/
internal/rest/adapters/
internal/client/generated/
scripts/generate-openapi.sh
scripts/generate-docs.sh
scripts/check-docs.sh
tools/configdoc/
```

Expected Makefile targets once the REST contract exists:

```text
make generate-openapi
make check-openapi
make generate-docs
make check-docs
```

Configuration documentation should be coupled to the typed config model rather
than maintained only as prose. A small Go helper should reflect the typed config
and `DefaultConfig()` to generate committed config reference artifacts, while
`docs/config/metadata.yml` supplies human-authored descriptions for stable
config paths. `make check-docs` must fail when generated config references are
stale, when stable config paths lack metadata, when metadata points to removed
paths or when stable path descriptions are left as placeholders.

Generated code must not own mail protocol state machines, backend registry, selector, health model, routing resolver implementation or Nauthilus transport implementation. Those remain explicit domain objects with hand-written tests.

## 17. OpenTelemetry and metrics

OpenTelemetry should be first-class from the beginning, not bolted on later.

Trace boundaries:

- accepted frontend session
- protocol pre-auth phase
- Nauthilus authentication request
- routing fact resolution
- backend selection
- backend connect
- backend TLS/STARTTLS
- proxy lifetime
- LMTP recipient routing
- REST API requests

Initial span names:

```text
nauthilus_director.session
nauthilus_director.imap.pre_auth
nauthilus_director.pop3.pre_auth
nauthilus_director.lmtp.transaction
nauthilus_director.sieve.pre_auth
nauthilus_director.nauthilus.auth
nauthilus_director.routing.resolve
nauthilus_director.backend.select
nauthilus_director.backend.connect
nauthilus_director.proxy.pipe
nauthilus_director.rest.request
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

Prometheus metrics should include sessions, auth totals/durations, routing resolver totals/durations, backend selection totals, backend health, backend maintenance, proxy bytes/durations, LMTP transaction totals/durations, LMTP recipient route/status totals, LMTP same-backend policy failures, LMTP DATA/BDAT stream totals/durations, LMTP backend status classes, REST requests and Redis operation health.

`backend_pool` and `shard_tag` are acceptable labels; raw backend identifiers are not metrics labels. Per-backend details belong in REST, logs and traces.
LMTP observability must also keep raw recipients, envelope senders, message identifiers, subjects and DATA/BDAT content out of logs, traces and metric labels.

## 18. Health checks and maintenance

Backend health should support two levels.

Light check:

- TCP connect
- optional TLS handshake
- optional greeting read

Deep check:

- protocol-specific login or transaction test
- IMAP: authenticate test user and logout
- POP3: authenticate test user and quit
- LMTP: LHLO and optional NOOP/RSET
- ManageSieve: greeting/capability and optional auth test

Maintenance mode should prevent new sessions from being assigned to a backend while optionally allowing existing sessions to drain.

Modes:

```text
soft: no new initial placements, existing sessions remain
hard: no new sessions, existing sessions may be killed after grace period
disabled: normal operation
```

Soft maintenance excludes a backend from new initial placements while preserving existing sessions and active pins by default. Hard maintenance excludes all new sessions and may terminate existing sessions after explicit grace. Maintenance and drain operations must be auditable.

Runtime weight `0` is weaker than maintenance. It removes a backend from weighted initial placement, but it does not by itself imply hard exclusion, session termination or maintenance audit semantics.

## 19. Configuration reload

Reload should be explicit and safe.

Reloadable:

- listener additions
- listener removals with graceful drain
- backend additions/removals
- backend maintenance defaults
- weights
- routing resolver configuration
- health intervals
- logging level

Not safely reloadable without restart, at least initially:

- changing REST listener bind address
- changing global telemetry exporter setup
- changing core protocol behavior

On reload:

1. Parse new config.
2. Validate new config.
3. Build new runtime snapshot.
4. Apply listener/backend/resolver changes.
5. Keep existing sessions on old backend object until closed.
6. New sessions use the new snapshot.

## 20. Security model

The director is in the authentication path and must be treated as security-sensitive. Security-by-design and security-by-default are hard requirements.

Rules:

- Never log credentials.
- Never log raw SASL blobs.
- Never log OAuth/OIDC bearer tokens.
- Avoid logging Sieve script contents.
- Use strict timeouts on unauthenticated sessions.
- Limit pre-auth command size.
- Limit line length and literal size.
- Protect REST API by default.
- Prefer localhost or management network binding for REST.
- Support TLS min version configuration.
- Avoid `skip_verify` in production examples.
- Explicitly document trusted backend network assumptions.
- Fail closed on ambiguous authentication, routing, Redis or backend-selection state.

## 21. Testing strategy

Unit tests:

- config validation
- env placeholder expansion and redaction
- routing resolver behavior, including `auth_attribute`, missing attribute handling and deterministic hash fallback
- backend selector determinism
- Redis-backed active affinity, user moves and user kicks
- health state transitions
- REST handlers and OpenAPI adapters
- Nauthilus client error mapping
- Nauthilus structured request mapping, including rejection of unknown JSON fields such as `service`
- SASL XOAUTH2/OAUTHBEARER parsing with secret-safe diagnostics
- route lookup staying director-only and side-effect-free

Integration tests:

- fake Nauthilus auth endpoint returning account and routing attributes
- fake IMAP backend
- fake POP3 backend
- fake LMTP backend
- fake ManageSieve backend
- TLS and STARTTLS flows
- HAProxy PROXY protocol flows
- backend down / maintenance / max connections
- backend runtime weight `0`, runtime in/out and drain operations
- user move/kick flows across active sessions

E2E tests:

- keep a deterministic guardrail lane through `make e2e`
- use fake Nauthilus authorities over HTTP and gRPC in the guardrail lane
- use fake IMAP, LMTP, ManageSieve and POP3 backends in the guardrail lane so tests can force protocol observations, backend failures, maintenance state, slow responses and secret-safe log assertions
- use real Redis or a Redis-compatible test service for active affinity and runtime overrides
- authenticate through the public protocol listener, then assert backend routing externally
- verify `auth_attribute` routing from Nauthilus-provided attributes
- verify active-user stickiness across parallel connections and reconnects
- verify route lookup does not authenticate credentials, create sessions or mutate Redis; LMTP recipient diagnostics may call only the no-auth Nauthilus identity lookup path
- verify TLS/STARTTLS and backend TLS/SNI behavior with test certificates
- scrape Prometheus metrics and optionally receive OTLP traces where the test environment provides collectors
- keep credentials and SASL bearer material out of test logs

Docker interoperability smoke tests:

- live beside the deterministic fake-service E2E lane and must not replace it
- may use a separate Makefile target such as `make e2e-interop` or `make e2e-docker`
- use pinned container images or digests so local runs and CI do not drift silently
- use `chrroessner/postfix` for Postfix-backed protocol peer scenarios where Postfix behavior is part of the externally visible contract
- use Dovecot project-provided Docker assets for IMAP, POP3, LMTP and ManageSieve backend interoperability once those protocol entrypoints exist
- use real Redis or the same Redis-compatible service policy as the guardrail lane
- skip with an explicit, stable message when Docker is unavailable or the corresponding production protocol entrypoint does not exist yet
- prove interoperability with real server behavior, packaging assumptions, listener exposure and TLS/backend-auth settings, while fake services continue to prove edge cases and deterministic director semantics

Local quality gate:

```text
make guardrails
```

`make guardrails` should include formatting, vet, lint, unit tests, race tests, E2E tests and build checks once the root production module exists.

## 22. Implementation milestones

### M0: Repository hygiene and foundation

Status: completed. The production root module, typed configuration loader,
Nauthilus auth boundary, routing resolver foundation, Redis state foundations,
OpenAPI workflow, CLI generated-client boundary, E2E harness scaffold and
`make guardrails` gate are in place for the IMAP MVP to start.

- keep the old implementation isolated under `poc/` as reference material only
- finalize package layout
- create the new production Go module skeleton under the root package layout
- add the approved foundation dependencies and tool pins to the production module
- add CI and basic test structure
- define public config schema from `docs/config/nauthilus-director.target.yml`
- implement typed config loading, canonical defaults, redacted/non-redacted dumps and validator-based validation
- align the director-side Nauthilus request/response models with the real HTTP JSON and gRPC contracts
- create the initial routing resolver abstraction and document `auth_attribute` plus hash fallback semantics
- create the E2E harness entrypoint and fake service structure so later protocol work can add externally observable tests immediately
- document the future Docker interoperability smoke lane without requiring Postfix or Dovecot containers before protocol entrypoints exist

### M1: IMAP MVP

Status: completed. The IMAP listener/session/proxy path, Nauthilus auth
boundary, director-owned routing, Redis-backed session affinity, backend
selection/authentication, secret-safe observability, deterministic fake-service
E2E lane, production server-binary entrypoint and pinned Dovecot
interoperability lane are in place.

- listener lifecycle
- IMAP greeting/CAPABILITY/STARTTLS/LOGIN/AUTH PLAIN
- Nauthilus auth call over the configured HTTP or gRPC transport
- routing resolver support for authenticated account attributes
- backend selection by active Redis-backed affinity or initial deterministic placement
- backend connect
- transparent proxy loop
- basic metrics/logging/tracing
- E2E proof for successful IMAP auth, routing resolver behavior, backend selection, active stickiness and secret-safe observable output, using deterministic fakes, the production `nauthilus-director` binary and Dovecot-backed Docker interoperability when the Docker lane is available

### M2: Backend runtime

Status: completed. Runtime-aware effective backend state, Redis-backed
backend/session/user control operations, health, maintenance, drain,
max-connection handling and deterministic fake-service E2E coverage are in
place. The production server binary now wires this runtime into the process
entrypoint used by IMAP and the control API. The real-server interoperability
lane additionally proves three Director processes sharing one Redis-compatible
state service across six Dovecot IMAP backends, including untagged default
backends, two explicit shards and distributed deep-health ownership.

- backend registry
- Redis-backed active affinity registry
- health checks
- maintenance mode
- max connection limits
- weighted/deterministic selection
- Redis-coordinated session registry
- graceful shutdown
- E2E proof for backend weight `0`, in/out, drain, user move and user kick
- Docker interop proof for cross-process active affinity, deep health checks,
  health-owner distribution, session kill, user kick, user move and hard
  backend drain against real Dovecot backends

### M3: REST API and client

Status: completed. The v1 generated OpenAPI REST boundary, generated client
SDK, `nauthilus-directorctl`, process-local listener runtime control, route
lookup, safe reload, config documentation guardrails, manpages and REST/CLI
parity proof are in place. The M3 route-lookup follow-up is closed by the
M2/M3 implementation, and the listener runtime-control follow-up is closed by
public-socket E2E proof through the production server and CLI binaries.
Binary-entry E2E proves CLI and REST state parity against the running
`nauthilus-director` process, and Docker interop proves the shared runtime
control surface against six real Dovecot backends behind three Director
processes.

The M3 user backend-pinning follow-up is complete. Operators can set, show and
clear one user-scoped concrete backend pin through generated REST and
`nauthilus-directorctl` commands without rewriting YAML. Backend pins are scoped
by protocol and backend pool, can target weight-zero or non-zero-weight
configured backends, bypass only the weight-zero selector exclusion, fail closed
for other backend safety exclusions and keep `users move` shard-targeted.
Public-boundary E2E starts the production server binary with three fake IMAP
backends in one pool, proves weight-zero commissioning, non-zero backend pinning,
active-strategy behavior, route lookup diagnostics and fail-closed pinned
backend failure. The detailed completion evidence lives in
`docs/specs/implementation/M3_USER_BACKEND_PINNING_FOLLOWUP.md`.

The M3 user placement-hold follow-up is complete. Operators can set, show and
clear a bounded user placement hold through generated REST and
`nauthilus-directorctl users hold` commands without rewriting YAML. Holds are
temporary runtime gates after identity resolution and before backend selection;
they do not choose a shard or backend, do not close existing sessions, and
clear removes only the hold. Public-boundary E2E starts the production server
binary with fake Nauthilus and fake IMAP backends, proves that a held login
waits without backend connections, sessions or reservations, applies a backend
pin as the same-shard migration target, clears the hold and verifies the waiting
login resumes on the target backend. The same lane proves unrelated IMAP traffic
continues normally, route lookup reports active hold context without mutation
or waiting, and `max_wait` temporary-fails without placement. The demo stack
also carries `contrib/demo-stack/scripts/prove-user-hold.sh` for an operator
proof against the Compose topology. The detailed completion evidence lives in
`docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`.

The follow-up million-scale runtime-state pass is complete within the M2/M3
scope. Runtime reads are cursor-paginated, reaping is due-time bounded, backend
capacity uses Redis Cluster-safe reservations, aggregate summaries avoid full
session listing and the optional Redis/Redis Cluster scale harness is documented
outside normal guardrails. The detailed completion evidence lives in
`docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`.

- OpenAPI-first workflow
- generated REST server boundary
- reproducible OpenAPI generation and stale-output check
- `/healthz`, `/readyz`
- backend list/show/maintenance/runtime operations
- process-local listener list/show/drain/resume operations
- session list/show/kill
- user list/show/move/kick/affinity/backend-pin/hold
- route lookup
- reload
- `nauthilus-directorctl`
- generated config documentation and stale-doc guardrails
- initial manpages for stable server/client command surfaces and the config file
  format
- E2E proof for REST and CLI managing the same Redis-backed runtime state and
  process-local listener socket state

### M4: Observability

Status: completed. The observability runtime, OTLP tracing, Prometheus
`/metrics` provider, structured log correlation, runtime instrumentation
coverage and deterministic fake-service E2E proof are in place. The detailed
completion evidence lives in
`docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`.

- OTLP exporter config
- traces for sessions/auth/routing/backend/proxy
- Prometheus metrics
- structured log correlation

### M5: LMTP Production

Status: completed. The production LMTP/LMTPS listener path, LMTP transaction
state machine, DATA/BDAT backend forwarding, peer authentication, recipient
identity lookup, runtime-aware same-backend placement, delivery-scoped
affinity, route lookup integration, observability coverage, deterministic
fake-service E2E proof and real Postfix-to-Director-to-Dovecot interop lane are
in place. The detailed completion evidence lives in
`docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`.

- production-ready LMTP and LMTPS entrypoints within the M5 scope
- LMTP state machine with DATA and BDAT handling
- LMTP STARTTLS, implicit TLS and client-auth handling
- truthfully mediated LMTP capability enforcement, including SMTPUTF8 and
  CHUNKING/BDAT boundaries
- recipient identity lookup through Nauthilus and routing through the resolver
  model
- delivery-scoped active-affinity holds for concurrent user-stateful placement
- single-backend transaction support
- same-backend-only multi-recipient handling
- per-recipient status mapping
- real Postfix-to-Director-to-Dovecot LMTP interoperability while preserving the
  existing Dovecot IMAP lane

### M6: ManageSieve / Sieve proxy

- ManageSieve pre-auth handling
- Nauthilus auth
- user placement hold gate after authoritative auth and before backend
  selection, backend connect, backend auth or proxy mode
- same-shard backend selection
- protocol/backend-pool-scoped backend-pin handling after the hold gate; do not
  reuse an IMAP or LMTP backend identifier as the concrete ManageSieve backend
- transparent proxying
- metrics/tracing without script leakage
- no Sieve script names, script contents, operator hold reasons, raw backend
  identifiers or raw error text as metric labels

### M7: POP3

- POP3 pre-auth state machine
- Nauthilus auth
- user placement hold gate after successful auth and routing fact resolution,
  before login success, backend selection, backend connect, backend auth or
  proxy mode
- backend selection
- protocol/backend-pool-scoped backend-pin handling after the hold gate; do not
  treat a client-supplied `USER` value as authoritative identity for hold
  enforcement
- transparent proxying
- temporary failure on hold timeout; never silently fall back to the old backend

### M8: Production hardening

- hardened Docker image
- systemd unit
- reload semantics
- pprof optional
- operational docs
- failure-mode docs
- rollout and operational migration guide
- document operator migration workflows that combine user placement holds,
  user moves, backend pins and active-affinity draining without rewriting YAML
  runtime configuration

## 23. Open decisions

All M0/M1 foundation decisions tracked in this document are settled enough to start implementation. New open decisions should be added here only when they are not already governed by the architecture, policy or target configuration above.

Known future decisions:

- Exact HTTP/gRPC routing resolver service contract for external routing services.
- Whether recipient lookup for LMTP should call a dedicated Nauthilus lookup mode, a generic routing service or a separate mailbox-directory service.
- Whether local OIDC token validation should ever be supported as an explicit non-default mode.
- Exact REST authorization model beyond initial bearer token and Nauthilus-backed OIDC delegation.

## 24. Immediate next steps

1. Treat the production `nauthilus-director` binary as the mandatory service
   entrypoint for future externally visible E2E and interoperability proof.
2. Keep the fast fake-service lane deterministic, but add or preserve at least
   one real-binary assertion whenever listener, control, routing, Redis or proxy
   bootstrap changes.
3. Proceed to M4 observability polish: OTLP exporter configuration, trace
   exporter lifecycle, richer Prometheus registration and operator-facing
   observability documentation.
4. Keep `make e2e-interop` as the real IMAP regression lane and run it whenever
   IMAP backend/proxy/bootstrap-sensitive code, runtime control, route lookup
   health ownership, or active-affinity behavior changes.
5. Start later protocol milestones only after the binary-entry IMAP/control
   baseline remains green.

The project should evolve as a small, sharp director: protocol-aware only where necessary, authenticated through Nauthilus, routed through director-owned facts and selectors, observable by default, and operationally safe enough to sit in front of real mail backends.
