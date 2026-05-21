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
- Do not ask Nauthilus for director routing decisions.
- Do not make the director a general-purpose load balancer.
- Do not introduce distributed consensus before the single-node semantics are correct.
- Do not hide backend failure behind vague errors. Failures must be observable and explainable.

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

The important point is separation of concerns: protocol handling must not become mixed with backend registry, Nauthilus client code and REST management.

### 5.1 Technical foundation

The engineering baseline is security-by-design, security-by-default, strict object-oriented boundaries in Go, intentional DRY and conservative dependency choices. Domain objects own their invariants; shared helpers are extracted when they remove real duplication without hiding protocol-specific behavior.

The new production codebase should start with a small set of explicitly approved foundation dependencies:

- Uber Fx (`go.uber.org/fx`) for application composition, lifecycle wiring and dependency injection.
- Viper for configuration loading and environment binding, including its `mapstructure`-based decode path.
- go-playground/validator (`github.com/go-playground/validator/v10`) for mandatory typed configuration validation after Viper/mapstructure decoding.
- `github.com/redis/go-redis/v9` pinned initially to `v9.19.0` for central
  production state: active user affinity, session coordination, operational
  caches and future distributed coordination needs. Redis support must be
  full-featured from the start, including ACL/auth, TLS, standalone, Sentinel
  and Cluster topologies, explicit timeouts, pooling, key namespacing, script
  execution and fail-closed behavior for required state.
- jsoniter for JSON paths where the project intentionally chooses it over the standard library.

These packages are accepted as architectural building blocks, not as blanket permission to add convenience dependencies. Additional vendor packages still need a concrete justification and should be avoided when a small local implementation is clearer, safer and cheaper to maintain.

OpenAPI is part of the foundation for the REST control API from the beginning. Because this project starts the production codebase from zero, the REST contract, generated REST server boundary, generated REST DTOs and generated client code should originate from the OpenAPI specification before hand-written REST handlers expand. This is not a retrofit model.

OpenAPI should not describe IMAP, POP3, LMTP, ManageSieve or backend-selection internals as REST concepts. Those remain explicit director domain models and are adapted at the REST boundary.

Configuration rules:

- YAML is the project default for examples, generated defaults and operator documentation.
- The Viper loader must support the common Viper configuration formats: YAML/YML, JSON, TOML, HCL, dotenv/env files and Java properties-style files where Viper supports them.
- Scalar config values must support Nauthilus-style environment expansion from
  the first production config loader. The supported placeholder syntax is
  `${NAME}` with `NAME` matching `[A-Za-z_][A-Za-z0-9_]*`; ordinary `$`
  characters remain literal and `$${NAME}` escapes a placeholder.
- Expansion happens after file/include/patch merging and before
  Viper/mapstructure decoding, typed validation and Viper environment
  overrides. Map keys are not expanded.
- Missing placeholders fail closed with a path-specific, secret-safe
  diagnostic. Errors must name the config path and missing variable, but never
  include the raw or partially expanded config value.
- Expanded values inherit the destination field's secret metadata. Redaction,
  `-P`, logs, metrics and REST config output must treat env-expanded secrets
  exactly like file-provided or literal secrets.
- Secret file paths may themselves be supplied via env expansion, for example
  `password_file: "${NAUTHILUS_DIRECTOR_REDIS_PASSWORD_FILE}"`. Inline secret
  values remain allowed only for typed secret fields and remain redacted by
  default.
- Viper and mapstructure are decoding tools only. The decoded typed config must be validated with go-playground/validator before it can become a runtime snapshot.
- Config decoding should reject unknown fields where the selected parser/decoder path can support strictness.
- Secret-bearing fields must use explicit secret metadata in the typed config model so redaction and `-P` behavior are deterministic.

Config inspection commands:

```text
nauthilus-director config dump -d --format yaml
nauthilus-director config dump -n --format yaml
nauthilus-director config dump -n -P --format yaml
```

Required semantics:

- `-d` prints canonical defaults only: full default configuration, deterministic key order, no environment, file, CLI or runtime overrides.
- `-n` prints non-default effective configuration after config value expansion
  and environment overrides: only values that differ from canonical defaults,
  redacted by default.
- `-P` includes protected credential values in config output. It must be explicit, never implied by another flag, and must not affect logs, metrics or REST responses.
- `--format` selects the output format for config dumps. The default is `yaml`; supported output formats should track the common Viper formats where serialization is practical.
- Config dump output is inspection output only. It must not include Redis runtime overrides unless a separate runtime-state command explicitly asks for them.

Generated code rules:

- approved generator: `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.0`
- generation must be available through a Makefile target
- generated artifacts should be committed when they are part of the build
- a check target must detect stale generated output
- generated REST server boundaries, DTOs and clients must stay at REST boundaries and adapt into explicit domain objects

### 5.2 Configuration target

The initial target configuration is documented as YAML in `docs/config/nauthilus-director.target.yml`.

It intentionally follows the same broad grouping style as Nauthilus config v2:

- `runtime`: process lifecycle, control server, shared timeouts and generic clients
- `observability`: logs, metrics, tracing and profiling
- `storage`: full Redis connection, security and topology configuration
- `auth`: Nauthilus authority definitions and transport selection
- `director`: mail listeners, routing, affinity, health, maintenance, backend pools and backends

This split keeps operational runtime concerns separate from the mail director domain. Nauthilus is still only an authentication authority; all backend selection remains under `director`.

Redis configuration lives in exactly one place: `storage.redis`. That includes connection topology, TLS, credentials and Redis key namespaces for affinity, sessions, user runtime state and backend runtime state. Active affinity uses Redis implicitly because Redis is the only production state backend for this project; no feature-specific Redis config subtree is part of the target schema.

OpenAPI is not a runtime configuration root. Specs belong under `docs/specs`, while generator configuration and stale-output checks belong in scripts and Makefile targets. Runtime config may later expose a control-server validation toggle, but code-generation metadata must not live in `nauthilus-director.target.yml`.

Documentation is maintained under `docs/`. Architecture notes, operator guides, target config examples, specs and manpages should not live at the repository root once the production tree takes shape. Manpages belong under `docs/man/`. Formal specs, including OpenAPI, belong under `docs/specs/`.

Config stability decision: the target configuration stabilizes by
implementation phase. Once a path is declared stable for a phase, it must not be
renamed, removed or semantically inverted without an explicit breaking-change
decision and matching docs, examples, migration notes and tests.

Stable for M0/M1:

- `runtime.process`, `runtime.servers.control`, `runtime.timeouts` and
  `runtime.clients`
- `observability`
- `storage.redis`, including topology, TLS, auth, pool, retry, health,
  key-prefix and namespace shape
- `auth.authorities`, including the HTTP-or-gRPC transport switch and OIDC
  delegation to Nauthilus
- `director.security`
- common listener fields: `protocol`, `service_name`, `network`, `address`,
  `authority`, `backend_pool`, `proxy_protocol` and `tls`
- `director.listeners.imap` and `director.listeners.imaps`
- `director.routing`, `director.affinity`, `director.health`,
  `director.maintenance` and `director.runtime_overrides`
- `director.backend_pools` and `director.backends` for the IMAP MVP, including
  backend TLS/SNI and backend authentication shape

Draft until their implementation phases:

- LMTP listener/backend details until M5
- ManageSieve listener/backend details until M6
- POP3 listener/backend details until M7
- protocol-specific config fields added for later capability negotiation,
  delivery semantics, script handling or backend protocol quirks

Draft sections may still move while their phase is being designed, but they
should follow the same grouping and naming style as the stable foundation.

The target file intentionally differs from the POC config where security and architecture decisions changed:

- passwords and secrets use file references instead of inline values
- `insecure_skip_verify` defaults to `false`
- Nauthilus has an explicit `transport` switch for HTTP or gRPC
- listeners and backends are keyed maps instead of arrays with embedded identifiers
- listeners refer to backend pools instead of relying on POC `match_identifier` lists
- the old `backend_server` root is replaced by `director.backends`
- routing, affinity, health and maintenance belong to the director domain

The implementation should treat unstabilized sections of this file as a draft
target, not as accidental compatibility with the archived POC schema.

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
  -> backend selection
  -> connect backend
  -> optional backend TLS / STARTTLS
  -> optional backend authentication / login replay
  -> proxy until EOF/error/timeout
  -> cleanup counters/session registry
```

## 7. Nauthilus integration

Nauthilus should be the authentication authority only. The director may ask Nauthilus to authenticate a user or to perform an identity lookup, but Nauthilus must not make director routing decisions. Backend selection is owned entirely by `nauthilus-director`.

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

No routing input belongs in this result. Backend selection runs after authentication and uses only director-owned routing state.

Example transport configuration:

```yaml
auth:
  authorities:
    default:
      transport: http # http or grpc
      http:
        endpoint: http://127.0.0.1:8080/api/v1/auth/json
        content_type: application/json
      grpc:
        address: 127.0.0.1:9443
        authority: nauthilus.local
```

### 7.1 SASL mechanisms and OIDC-backed credentials

The director must support both password-based and bearer-token based mail authentication mechanisms at the protocol boundary.

Required mechanisms for user-stateful protocols:

- `PLAIN`
- `LOGIN`, where the frontend protocol commonly exposes it
- `XOAUTH2`
- `OAUTHBEARER`

Mechanism handling rules:

- `PLAIN` and `LOGIN` provide username/password credentials.
- `XOAUTH2` and `OAUTHBEARER` provide bearer-token credentials. The token must be treated as authentication material and must never be logged, traced or exposed in metrics.
- The director may parse the SASL envelope enough to extract the authorization identity, authentication identity, bearer token and optional client metadata.
- The director must not validate OIDC issuer, signature, audience or scope locally unless the architecture later introduces an explicit local validation mode. The default production model delegates token validation to Nauthilus.
- The request sent to Nauthilus must include the original mechanism name so Nauthilus can apply mechanism-specific policy.
- SASL-IR is allowed where the frontend protocol supports it, but size limits and pre-auth timeouts still apply.

OIDC integration with Nauthilus:

- Nauthilus is the authority for OIDC discovery, token validation, issuer/audience/scope policy and identity mapping.
- The director config may carry issuer/audience/scope hints for operator visibility and request metadata, but those hints are not a local authorization decision.
- The director-to-Nauthilus transport must be TLS-protected when bearer-token mechanisms are enabled outside a fully trusted local transport.
- Control API OIDC/JWT authentication also goes through Nauthilus authority handling; the REST server should not grow a separate OIDC implementation with different policy.

Example mechanism configuration:

```yaml
auth:
  authorities:
    default:
      mechanisms:
        password:
          enabled: true
          names:
            - plain
            - login
        bearer:
          enabled: true
          names:
            - xoauth2
            - oauthbearer
          token_max_bytes: 16384
          validation: nauthilus
      oidc:
        enabled: true
        authority_mode: nauthilus
        issuer_hint: https://auth.example.org
        audience_hint: mail
        required_scopes:
          - email
```

### 7.2 HTTP JSON authentication request

The director uses only the HTTP JSON endpoint when `auth.authorities.<name>.transport` is `http`. The request body is the real structured Nauthilus auth DTO encoded as `application/json`. JSON is strict: unknown top-level fields are rejected. This means the director must not send fields such as `service`, nested `tls`, nested `proxy`, `listener`, `session_id`, `backend_identifier` or `routing_hint` in the JSON body unless Nauthilus adds those fields explicitly.

Current JSON request shape for password authentication:

```json
{
  "username": "user@example.org",
  "password": "secret",
  "client_ip": "203.0.113.10",
  "client_port": "54321",
  "client_hostname": "client.example.org",
  "client_id": "client-123",
  "external_session_id": "director-session-01HZY...",
  "user_agent": "imap-client/1.0",
  "local_ip": "192.0.2.10",
  "local_port": "993",
  "protocol": "imap",
  "method": "plain",
  "ssl": "on",
  "ssl_session_id": "tls-session-id",
  "ssl_client_verify": "SUCCESS",
  "ssl_client_dn": "CN=client,OU=mail",
  "ssl_client_cn": "client",
  "ssl_issuer": "CN=issuer",
  "ssl_client_notbefore": "2026-01-01T00:00:00Z",
  "ssl_client_notafter": "2026-12-31T23:59:59Z",
  "ssl_subject_dn": "CN=subject",
  "ssl_issuer_dn": "CN=issuer-dn",
  "ssl_client_subject_dn": "CN=client-subject",
  "ssl_client_issuer_dn": "CN=client-issuer",
  "ssl_protocol": "TLSv1.3",
  "ssl_cipher": "TLS_AES_256_GCM_SHA384",
  "ssl_serial": "serial-1",
  "ssl_fingerprint": "aa:bb:cc",
  "oidc_cid": "oidc-client-id",
  "auth_login_attempt": 1
}
```

Only `username` is always required by the structured DTO. `password` is required for normal authentication, but not for lookup mode or list-accounts mode.

Identity lookup uses the same endpoint and request body, without a password:

```text
POST /api/v1/auth/json?mode=no-auth
```

List-accounts uses:

```text
GET  /api/v1/auth/json?mode=list-accounts
POST /api/v1/auth/json?mode=list-accounts
```

The protocol identity belongs in `protocol`, not in a top-level `service` body field. The Nauthilus HTTP service is implied by the JSON endpoint and by server-side handler context.

Current successful HTTP JSON response:

```json
{
  "ok": true,
  "account_field": "account",
  "totp_secret_field": "totp",
  "backend": 2,
  "attributes": {
    "dn": ["cn=user,dc=example,dc=org"]
  }
}
```

For JSON authentication failures, Nauthilus returns HTTP `403` with an empty JSON body and response headers such as `Auth-Status`, `Auth-Wait` and `X-Nauthilus-Session`. Temporary failures return HTTP `500` with an `error` JSON body.

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

There is one routing model for this project: Nauthilus authenticates; the director selects the backend.

Nauthilus may return authentication status, account fields, backend type identifiers used internally by Nauthilus, attributes and session/correlation metadata. The director may use those values to understand the authentication result, but not to choose a mail backend.

The director's routing inputs are its own configuration and runtime state:

- username or normalized account key
- frontend protocol
- listener/service identity
- configured tenant or security-domain mapping, if added to the director config
- backend health and maintenance state
- max connection limits and weights
- Redis-backed active affinity and runtime override state

The v1 model keeps the Nauthilus client interface transport-neutral and selects the concrete HTTP or gRPC client from configuration. Both transports must return the same director-level auth outcome: authenticated, rejected or temporary failure, plus safe metadata for logging and correlation.

## 8. Backend selection

Backend selection must be deterministic, observable and safe.

Input candidates:

- username
- tenant/security-domain
- protocol
- listener match identifiers
- backend health state
- backend maintenance flag
- max connection limits
- weight

Selection modes:

```yaml
director:
  routing:
    default_selector: consistent_hash
    hash_key: username
    failover:
      enabled: true
      strategy: same_shard_then_any_healthy
```

Supported selector strategy candidates:

- consistent hash by username
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

For LMTP the default should be recipient-based.

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

Redis is the central production state store for active affinity and session coordination. Local in-process state may be used as a cache or fast path, but it must not be the source of truth for production active-user stickiness when multiple director instances exist.

Redis integration is a production subsystem, not a best-effort cache. It must support:

- ACL username and password-file based authentication
- TLS with CA, SNI/server name, minimum TLS version, optional client certificate and `insecure_skip_verify: false` by default
- standalone, Sentinel and Cluster deployment modes
- explicit connect, read, write, pool and retry timeouts
- pool sizing and idle-connection controls
- key prefixing and schema versioning so multiple environments can share Redis safely
- health checks that distinguish unavailable Redis from backend unavailability
- fail-closed behavior when Redis is required for active affinity: do not silently fall back to stateless hashing for user-stateful protocols

Redis state model decision:

- Active affinity and session coordination use per-affinity Redis key groups.
  Keys that must be touched atomically share a Redis Cluster hash tag derived
  from the normalized affinity key, for example `{aff:<affinity_hash>}`.
- The normal routing path uses small atomic Redis Lua scripts, not distributed
  locks. Scripts cover session open, heartbeat, close, expired-session reaping,
  user move, user kick, affinity clear and administrative pin changes.
- Scripts use Redis server time, update a generation counter and fail closed on
  ambiguous state. Administrative mutations should use compare-and-set style
  generation checks so concurrent CLI/API operations do not silently overwrite
  each other.
- Session liveness is lease-based. Each frontend session refreshes its lease;
  expired leases are removed by the next relevant script call or by a periodic
  reaper. A crashed director instance must not leave permanent active sessions.
- The affinity state expires only after the last matching session closes or
  expires, plus `idle_grace`. Administrative pins may persist until explicitly
  cleared or until an optional configured TTL expires.
- Backend runtime overrides live in separate Redis hashes keyed by backend
  identifier. They are versioned and persist until cleared unless an explicit
  TTL was requested for a temporary operation.
- Secondary indexes for REST/CLI listing are repairable convenience indexes.
  The per-affinity state group and backend runtime hashes remain the source of
  truth.

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

The affinity hash is derived from tenant and normalized user identity. Raw
usernames should not be required in Redis keys; any human-readable user details
stored for diagnostics must be optional, redaction-aware and never required for
routing correctness.

Production affinity key:

```text
tenant + normalized_username -> shard_tag + active_session_count + expiry_after_last_close
```

Protocol-specific backend resolution:

```text
tenant + normalized_username -> shard_tag
shard_tag + protocol -> backend_identifier
```

This matters for IMAP, POP3 and ManageSieve because clients can hold long-lived mailbox state. A reconnect or parallel connection for the same user must not silently land on a different backend while older sessions are still open.

For LMTP, the affinity identity is the recipient mailbox. If recipient identity maps to the same user/shard model as interactive protocols, delivery should prefer the same `shard_tag`. Multi-recipient transactions are accepted only when all accepted recipients resolve to the same backend target. The director does not split one incoming LMTP transaction across multiple backends.

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

Optional later:

- SASL-IR
- AUTHENTICATE LOGIN
- literal handling for LOGIN/AUTHENTICATE edge cases
- command pipelining robustness

After successful authentication, the director should connect to the selected backend, perform the configured backend authentication step and transition to transparent proxy mode.

Backend authentication is explicit and configurable. Nauthilus remains the preferred frontend authentication authority, but operators may decide whether the backend receives a master-user login or the original user credential material.

Supported backend auth modes for user-stateful protocols:

- `master_user`: the director authenticates to the backend with a configured master credential and opens the session as the authenticated user. This is the preferred production mode when the backend supports it.
- `credential_replay`: the director forwards the original authentication material to the backend after Nauthilus has accepted it. For `PLAIN` and `LOGIN`, this means username/password replay. For `XOAUTH2` and `OAUTHBEARER`, the original bearer mechanism and token are passed through to the backend.

Backend auth rules:

- The selected mode is configured per backend or inherited from a backend-pool/default policy once such inheritance exists.
- `master_user` requires secret-file based credentials, backend TLS or another explicitly trusted private transport, and strict redaction.
- `credential_replay` must be opt-in because it extends the lifetime and blast radius of user passwords or bearer tokens inside the director.
- `credential_replay` must preserve the original mechanism name where the backend needs it.
- Both modes must avoid logging passwords, master credentials, SASL blobs and bearer tokens.
- If a backend cannot satisfy the selected auth mode, the session must fail closed before entering proxy mode.

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

Optional:

- APOP, likely not needed initially
- additional SASL AUTH mechanisms, if required

After authentication and backend selection, proxy transparently.

## 12. LMTP design

LMTP is not a login protocol. Routing happens per envelope recipient.

The frontend LMTP listener still needs transport security and optional client
authentication. This authenticates the submitting LMTP peer, not the mailbox
user and not the backend routing decision.

Required commands:

- LHLO
- STARTTLS
- AUTH, when listener client authentication is enabled
- MAIL FROM
- RCPT TO
- DATA
- RSET
- NOOP
- QUIT

The director uses a same-backend-only recipient routing strategy.

- Accept one transaction.
- Resolve each `RCPT TO` recipient through Nauthilus or a recipient lookup API before accepting it into the transaction.
- The first accepted recipient establishes the transaction backend target.
- Additional recipients are accepted only if they resolve to the same backend target.
- Recipients that resolve to another backend are rejected or temporary-failed before `DATA`, so the sending side can retry them in a separate transaction.
- `DATA` is forwarded only to the single selected backend for the accepted recipient set.
- The director must not spool one message body for replay to multiple backend groups.

LMTP must return per-recipient status.

Frontend LMTP security rules:

- Listener TLS supports `disabled`, `starttls` and `implicit` modes.
- STARTTLS is advertised only for `starttls` listeners; implicit TLS listeners do not advertise STARTTLS.
- LMTP client authentication supports mTLS and optional SASL-style `AUTH` mechanisms validated through the configured Nauthilus authority.
- `AUTH` identity is an ingress authorization identity for the submitting peer. It must not become the mailbox identity and must not drive backend selection.
- Deployments that expose LMTP beyond loopback or a strictly trusted private network should require TLS and either mTLS or LMTP AUTH.
- When listener TLS is disabled, the bind address and trusted network assumptions must be explicit in configuration and documentation.

Outbound LMTP client security rules:

- When the director connects to an LMTP backend, it acts as an LMTP client and must support backend TLS modes `disabled`, `starttls` and `implicit`.
- Backend TLS must support SNI via `tls.server_name`, CA validation, minimum TLS version and optional client certificate/key for mTLS.
- The outbound LMTP client must support backend authentication before `MAIL FROM`/`RCPT TO` when the selected backend requires it.
- Backend authentication may use mTLS, SASL-style service credentials or a future token source. It authenticates the director to the backend, not the mailbox user.
- Supported outbound LMTP AUTH mechanisms should include `PLAIN` and `LOGIN`; `XOAUTH2` and `OAUTHBEARER` are allowed when a configured service token source exists.
- Backend credentials and tokens must use secret-file references and must never be logged.

## 13. Sieve / ManageSieve design

Sieve itself is the mail filtering language, but clients usually talk to a ManageSieve service to upload and manage Sieve scripts. For this project, `nauthilus-director` should not execute Sieve scripts. It should proxy ManageSieve to the correct backend.

The useful feature is routing a user to the same mailstore for IMAP and ManageSieve.

Target protocol:

- ManageSieve, usually TCP port 4190
- optional TLS or STARTTLS
- SASL authentication, including PLAIN, LOGIN, XOAUTH2 and OAUTHBEARER

Frontend commands/capabilities to handle before proxy mode:

- server greeting / capabilities
- STARTTLS
- AUTHENTICATE PLAIN
- AUTHENTICATE XOAUTH2
- AUTHENTICATE OAUTHBEARER
- AUTHENTICATE LOGIN, optional
- LOGOUT

After authentication:

```text
ManageSieve client
  -> director authenticates via Nauthilus
  -> director selects same backend as IMAP for the user
  -> director connects to backend ManageSieve service
  -> director establishes backend auth/trust
  -> transparent proxy mode
```

Important requirements:

- The selected backend for ManageSieve must match the selected user's mailstore.
- Routing should use the same affinity key as IMAP unless explicitly configured otherwise.
- Backend protocol should be represented separately from frontend protocol: `sieve` or `managesieve`.
- Sieve script contents should not be logged.
- Traces and logs must avoid recording script bodies.
- Metrics may count commands but must not include script names as high-cardinality labels by default.

Target configuration shape:

```yaml
director:
  listeners:
    sieve:
      protocol: sieve
      service_name: sieve
      network: tcp
      address: "127.0.0.1:4190"
      authority: default
      backend_pool: sieve-default
      tls:
        mode: starttls
      sieve:
        capabilities:
          - SASL=PLAIN
          - SASL=XOAUTH2
          - SASL=OAUTHBEARER
          - STARTTLS
        auth_mechanisms:
          - plain
          - xoauth2
          - oauthbearer

  backend_pools:
    sieve-default:
      protocol: sieve
      selector: rendezvous_hash
      backends:
        - mailstore-a-sieve

  backends:
    mailstore-a-sieve:
      protocol: sieve
      shard_tag: mailstore-a
      address: "127.0.0.1:4190"
      weight: 100
      max_connections: 500
      tls:
        mode: starttls
        ca_file: /etc/nauthilus-director/mailstore-ca.pem
        server_name: mailstore-a.example.org
        insecure_skip_verify: false
      health_check:
        enabled: true
        deep_check: true
```

Decision: use separate backend entries per protocol and connect them through the same `shard_tag`. This avoids assuming IMAP, LMTP and ManageSieve ports live on identical host/port definitions while preserving user affinity.

## 14. REST control API

The director should expose an administrative REST API for introspection, controlled automation and eventually a CLI/client.

It must not be part of the mail protocol data path. It should be optional and bind to localhost or a protected management interface by default.

Deployment decision for v1: the REST control API runs inside the main
`nauthilus-director` process on its own `runtime.servers.control` listener. It
shares the same typed config snapshot, Redis-backed runtime state, lifecycle and
observability wiring as the mail protocol listeners, but it remains isolated
from the mail data path by listener, authentication, authorization and handler
boundaries.

A separate management process is not part of the v1 architecture. A future
control-only mode may be designed later, but only as an explicit architecture
extension with its own lifecycle, health and state-coordination rules.

### 14.1 Authentication

Supported authentication modes:

- disabled
- static bearer token
- mTLS
- reverse-proxy authenticated headers
- OIDC/JWT via Nauthilus

Target v1 configuration:

```yaml
runtime:
  servers:
    control:
      enabled: true
      address: "127.0.0.1:9090"
      auth:
        bearer:
          enabled: true
          token_file: /etc/nauthilus-director/control-token
        oidc:
          enabled: true
          authority: default
          validation: nauthilus
          required_scopes:
            - nauthilus-director.admin
```

The control API must never write the YAML configuration file. Mutating operations change runtime state only. Runtime state lives in Redis and is reflected into in-process snapshots; configuration remains the immutable baseline until an operator changes and reloads it outside the API.

### 14.2 Endpoints

Health:

```text
GET /healthz
GET /readyz
```

Version and config:

```text
GET /api/v1/version
GET /api/v1/config/effective
GET /api/v1/config/defaults
GET /api/v1/config/non-default
POST /api/v1/reload
```

REST config endpoints must redact protected values. Credential-bearing config output is a local CLI/server-binary feature only and requires `-P`.

Backends:

```text
GET /api/v1/backends
GET /api/v1/backends/{identifier}
POST /api/v1/backends/{identifier}/maintenance
DELETE /api/v1/backends/{identifier}/maintenance
POST /api/v1/backends/{identifier}/healthcheck
PUT /api/v1/backends/{identifier}/runtime/weight
POST /api/v1/backends/{identifier}/runtime/in
POST /api/v1/backends/{identifier}/runtime/out
POST /api/v1/backends/{identifier}/runtime/drain
DELETE /api/v1/backends/{identifier}/runtime
```

Sessions:

```text
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
DELETE /api/v1/sessions/{session_id}
```

Users:

```text
GET /api/v1/users
GET /api/v1/users/{user_key}
GET /api/v1/users/{user_key}/sessions
GET /api/v1/users/{user_key}/affinity
PUT /api/v1/users/{user_key}/affinity
DELETE /api/v1/users/{user_key}/affinity
POST /api/v1/users/{user_key}/move
POST /api/v1/users/{user_key}/kick
```

User management here means runtime routing/session management, not account directory CRUD. The API manages active sessions, Redis-backed affinity records and administrative pins for known users. User credentials, account lifecycle and identity policy remain owned by Nauthilus or the backing identity systems behind Nauthilus.

User move semantics:

- A move changes the user's Redis-backed affinity target to a new `shard_tag` or protocol-specific backend.
- Existing TCP sessions cannot be magically moved. The request must choose a strategy: `new_sessions_only`, `kick_existing`, or `drain_existing`.
- `kick_existing` terminates matching frontend sessions after recording an audit event.
- `drain_existing` keeps existing sessions on the old backend and sends new sessions to the new affinity target after the last old session closes or after an explicit grace expires.
- Moves must be observable through logs, traces, metrics and the route lookup endpoint.

Backend runtime override semantics:

- `runtime/weight` changes the effective runtime weight stored in Redis. Setting weight to `0` removes the backend from new initial placement while preserving the immutable configured weight.
- `runtime/out` makes a backend ineligible for new placements without editing configuration.
- `runtime/in` removes that runtime exclusion.
- `runtime/drain` combines `runtime/out` with an optional user/session drain plan.
- `DELETE /runtime` clears Redis-backed runtime overrides and returns to config-derived behavior.
- Active user pins may keep existing users on a backend with runtime weight `0` until they are moved, kicked, drained or the backend becomes hard-down/hard-maintenance.

Routing debug:

```text
POST /api/v1/route/lookup
```

Route lookup decision: this endpoint is a director-only routing diagnostic. It
does not authenticate credentials, does not call Nauthilus and does not ask
Nauthilus for identity or routing input. The caller supplies an already known or
operator-provided identity key, protocol and listener context; the director then
explains how its own config, Redis affinity, runtime overrides, health and
maintenance state would select a backend.

The endpoint must be side-effect free. It may read Redis-backed affinity and
runtime state, but it must not create sessions, refresh leases, mutate affinity,
perform backend auth or trigger Nauthilus auth/lookup calls. If a future
diagnostic needs to test Nauthilus authentication or identity normalization, it
must be a separate auth diagnostic surface, not part of `route/lookup`.

Example request:

```json
{
  "protocol": "imap",
  "username": "user@example.org",
  "client_ip": "203.0.113.10",
  "listener": "imaps"
}
```

Example response:

```json
{
  "selected_backend": "4174d130-50ef-4a7e-b413-7fed56280d0e",
  "reason": "consistent_hash",
  "healthy": true,
  "maintenance": false,
  "shard_tag": "mailstore-a"
}
```

Metrics and tracing helpers:

```text
GET /metrics
GET /debug/pprof/...
```

`/metrics` should be Prometheus format and may be served on a separate listener if desired.

## 15. CLI client

A small CLI client should make operations scriptable.

Initial binary name:

```text
nauthilus-directorctl
```

The client command grammar must use clean nested subcommands. The command
shape should be stable, discoverable through help output, and generated or
tested together with the REST contract where practical.

Example commands:

```text
nauthilus-director --version
nauthilus-directorctl status
nauthilus-directorctl --version
nauthilus-directorctl backends list
nauthilus-directorctl backends show <identifier>
nauthilus-directorctl backends maintenance enable <identifier> --reason "storage migration"
nauthilus-directorctl backends maintenance disable <identifier>
nauthilus-directorctl backends weight set <identifier> 0 --runtime --reason "drain host"
nauthilus-directorctl backends out <identifier> --reason "host maintenance"
nauthilus-directorctl backends in <identifier>
nauthilus-directorctl backends drain <identifier> --mode soft --reason "host replacement"
nauthilus-directorctl sessions list --protocol imap
nauthilus-directorctl sessions show <session-id>
nauthilus-directorctl sessions kill <session-id>
nauthilus-directorctl users list
nauthilus-directorctl users show user@example.org
nauthilus-directorctl users sessions user@example.org
nauthilus-directorctl users move user@example.org --to-shard mailstore-b --strategy kick-existing
nauthilus-directorctl users kick user@example.org --reason "operator requested reconnect"
nauthilus-directorctl users affinity clear user@example.org
nauthilus-directorctl route lookup --protocol imap --user user@example.org --client-ip 203.0.113.10
nauthilus-directorctl reload
```

Client config:

```yaml
server: http://127.0.0.1:9090
bearer_token_file: ~/.config/nauthilus-directorctl/token
request_timeout: 5s
output: table
```

Output modes:

- table
- json
- yaml

Operational list/show commands default to `table` for humans and support at least `json` and `yaml` for automation. Config dump commands default to `yaml` and support the common Viper config formats where serialization is practical.

Both binaries must implement `--version` and print at least version, commit, build date and Go version when those values are embedded at build time.

Go client package sketch:

```go
type Client struct {
    baseURL string
    token   string
    http    *http.Client
}

func (c *Client) ListBackends(ctx context.Context) ([]BackendStatus, error)
func (c *Client) GetBackend(ctx context.Context, id string) (*BackendStatus, error)
func (c *Client) SetMaintenance(ctx context.Context, id string, req MaintenanceRequest) error
func (c *Client) ClearMaintenance(ctx context.Context, id string) error
func (c *Client) SetRuntimeWeight(ctx context.Context, id string, req RuntimeWeightRequest) error
func (c *Client) SetBackendIn(ctx context.Context, id string, req BackendInRequest) error
func (c *Client) SetBackendOut(ctx context.Context, id string, req BackendOutRequest) error
func (c *Client) DrainBackend(ctx context.Context, id string, req BackendDrainRequest) error
func (c *Client) ClearBackendRuntimeOverride(ctx context.Context, id string) error
func (c *Client) ListSessions(ctx context.Context, filter SessionFilter) ([]SessionInfo, error)
func (c *Client) KillSession(ctx context.Context, id string) error
func (c *Client) ListUsers(ctx context.Context, filter UserFilter) ([]UserInfo, error)
func (c *Client) GetUser(ctx context.Context, key string) (*UserInfo, error)
func (c *Client) MoveUser(ctx context.Context, key string, req UserMoveRequest) error
func (c *Client) KickUser(ctx context.Context, key string, req UserKickRequest) error
func (c *Client) ClearUserAffinity(ctx context.Context, key string) error
func (c *Client) LookupRoute(ctx context.Context, req RouteLookupRequest) (*RouteLookupResponse, error)
func (c *Client) Reload(ctx context.Context) error
```

The CLI must use the generated OpenAPI REST client SDK as its HTTP transport
boundary. Hand-written CLI code may provide command structure, configuration,
output formatting and operator-friendly error messages, but it must not maintain
a parallel REST client model or duplicate request/response DTOs. If a thin
domain facade is useful, it should wrap the generated SDK and translate into
CLI-facing commands without changing the REST contract.

CLI mutating commands must state whether they change runtime state or request a reload. Runtime operations write Redis-backed state only; they must not patch, rewrite or persist changes into the YAML configuration.

### 15.1 REST contract and code generation

The REST API and `nauthilus-directorctl` should use an OpenAPI-first workflow from hour zero.

Generator decision: use `oapi-codegen` `v2.7.0` from
`github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen`. The initial
generated surface should use Go's standard `net/http` server style, strict
server interfaces, generated models and a generated client-with-responses SDK
for `nauthilus-directorctl`. The generator version and configuration schema
version must be pinned, and generation must be reproducible through Makefile
targets.

Repository layout:

```text
docs/specs/openapi/nauthilus-director.yaml
docs/man/
internal/rest/generated/
internal/rest/adapters/
internal/client/generated/
scripts/generate-openapi.sh
```

Expected Makefile targets once the REST contract exists:

```text
make generate-openapi
make check-openapi
```

The generated surface should initially be narrow:

- REST server interfaces or route binding code
- REST request/response DTOs
- generated REST client SDK for `nauthilus-directorctl`
- client models generated from the same OpenAPI contract
- manpage sources under `docs/man/` when CLI commands become stable

The generated surface should not own the mail protocol state machines, backend registry, selector, health model or Nauthilus transport implementation. Those remain explicit domain objects with hand-written tests.

Hand-written REST code should implement generated interfaces and translate
generated DTOs into director domain objects. `nauthilus-directorctl` should call
the generated client SDK and translate CLI flags/subcommands into generated
request objects. Avoid parallel hand-written REST structs or clients that
duplicate generated OpenAPI models.

## 16. OpenTelemetry

OpenTelemetry should be first-class from the beginning, not bolted on later.

Observability label decision: metrics use a strict low-cardinality allowlist.
Anything outside that allowlist must not become a Prometheus label without an
explicit architecture update, tests and a cardinality review. Logs and traces may
carry additional diagnostic attributes when they are redaction-safe, but secrets
and authentication material are never allowed in any observability output.

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

`route` must be the OpenAPI route template, never the raw request path.
`reason_class` must be a bounded enum, not raw error text. Per-backend details
belong in REST, logs and traces; metrics aggregate by pool, shard and protocol.

### 16.1 Traces

Trace boundaries:

- accepted frontend session
- protocol pre-auth phase
- Nauthilus authentication request
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
nauthilus_director.backend.select
nauthilus_director.backend.connect
nauthilus_director.proxy.pipe
nauthilus_director.rest.request
```

Initial span attributes:

```text
service.name = nauthilus-director
mail.protocol = imap|pop3|lmtp|sieve
mail.service = imap|imaps|pop3|pop3s|lmtp|lmtps|sieve
net.peer.ip = client IP
net.peer.port = client port
server.address = listener address
server.port = listener port
session.id = internal session id
backend.identifier = selected backend identifier
backend.shard_tag = selected shard
backend.protocol = imap|pop3|lmtp|sieve
nauthilus.decision = accept|reject|tempfail
```

Avoid high-cardinality or sensitive attributes by default:

- raw username
- password
- Sieve script names/content
- full recipient list
- full commands

Use hashed or redacted values if needed:

```text
user.hash = sha256(username + configured_salt)
recipient.count = 3
```

### 16.2 Trace propagation

For REST and Nauthilus HTTP calls, use W3C trace context headers.

The director should propagate trace context to Nauthilus so that traces can show:

```text
mail client session
  -> director pre-auth
    -> Nauthilus auth request
      -> Redis / LDAP / Lua / auth pipeline spans inside Nauthilus
  -> director backend connect
  -> proxy lifetime
```

For raw IMAP/POP3/LMTP/Sieve clients there is no standard trace context. The director creates the root span for those sessions.

### 16.3 Metrics

Prometheus metrics should include:

```text
nauthilus_director_sessions_active{protocol,service,listener}
nauthilus_director_sessions_total{protocol,service,listener,result}
nauthilus_director_auth_total{protocol,service,mechanism,transport,result}
nauthilus_director_auth_duration_seconds{protocol,service,mechanism,transport,result}
nauthilus_director_backend_connections_active{backend_pool,shard_tag,protocol}
nauthilus_director_backend_connections_total{backend_pool,shard_tag,protocol,result}
nauthilus_director_backend_health{backend_pool,shard_tag,protocol}
nauthilus_director_backend_maintenance{backend_pool,shard_tag,protocol,maintenance_mode}
nauthilus_director_backend_runtime_override{backend_pool,shard_tag,operation}
nauthilus_director_backend_select_total{protocol,backend_pool,shard_tag,reason_class,result}
nauthilus_director_user_move_total{protocol,result,strategy}
nauthilus_director_user_kick_total{protocol,result}
nauthilus_director_proxy_bytes_total{protocol,direction,backend_pool,shard_tag}
nauthilus_director_proxy_duration_seconds{protocol,backend_pool,shard_tag,result}
nauthilus_director_lmtp_recipients_total{result,backend_pool,shard_tag}
nauthilus_director_lmtp_transactions_total{result}
nauthilus_director_rest_requests_total{route,method,status_class}
nauthilus_director_rest_request_duration_seconds{route,method,status_class}
```

Cardinality rules:

- Labels must come from the allowlist above.
- `backend_pool` and `shard_tag` are acceptable; raw backend identifiers are not
  metrics labels.
- `protocol`, `service`, `listener`, `result`, `reason_class`, `transport`,
  `mechanism`, `direction`, `method`, `route` and `status_class` must be
  bounded enums or route templates.
- Never label by raw username, user hash, raw recipient, session ID, trace ID,
  request ID, client IP, raw backend identifier, token, password, SASL blob or
  raw error text.

### 16.4 Logs

Use structured logs. Every session log should include:

```text
session_id
protocol
service
client_ip
listener
backend_identifier, after selection
result
error, if any
```

Sensitive values must be redacted:

- passwords
- auth blobs
- OAuth/OIDC bearer tokens
- Sieve script bodies
- full message content

## 17. Health checks

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

Health state should include:

```go
type BackendHealth struct {
    Identifier       string
    Protocol         string
    Healthy          bool
    LastError        string
    LastCheckedAt    time.Time
    ConsecutiveFails int
    ConsecutiveOK    int
    Latency          time.Duration
}
```

Avoid flapping with thresholds:

```yaml
director:
  health:
    unhealthy_after: 3
    healthy_after: 2
    jitter: 500ms
```

## 18. Maintenance mode

Maintenance mode should prevent new sessions from being assigned to a backend while optionally allowing existing sessions to drain.

Maintenance semantics decision: soft and hard maintenance are separate
operational states, not aliases for runtime weight `0`.

Modes:

```text
soft: no new initial placements, existing sessions remain
hard: no new sessions, existing sessions may be killed after grace period
disabled: normal operation
```

Soft maintenance:

- The backend is excluded from new initial placements and normal balancing.
- Existing sessions remain until they close naturally, are kicked, are moved or
  the backend becomes hard-down/hard-maintenance.
- For user-stateful protocols, active pins that already point to the backend may
  continue to receive additional sessions for the same affinity key while the
  user still has active sessions there, unless an explicit drain or move policy
  says otherwise. This preserves mailbox state and avoids splitting a live user
  across backends.
- New users without an active pin must not be assigned to a soft-maintenance
  backend.

Hard maintenance:

- The backend is excluded from all new sessions, including sessions that would
  otherwise follow an active pin.
- Existing sessions are terminated after the requested grace period. A request
  may choose immediate termination by setting grace to zero.
- Active affinity may move away from hard-maintenance backends. Such movement is
  explicit, logged, traced and counted.

Drain is an operational workflow built on top of maintenance and runtime state:

- `runtime/drain` makes the backend ineligible for new initial placement.
- Existing sessions follow the requested strategy: keep until close, kick after
  grace, or move after grace where the protocol and state model allow it.
- Drain operations must record audit metadata: actor, reason, mode, requested
  grace, affected backend and affected session/user counts.

Runtime weight `0` is weaker than maintenance. It removes a backend from
weighted initial placement, but it does not by itself imply hard exclusion,
session termination or maintenance audit semantics.

REST API should allow setting maintenance with reason and optional expiry:

```json
{
  "mode": "soft",
  "reason": "storage migration",
  "grace": "5m",
  "expires_at": "2026-05-17T02:00:00Z"
}
```

## 19. Configuration reload

Reload should be explicit and safe.

Reloadable:

- listener additions
- listener removals with graceful drain
- backend additions/removals
- backend maintenance defaults
- weights
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
4. Apply listener/backend changes.
5. Keep existing sessions on old backend object until closed.
6. New sessions use the new snapshot.

## 20. Security model

The director is in the authentication path and must be treated as security-sensitive. Security-by-design and security-by-default are hard requirements: the secure behavior must be the normal configured path, not an optional hardening appendix.

Rules:

- Never log credentials.
- Never log raw SASL blobs.
- Avoid logging Sieve script contents.
- Use strict timeouts on unauthenticated sessions.
- Limit pre-auth command size.
- Limit line length and literal size.
- Protect REST API by default.
- Prefer localhost or management network binding for REST.
- Support mTLS for REST later.
- Support TLS min version configuration.
- Avoid `skip_verify` in production examples.
- Explicitly document trusted backend network assumptions.

## 21. Testing strategy

Unit tests:

- config validation
- TLS config mapping
- IMAP parser edge cases
- POP3 parser edge cases
- LMTP parser edge cases
- ManageSieve parser edge cases
- backend selector determinism
- Redis-backed active affinity, user moves and user kicks
- health state transitions
- REST handlers
- Nauthilus client error mapping
- Nauthilus structured request mapping, including rejection of unknown JSON fields such as `service`
- SASL XOAUTH2/OAUTHBEARER parsing with secret-safe diagnostics
- OIDC/JWT control API delegation to Nauthilus
- LMTP listener client-auth handling as ingress authorization, separate from recipient routing

Integration tests:

- fake IMAP backend
- fake POP3 backend
- fake LMTP backend
- fake ManageSieve backend
- fake Nauthilus auth endpoint
- TLS and STARTTLS flows
- LMTP AUTH and mTLS listener authorization flows
- HAProxy PROXY protocol flows
- backend down / maintenance / max connections
- backend runtime weight `0`, runtime in/out and drain operations
- user move/kick flows across active sessions

End-to-end tests are required for externally visible behavior from the first
production milestones. They must prove the product from the outside by starting
real director processes and talking to real sockets, REST endpoints and CLI
commands. They must not prove behavior by importing internal Go packages or
calling in-process helpers.

E2E tests:

- run through `make e2e`
- use fake or containerized Nauthilus authorities over HTTP and gRPC
- use fake IMAP, LMTP, ManageSieve and POP3 backends that expose protocol-level
  observations
- use real Redis or a Redis-compatible test service for active affinity and
  runtime overrides
- authenticate through the public protocol listener, then assert backend
  routing externally
- verify active-user stickiness across parallel connections and reconnects
- verify user move, user kick, backend weight `0`, backend in/out and drain via
  REST and `nauthilus-directorctl`
- verify TLS/STARTTLS and backend TLS/SNI behavior with test certificates
- verify config dump, redaction, `-P`, env expansion and `--version` through
  the binaries
- scrape Prometheus metrics and optionally receive OTLP traces where the test
  environment provides collectors
- keep credentials and SASL bearer material out of test logs

CI:

```text
go test ./...
go test -race ./...
make e2e
golangci-lint run
govulncheck ./...
gofmt/gofumpt check
```

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
- create the initial OpenAPI spec, generated REST boundary and generator/check Makefile targets before implementing REST handlers
- create the E2E harness entrypoint and fake service structure so later
  protocol work can add externally observable tests immediately

### M1: IMAP MVP

- listener lifecycle
- IMAP greeting/CAPABILITY/STARTTLS/LOGIN/AUTH PLAIN
- Nauthilus auth call over the configured HTTP or gRPC transport
- backend selection by active Redis-backed affinity or initial deterministic placement
- backend connect
- transparent proxy loop
- basic metrics/logging
- E2E proof for successful IMAP auth, backend selection, active stickiness and
  secret-safe observable output

### M2: Backend runtime

- backend registry
- Redis-backed active affinity registry
- health checks
- maintenance mode
- max connection limits
- weighted/deterministic selection
- Redis-coordinated session registry
- graceful shutdown
- E2E proof for backend weight `0`, in/out, drain, user move and user kick

### M3: REST API and client

- OpenAPI-first workflow from hour zero
- generated REST server boundary
- reproducible OpenAPI generation and stale-output check
- `/healthz`, `/readyz`
- backend list/show/maintenance
- session list/show/kill
- user list/show/move/kick/affinity
- backend runtime weight/in/out/drain
- route lookup
- reload
- `nauthilus-directorctl`
- E2E proof for REST and CLI managing the same Redis-backed runtime state

### M4: OpenTelemetry

- OTLP exporter config
- traces for sessions/auth/backend/proxy
- Prometheus metrics
- structured log correlation

### M5: LMTP MVP

- LMTP state machine
- LMTP STARTTLS, implicit TLS and client-auth handling
- recipient routing
- single-backend transaction support
- same-backend-only multi-recipient handling
- per-recipient status mapping

### M6: ManageSieve / Sieve proxy

- ManageSieve pre-auth handling
- Nauthilus auth
- same-shard backend selection
- transparent proxying
- metrics/tracing without script leakage

### M7: POP3

- POP3 pre-auth state machine
- Nauthilus auth
- backend selection
- transparent proxying

### M8: Production hardening

- hardened Docker image
- systemd unit
- reload semantics
- pprof optional
- operational docs
- failure-mode docs
- rollout and operational migration guide

## 23. Open decisions

All M0/M1 foundation decisions tracked in this document are settled. New open
decisions should be added here only when they are not already governed by the
architecture, policy or target configuration above.

## 24. Immediate next steps

1. Create the new production Go module skeleton under the root package layout.
2. Add the approved foundation dependencies and tool pins to the production module.
3. Implement typed config loading, canonical defaults, redacted/non-redacted dumps and validator-based validation against `docs/config/nauthilus-director.target.yml`.
4. Add the initial OpenAPI specification under `docs/specs/openapi/nauthilus-director.yaml` and wire reproducible generation/check targets.
5. Build the E2E harness with fake Nauthilus and fake backend test servers before expanding production protocol code.
6. Implement the IMAP MVP end-to-end with Redis-backed active affinity, basic metrics, structured logs, trace boundaries and externally observable E2E coverage.

The project should evolve as a small, sharp director: protocol-aware only where necessary, authenticated through Nauthilus, observable by default, and operationally safe enough to sit in front of real mail backends.
