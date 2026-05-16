# nauthilus-director Architecture and Roadmap

Status: working design document

This document captures the intended direction for `nauthilus-director` as a production-grade mail protocol director/proxy tightly integrated with Nauthilus. It is intentionally ambitious: it should guide the next weeks of implementation work and keep architectural decisions explicit.

## 1. Purpose

`nauthilus-director` is intended to become a lightweight, observable and policy-aware replacement for the Dovecot Director use case.

It should not become a full IMAP, POP3, LMTP, ManageSieve or Sieve implementation. Its job is to terminate or pass through the minimum protocol surface required for authentication, routing, policy decisions, health-aware backend selection and observability, and then proxy traffic to the selected backend service.

The core idea:

```text
client
  -> nauthilus-director
      -> optional TLS / STARTTLS / HAProxy PROXY protocol
      -> protocol-specific pre-auth state machine
      -> Nauthilus authentication / lookup / policy decision
      -> deterministic backend selection
      -> transparent bidirectional proxying
          -> Dovecot / LMTP / ManageSieve / POP3 backend
```

The director should be operationally boring: predictable, inspectable, reloadable, measurable and safe under failure.

## 2. Non-goals

The project should deliberately avoid the following traps:

- Do not implement a complete IMAP server.
- Do not implement mailbox semantics.
- Do not parse every post-auth command unless required for safe proxy operation.
- Do not duplicate Nauthilus policy logic inside the director.
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
- Nauthilus requests
- logging
- metrics
- tracing
- graceful shutdown

## 4. Current foundation

The existing repository already points in the correct direction:

- configuration model for listeners
- listener kind separation, currently including IMAP and LMTP
- capability and authentication mechanism configuration
- backend server model with protocol, identifier, weight, max connections, maintenance, deep check and TLS settings
- Nauthilus HTTP endpoint configuration
- validation via `go-playground/validator`
- Viper-based configuration handling

This is a good starting point. The missing part is not primarily configuration. The missing part is the runtime architecture: protocol state machines, routing state, health state, proxy loops, observability and tests.

## 5. High-level components

Proposed package layout:

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

This can be adjusted, but the important point is separation of concerns: protocol handling must not become mixed with backend registry, Nauthilus client code and REST management.

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
  -> Nauthilus auth / lookup / policy
  -> backend selection
  -> connect backend
  -> optional backend TLS / STARTTLS
  -> optional backend authentication / login replay
  -> proxy until EOF/error/timeout
  -> cleanup counters/session registry
```

## 7. Nauthilus integration

Nauthilus should be the policy and authentication authority. The director should ask Nauthilus for decisions, but should remain capable of deterministic fallback routing if Nauthilus returns only user attributes and no explicit backend.

### 7.1 IMAP/POP3/ManageSieve authentication request

Candidate JSON request:

```json
{
  "username": "user@example.org",
  "password": "secret",
  "client_ip": "203.0.113.10",
  "service": "imap",
  "protocol": "imap",
  "session_id": "...",
  "listener": "imaps",
  "tls": {
    "enabled": true,
    "sni": "imap.example.org",
    "version": "TLS1.3",
    "cipher": "TLS_AES_256_GCM_SHA384"
  },
  "proxy": {
    "source_ip": "203.0.113.10",
    "source_port": 54321,
    "destination_ip": "192.0.2.10",
    "destination_port": 993
  }
}
```

Candidate response:

```json
{
  "authenticated": true,
  "username": "user@example.org",
  "subject": "user@example.org",
  "backend_identifier": "4174d130-50ef-4a7e-b413-7fed56280d0e",
  "backend_protocol": "imap",
  "shard_tag": "mailstore-a",
  "routing_hint": "stable",
  "session_id": "...",
  "policy": {
    "action": "accept",
    "reason": "authenticated",
    "ttl_seconds": 300
  },
  "attributes": {
    "uid": "...",
    "tenant": "default",
    "mail_host": "mailstore-a.example.org"
  }
}
```

### 7.2 Routing authority decision

There are two possible models.

Model A: Nauthilus selects the backend.

- Pro: policy engine has full control.
- Pro: easiest to reason about from an auth/policy perspective.
- Con: Nauthilus must know director backend identifiers.

Model B: Nauthilus authenticates and returns attributes; the director selects the backend.

- Pro: director owns director-specific topology.
- Pro: Nauthilus remains less coupled.
- Con: policy cannot fully force backend unless a routing hint is standardized.

Recommended model: hybrid.

Nauthilus may return `backend_identifier` or `shard_tag`. If present and valid, the director honors it unless the backend is unhealthy or in maintenance. If absent, the director applies deterministic routing based on configured selector policy.

## 8. Backend selection

Backend selection must be deterministic, observable and safe.

Input candidates:

- explicit `backend_identifier` from Nauthilus
- `shard_tag` from Nauthilus
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
routing:
  mode: consistent_hash
  hash_key: username
  honor_nauthilus_backend_identifier: true
  honor_nauthilus_shard_tag: true
  failover:
    enabled: true
    strategy: same_shard_then_any_healthy
```

Possible selector strategies:

- explicit identifier
- consistent hash by username
- rendezvous hashing
- weighted round-robin for stateless flows
- least connections within shard
- fixed shard tag mapping

For IMAP/POP3/ManageSieve the default should be sticky/deterministic by user.

For LMTP the default should be recipient-based.

## 9. Session affinity

The director must preserve affinity for a user where required.

Minimal single-node affinity:

```text
username + protocol + tenant -> backend_identifier + expiry
```

Possible later distributed affinity backends:

- Redis
- Nauthilus-provided routing memory
- static hashing only, no shared state

Recommendation for v1: avoid distributed affinity. Use deterministic hashing plus optional local cache. If the same config is deployed on all director instances, rendezvous hashing should give stable decisions without shared mutable state.

## 10. IMAP design

The IMAP implementation should support only the pre-auth subset needed to authenticate and route.

Required frontend commands before proxy mode:

- CAPABILITY
- NOOP
- LOGOUT
- STARTTLS
- AUTHENTICATE PLAIN
- LOGIN
- ID, optional

Optional later:

- AUTHENTICATE LOGIN
- SASL-IR
- literal handling for LOGIN/AUTHENTICATE edge cases
- command pipelining robustness

After successful authentication, the director should connect to the selected backend and transition to transparent proxy mode.

Important design decision: backend login replay.

Options:

1. Replay original credentials to backend Dovecot.
2. Use a director/master credential to authenticate to backend as the user.
3. Use Dovecot proxy protocol / trusted forwarding mechanism if available.
4. Let Nauthilus be the only authenticator and use backend-side trusted auth.

For production, replaying user passwords is simple but not ideal. A better long-term target is trusted backend authentication with clear network boundaries and strict backend ACLs.

## 11. POP3 design

POP3 support should come after IMAP MVP.

Required commands before proxy mode:

- CAPA
- STLS
- USER
- PASS
- QUIT
- NOOP

Optional:

- APOP, likely not needed initially
- SASL AUTH, if required

After authentication and backend selection, proxy transparently.

## 12. LMTP design

LMTP is not a login protocol. Routing happens per envelope recipient.

Required commands:

- LHLO
- STARTTLS
- MAIL FROM
- RCPT TO
- DATA
- RSET
- NOOP
- QUIT

The director needs a recipient routing strategy.

Simplest v1 model:

- Accept one transaction.
- Collect all RCPT TO recipients.
- Resolve each recipient through Nauthilus or a recipient lookup API.
- If all recipients map to the same backend, forward normally.
- If recipients map to different backends, either:
  - split delivery into multiple backend LMTP transactions, or
  - reject/tempfail recipients that do not match the first selected backend.

Recommended production model: split by backend.

```text
incoming LMTP transaction
  recipients: a@example.org, b@example.org, c@example.org
  routing:
    backend-1: a@example.org, c@example.org
    backend-2: b@example.org
  DATA body is streamed/spooled once and replayed to each backend group
```

This requires careful memory and spool handling.

For small messages, memory buffering is acceptable. For larger messages, spool to disk with size limits and secure temporary files.

LMTP must return per-recipient status.

## 13. Sieve / ManageSieve design

Sieve itself is the mail filtering language, but clients usually talk to a ManageSieve service to upload and manage Sieve scripts. For this project, `nauthilus-director` should not execute Sieve scripts. It should proxy ManageSieve to the correct backend.

The useful feature is routing a user to the same mailstore for IMAP and ManageSieve.

Target protocol:

- ManageSieve, usually TCP port 4190
- optional TLS or STARTTLS
- SASL authentication, commonly PLAIN or LOGIN

Frontend commands/capabilities to handle before proxy mode:

- server greeting / capabilities
- STARTTLS
- AUTHENTICATE PLAIN
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

Possible config addition:

```yaml
x-defaultSieveListener: &x-defaultSieveListener
  kind: sieve
  type: tcp
  capability:
    - "SASL=PLAIN"
    - "STARTTLS"
  auth_mechanisms:
    - plain

backend_server:
  - protocol: sieve
    identifier: mailstore-a-sieve
    shard_tag: mailstore-a
    host: 127.0.0.1
    port: 4190
    weight: 100
    max_connections: 500
    check_interval: 5s
    deep_check: true
```

Open question: whether IMAP and ManageSieve should use the same backend identifier or separate protocol-specific backend identifiers sharing the same `shard_tag`.

Recommended: use separate backend entries per protocol, but same `shard_tag`. This avoids assuming IMAP, LMTP and ManageSieve ports live on identical host/port definitions while preserving user affinity.

## 14. REST control API

The director should expose an administrative REST API for introspection, controlled automation and eventually a CLI/client.

It must not be part of the mail protocol data path. It should be optional and bind to localhost or a protected management interface by default.

### 14.1 Authentication

Possible modes:

- disabled
- static bearer token
- mTLS
- reverse-proxy authenticated headers
- future: OIDC/JWT via Nauthilus

Recommended v1:

```yaml
rest:
  enabled: true
  listen: 127.0.0.1:9090
  auth:
    type: bearer
    token_file: /etc/nauthilus-director/rest-token
```

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
POST /api/v1/reload
```

Backends:

```text
GET /api/v1/backends
GET /api/v1/backends/{identifier}
POST /api/v1/backends/{identifier}/maintenance
DELETE /api/v1/backends/{identifier}/maintenance
POST /api/v1/backends/{identifier}/healthcheck
```

Sessions:

```text
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
DELETE /api/v1/sessions/{session_id}
```

Routing debug:

```text
POST /api/v1/route/lookup
```

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

## 15. REST client sketch

A small CLI client should make operations scriptable.

Possible binary name:

```text
nauthilus-directorctl
```

Example commands:

```text
nauthilus-directorctl status
nauthilus-directorctl backends list
nauthilus-directorctl backends show <identifier>
nauthilus-directorctl backends maintenance enable <identifier> --reason "storage migration"
nauthilus-directorctl backends maintenance disable <identifier>
nauthilus-directorctl sessions list --protocol imap
nauthilus-directorctl sessions show <session-id>
nauthilus-directorctl sessions kill <session-id>
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
func (c *Client) ListSessions(ctx context.Context, filter SessionFilter) ([]SessionInfo, error)
func (c *Client) KillSession(ctx context.Context, id string) error
func (c *Client) LookupRoute(ctx context.Context, req RouteLookupRequest) (*RouteLookupResponse, error)
func (c *Client) Reload(ctx context.Context) error
```

The CLI should be generated from or share models with the REST server to avoid drift.

## 16. OpenTelemetry

OpenTelemetry should be first-class from the beginning, not bolted on later.

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

Recommended span names:

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

Recommended span attributes:

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
    -> Nauthilus auth/policy request
      -> Redis / LDAP / Lua / policy engine spans inside Nauthilus
  -> director backend connect
  -> proxy lifetime
```

For raw IMAP/POP3/LMTP/Sieve clients there is no standard trace context. The director creates the root span for those sessions.

### 16.3 Metrics

Prometheus metrics should include:

```text
nauthilus_director_sessions_active{protocol,service}
nauthilus_director_sessions_total{protocol,service,result}
nauthilus_director_auth_total{protocol,service,result}
nauthilus_director_auth_duration_seconds{protocol,service,result}
nauthilus_director_backend_connections_active{backend,protocol}
nauthilus_director_backend_connections_total{backend,protocol,result}
nauthilus_director_backend_health{backend,protocol}
nauthilus_director_backend_maintenance{backend,protocol}
nauthilus_director_backend_select_total{protocol,reason,result}
nauthilus_director_proxy_bytes_total{protocol,direction,backend}
nauthilus_director_proxy_duration_seconds{protocol,backend,result}
nauthilus_director_lmtp_recipients_total{result,backend}
nauthilus_director_lmtp_transactions_total{result}
nauthilus_director_rest_requests_total{route,method,status}
nauthilus_director_rest_request_duration_seconds{route,method,status}
```

Cardinality rules:

- `backend` is acceptable if backend count is bounded.
- `protocol`, `service`, `result`, `reason` are acceptable.
- never label by raw username, raw recipient, session ID or client IP.

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
health:
  unhealthy_after: 3
  healthy_after: 2
  check_jitter: 500ms
```

## 18. Maintenance mode

Maintenance mode should prevent new sessions from being assigned to a backend while optionally allowing existing sessions to drain.

Modes:

```text
soft: no new sessions, existing sessions remain
hard: no new sessions, existing sessions may be killed after grace period
disabled: normal operation
```

REST API should allow setting maintenance with reason and optional expiry:

```json
{
  "mode": "soft",
  "reason": "storage migration",
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

The director is in the authentication path and must be treated as security-sensitive.

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
- health state transitions
- REST handlers
- Nauthilus client error mapping

Integration tests:

- fake IMAP backend
- fake POP3 backend
- fake LMTP backend
- fake ManageSieve backend
- fake Nauthilus auth endpoint
- TLS and STARTTLS flows
- HAProxy PROXY protocol flows
- backend down / maintenance / max connections

End-to-end tests later:

- Docker Compose with Dovecot backend instances
- Nauthilus test instance
- Prometheus scrape
- OTLP collector

CI:

```text
go test ./...
go test -race ./...
staticcheck ./...
govulncheck ./...
gofmt/gofumpt check
```

## 22. Suggested implementation milestones

### M0: Repository hygiene

- finalize package layout
- add CI
- add basic test structure
- document architecture
- define public config schema

### M1: IMAP MVP

- listener lifecycle
- IMAP greeting/CAPABILITY/STARTTLS/LOGIN/AUTH PLAIN
- Nauthilus auth call
- backend selection by explicit identifier or deterministic hash
- backend connect
- transparent proxy loop
- basic metrics/logging

### M2: Backend runtime

- backend registry
- health checks
- maintenance mode
- max connection limits
- weighted/deterministic selection
- session registry
- graceful shutdown

### M3: REST API and client

- `/healthz`, `/readyz`
- backend list/show/maintenance
- session list/show/kill
- route lookup
- reload
- `nauthilus-directorctl`

### M4: OpenTelemetry

- OTLP exporter config
- traces for sessions/auth/backend/proxy
- Prometheus metrics
- structured log correlation

### M5: LMTP MVP

- LMTP state machine
- recipient routing
- single-backend transaction support
- later multi-backend split delivery
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
- migration guide from Dovecot Director use cases

## 23. Important open decisions

1. Does Nauthilus return an explicit backend identifier, only attributes, or both?
2. Should IMAP, LMTP and ManageSieve backend entries be separate objects connected by `shard_tag`?
3. For backend authentication, do we replay user credentials or implement trusted backend auth?
4. For LMTP multi-recipient delivery, do we split by backend in v1 or defer?
5. Do we need distributed affinity, or is deterministic hashing enough?
6. Should the REST API live in the same process or optionally on a separate listener/process?
7. How much of the current config schema should be considered stable?
8. Which observability labels are allowed without cardinality risk?
9. Should route lookup call Nauthilus or only simulate director-side routing?
10. How should maintenance mode interact with active long-lived IMAP sessions?

## 24. Recommended immediate next steps

1. Add this document to the repository.
2. Create GitHub issues for M0 through M2 only.
3. Implement minimal runtime skeleton with clean interfaces.
4. Build fake backend test servers before implementing too much production code.
5. Make IMAP MVP work end-to-end.
6. Add metrics/tracing early, not after the protocol work is finished.

The project should evolve as a small, sharp director: protocol-aware only where necessary, policy-aware through Nauthilus, observable by default, and operationally safe enough to sit in front of real mail backends.
