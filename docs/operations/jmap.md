# JMAP Reverse Proxying

`nauthilus-director` can route JMAP (RFC 8620, RFC 8621) clients to JMAP
backends per account. A JMAP listener is an HTTPS reverse proxy: it
authenticates every request through Nauthilus, resolves the account's shard
with the same routing facts the mail protocols use, holds director placement
state while the request runs and forwards the request unchanged to the selected
JMAP backend.

The director never translates between JMAP and IMAP, POP3, LMTP or ManageSieve,
never interprets JMAP method calls and never aggregates accounts across
backends. A deployment whose backends do not speak JMAP cannot use this
listener.

## Request Flow

```text
JMAP client
  -> HAProxy or another TCP proxy (optional, PROXY v1/v2 from trusted CIDRs)
  -> nauthilus-director JMAP listener (implicit TLS, HTTP/1.1)
      -> path and method allowlist, header and body limits
      -> Basic: Nauthilus password check (protocol jmap, method plain)
         Bearer: introspection with the listener token policy,
                 then identity lookup (protocol jmap, method recipient_lookup)
      -> routing by the authenticated account (shard attribute, fail closed)
      -> user hold gate, operator pins, maintenance, active affinity
      -> short request hold, or a session lease for event streams
      -> backend connection owned by this client connection
         (PROXY v2 with the client address, verified TLS)
          -> JMAP backend (re-verifies the Authorization header)
```

## Listener And Transport

A JMAP listener is configured under `director.listeners.<name>` with
`protocol: jmap`. The default configuration defines no JMAP listener, so an
upgrade never opens a new port by itself.

- `tls.mode` must be `implicit`. The listener advertises only `http/1.1` in
  ALPN; HTTP/2 is not offered, so one frontend connection always belongs to one
  client.
- `proxy_protocol` works exactly as for the mail listeners: a peer inside
  `trusted_cidrs` sends one PROXY v1 or v2 header before TLS, and its source
  address becomes the client address for Nauthilus, logs and the backend.
- HAProxy health checks with `check-send-proxy` send a PROXY v2 `LOCAL` header
  (v1: `PROXY UNKNOWN`), which a listener refuses by default. Set
  `proxy_protocol.accept_local: true` on a listener that HAProxy checks: a
  trusted peer's `LOCAL`/`UNKNOWN` connection is then accepted and keeps its
  real TCP endpoints, while untrusted peers are still refused before anything
  is read. Point the check at `jmap.health_path`, for example
  `option httpchk GET /director/healthz` with `check check-ssl
  check-send-proxy`. Accepted LOCAL connections are counted with
  `result="local"` in `nauthilus_director_listener_lifecycle_total`.
- The TLS handshake and the request header are bounded by
  `jmap.timeouts.read_header`. The whole request, including an upload body, is
  bounded by `jmap.timeouts.read`. Idle keep-alive connections close after
  `jmap.timeouts.idle`. There is no write timeout, so event streams stay open
  for as long as the client and the backend keep them.
- Listener drain and shutdown disable keep-alive and close idle connections at
  once; running requests and event streams continue until they end, the hard
  drain grace expires or the shutdown deadline closes them. Resume enables
  keep-alive again.
- `jmap.health_path` (for example `/director/healthz`) optionally answers 200
  locally, without authentication and without touching a backend, for load
  balancer checks.

## Proxied Surface

Only these paths are forwarded; everything else is answered 404 without
authentication:

| Path | Methods | Endpoint label |
| --- | --- | --- |
| `/.well-known/jmap` | GET, HEAD | `session` |
| `/jmap/api/` (also `/jmap/api`) | POST | `api` |
| `/jmap/upload/{accountId}/` | POST | `upload` |
| `/jmap/download/{accountId}/{blobId}/{name}` | GET, HEAD | `download` |
| `/jmap/eventsource/` (also `/jmap/eventsource`) | GET | `eventsource` |

A path that is not in canonical form, such as `/jmap/api/../healthz` or
`/jmap//api/`, is not forwarded. The backend's own `/jmap/healthz` is not
reachable through the listener. Upload and download paths need at least one
segment after `/jmap/upload/` or `/jmap/download/`. A method the endpoint does
not accept, including `OPTIONS`, is answered 405 with an `Allow` header before
authentication. A request with an `Upgrade` header is answered 400: no request
switches protocols, and `Connection`/`Upgrade` are additionally removed from
every forwarded request.

Request bodies are limited to `jmap.limits.max_request_body_bytes` (default
10 MiB) and uploads to `jmap.limits.max_upload_body_bytes` (default 50 MiB).
A declared `Content-Length` above the limit is answered 413 before
authentication; a streamed body that grows past it is cut off and answered
413. Headers are limited to `jmap.limits.max_header_bytes` (default 64 KiB).
Choose limits at least as large as the backend's own (`max_size_request`,
`max_size_upload`), or clients see the director's 413 before the backend's
JMAP-level error.

Request and response bodies are streamed, never buffered. Range requests,
`Content-Disposition`, `Content-Security-Policy`, `X-Content-Type-Options`
and every other end-to-end header pass through unchanged; hop-by-hop headers
are handled per HTTP. The `Host` header keeps the public name the client used.
Client-supplied `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `X-Client-IP` and
`True-Client-IP` headers are removed: the client address reaches the backend
only through the PROXY header of the backend connection.

### Session Resource

The session resource is passed through unchanged. The backend must advertise
the director's public URL (`apiUrl`, `downloadUrl`, `uploadUrl`,
`eventSourceUrl`). When `jmap.public_base_url` is set, the director compares
the origin of these four URLs in every successful session response with it and
logs a `jmap.session_url` warning naming the mismatching property; it does not
rewrite the document.

## Authentication

Every request is authenticated; there are no sessions or cookies at the
director.

- **Basic** (`jmap.auth.basic.enabled`, default on): the user name and
  password go to the listener authority with protocol `jmap` and method
  `plain`. The authority result supplies the canonical account and the routing
  attributes.
- **Bearer** (`jmap.auth.bearer.enabled`, default off): the token is
  introspected (RFC 7662) at the introspection endpoint and with the client
  credentials of the listener authority
  (`auth.authorities.<name>.mechanisms.bearer.introspection`), but with the
  listener's own token policy: `required_audience` and/or `required_resource`
  (for example the RFC 8707 resource `https://mail.example.org/`),
  `required_scope` and `account_claim`. The mail SASL bearer policy of the
  authority is never inherited. `jmap.auth.bearer.introspection_client`
  optionally gives the listener its own introspection client (`client_id`,
  `auth_method`, and `client_secret_file` or `client_private_key_file` with
  `client_key_id`/`client_assertion_alg` for `private_key_jwt`), replacing the
  authority's client credentials for this listener only; IMAP, POP3 and
  ManageSieve keep the authority client. Without `client_id` the authority
  client is inherited. Secrets are accepted only as files; the file is checked
  for readability when the listener starts (a failure names the setting, never
  the path or content) and read again for every introspection, so rotation
  needs no restart. The token's account is then looked up without
  a credential (protocol `jmap`, method `recipient_lookup`), and the lookup
  result supplies the canonical account and the routing attributes, including
  the shard attribute that a token alone does not carry.

| Situation | Answer |
| --- | --- |
| No `Authorization` header | 401 with `WWW-Authenticate: Basic realm="…", charset="UTF-8"` and/or `Bearer realm="…"` |
| Unsupported scheme, malformed or oversized credential | 401 with the challenges, `error="invalid_token"` on Bearer |
| Rejected password, inactive token, wrong audience/resource/scope, unknown account | 401 with the challenges |
| Authority unreachable or temporary failure | 503 with `Retry-After` |

The `Authorization` header is forwarded to the backend unchanged; the backend
verifies every request itself, so JMAP backends use `auth.mode: none` at the
director and need no master user.

### Authentication Cache

Successful results are cached in process for `jmap.auth.cache.ttl` (default
30s, at most 10m) and up to `jmap.auth.cache.max_entries` (default 10000,
least recently used first out). The key is an HMAC-SHA-256, under a random key
created at process start, of the scheme, the credential and the client address,
so neither the credential nor a reusable digest of it is kept, a restart
invalidates the cache and every new client address reaches Nauthilus again.
Rejected and failed credentials are never cached. The cache only saves the
routing decision: the backend still verifies the credential of every request,
so a revoked password or token stops working at the backend immediately.

Credentials, tokens and `Authorization` headers never appear in logs, traces,
metrics or error responses.

## Routing

Requests are routed strictly by the authenticated account. Account identifiers
in the request path (`/jmap/upload/{accountId}/`, shared accounts in
`/jmap/download/…`) are never used for routing; access to other accounts is the
backend's authorization decision.

The shard comes from the `director.routing.auth_attributes.shard_tag`
attribute of the authority result (`mailShard` by default). When the attribute
is missing, JMAP fails closed by default:

| `jmap.routing.missing_shard` | Answer |
| --- | --- |
| `forbidden` (default) | 403 — the client should not retry with the same account |
| `unavailable` | 503 with `Retry-After` |
| `hash_fallback` | route by the rendezvous hash over the configured shards, like the mail protocols |

The mail protocols fall back to hashing when the directory has no shard
attribute for an account, whether the login used a password or a bearer token
(IMAP, POP3 and ManageSieve bearer logins resolve the token account through the
same identity lookup since `v1.1.2`), because an IMAP session that lands on the
wrong shard at least shows the wrong mailbox visibly; a JMAP client would
silently synchronise an empty account and write into the wrong store. A
multi-valued shard attribute is always an error (503).

## Placement And Affinity

JMAP uses the shared placement service, so operator user holds, backend pins
for `protocol: jmap`, maintenance, runtime weight, drain, health and active
affinity apply exactly as for the mail protocols. Placement keys are the
tenant and the canonical account, so IMAP, POP3, ManageSieve, LMTP and JMAP
of one account converge on the same `backend_node` while any of them holds the
binding — JMAP backends must therefore share `shard_tag` and `backend_node`
with the other protocol endpoints of the same mailstore.

- **Ordinary requests** open a short request hold for the request's lifetime
  (`jmap.placement.request_lease_ttl`, default 2m). A request that runs longer
  than half the TTL — a large upload, a slow download or API call — refreshes
  the hold every half TTL until it ends, so the binding never lapses under a
  running request. Request holds keep the backend-node binding like other
  holders but reserve no backend capacity and are not listed as sessions (they
  are stored with the non-session holder kind). Control actions do not cut
  ordinary requests; the next request is placed again.
- **Event streams** (`/jmap/eventsource/`) open a counted session lease for
  their whole lifetime. The lease is refreshed every
  `jmap.event_source.heartbeat_interval` (default 30s, at most half of
  `runtime.timeouts.proxy_idle`). A kick, drain or move control action seen at
  a heartbeat, a failed heartbeat, `nauthilus-directorctl users kick`,
  `sessions kill`, a backend drain or maintenance that closes existing
  sessions and a listener hard drain end the stream; the client reconnects
  and is placed again, possibly on a new backend. Event streams appear in `nauthilus-directorctl sessions list` with
  `protocol=jmap`.

A request that cannot be placed (no healthy backend, hold timeout, Redis
failure) is answered 503 with `Retry-After`.

### Operating Costs

Every proxied request, including each `GET /.well-known/jmap`, costs about
three Redis round trips for its hold (placement reads, open, close) plus the
user-hold check, and one more per half TTL for long requests. Event streams
add one heartbeat per `heartbeat_interval`. Nauthilus is contacted only on a
cache miss: once per credential and client address per `auth.cache.ttl`, twice
(introspection and lookup) for Bearer.

## Backend Connections

Backend connections are never shared between frontend connections. Each
frontend connection owns its own backend transports; every backend connection
starts with a PROXY v2 header naming that frontend connection's client address
(when `haproxy.enabled: true`), followed by verified TLS
(`tls.mode: implicit`, `ca_file`, `server_name`). Keep-alive reuse happens
only within one frontend connection, so a backend that trusts PROXY headers
always sees the right client for every request. All backend connections of a
frontend connection are closed when it closes. HTTP/2 is not used towards the
backend, responses are not decompressed and no proxy from the environment is
used.

Mail protocols keep writing PROXY v1; only JMAP writes v2.

## Health Checks

With `health_check.enabled: true`, a JMAP backend is probed with
`GET /jmap/healthz` over HTTPS, preceded by the PROXY header when
`haproxy.enabled` is true, within `director.health.timeout`. Any 2xx answer is
healthy. The probe carries no credentials; JMAP backends need no health
identity or password file, and `deep_check` is not supported.

## Observability

Every request produces one `jmap.request` event: at debug level when it was
proxied successfully, at info level when the director refused it or the backend
failed. Metrics:

- `nauthilus_director_jmap_requests_total`
- `nauthilus_director_jmap_request_duration_seconds` (includes event-stream
  lifetimes)

Labels: `protocol`, `listener`, `backend_pool`, `operation` (`session`, `api`,
`upload`, `download`, `eventsource`, `health`, `unknown`), `status_class`
(`2xx` … `5xx`, `none` for aborted streams), `result` (authentication outcome:
`authenticated`, `cached`, `missing`, `malformed`, `rejected`, `tempfail`,
`none`) and `reason_class` (`ok`, `auth`, `routing`, `no_backend`,
`backend_connect`, `timeout`, `size_body_too_large`, `not_found`,
`unsupported`, `control_action`, `canceled`, `unavailable`,
`temporary_failure`). Paths, account names, client addresses and backend
identifiers are never labels. Logs may name the backend identifier and shard
tag, never the account or a credential. Backend PROXY headers are counted in
`nauthilus_director_backend_proxy_protocol_total` like for the other protocols.

## Configuration

```yaml
director:
  listeners:
    jmap:
      protocol: jmap
      service_name: jmap
      network: tcp
      address: "0.0.0.0:8443"
      authority: default
      backend_pool: jmap-default
      proxy_protocol:
        enabled: true
        trusted_cidrs: ["10.0.0.0/8"]
        # HAProxy check-send-proxy health checks send PROXY v2 LOCAL.
        accept_local: true
      tls:
        mode: implicit
        cert: /etc/nauthilus-director/tls/tls.crt
        key: /etc/nauthilus-director/tls/tls.key
        min_tls_version: TLS1.2
      jmap:
        public_base_url: https://mail.example.org
        health_path: /director/healthz
        auth:
          realm: mail.example.org
          basic:
            enabled: true
          bearer:
            enabled: true
            required_resource: https://mail.example.org/
            required_scope: mail:account:read
            account_claim: mail_account
            # Optional: a dedicated introspection client for this listener.
            introspection_client:
              client_id: director-jmap-introspection
              auth_method: client_secret_basic
              client_secret_file: /etc/nauthilus-director/jmap-introspection/client-secret
          cache:
            ttl: 30s
            max_entries: 10000
        routing:
          missing_shard: forbidden
        limits:
          max_header_bytes: 65536
          max_request_body_bytes: 10485760
          max_upload_body_bytes: 52428800
        timeouts:
          read_header: 10s
          read: 10m
          idle: 2m
          backend_response_header: 2m
        placement:
          request_lease_ttl: 2m
        event_source:
          heartbeat_interval: 30s

  backend_pools:
    jmap-default:
      protocol: jmap
      selector: rendezvous_hash
      backends: [mailstore-a-jmap]

  backends:
    mailstore-a-jmap:
      protocol: jmap
      shard_tag: mailstore-a
      backend_node: mailstore-a-node-1
      address: "mailstore-a.internal.example:8443"
      weight: 100
      max_connections: 1000
      maintenance: disabled
      haproxy:
        enabled: true
      tls:
        mode: implicit
        ca_file: /etc/nauthilus-director/mailstore-ca.pem
        server_name: mailstore-a.internal.example
        min_tls_version: TLS1.2
      auth:
        mode: none
      health_check:
        enabled: true
        deep_check: false
```

Every `jmap` value shown is the default except `public_base_url`,
`health_path`, `realm` and the bearer block; `jmap: {}` is a valid minimal
block (Basic only, fail-closed routing). The full option reference is in
`nauthilus-director.yaml(5)`, section "JMAP LISTENERS AND BACKENDS".
`max_connections` applies to event streams only, because ordinary requests
reserve no backend capacity.

Validation refuses a JMAP listener without implicit TLS, without any enabled
scheme, with Bearer but without a token binding or scope, with an
`introspection_client` whose credentials do not match its `auth_method` or
that sets credentials without `client_id`, with Basic on an
authority without the password mechanism, and JMAP backends without implicit
TLS, with director-owned backend credentials or with `deep_check`.

## Backend Requirements

- Serve `/.well-known/jmap`, `/jmap/api/`, `/jmap/upload/`, `/jmap/download/`,
  `/jmap/eventsource/` and an unauthenticated `/jmap/healthz` over TLS.
- Advertise the director's public URL in the session resource.
- Verify Basic and Bearer credentials of every request against the same
  Nauthilus, and require the same token audience or resource.
- Accept PROXY v2 from the director's addresses before TLS, and trust
  client addresses only from those peers.
- Optionally refuse accounts that belong to another shard, as defence in depth
  behind the director's own fail-closed routing.

## Limitations

- JMAP over WebSocket (RFC 8887) is not proxied; requests carrying an
  `Upgrade` header are refused with 400.
- No CORS handling: preflight `OPTIONS` requests are answered 405, so browser
  clients on another origin are not supported.
- No session resource rewriting; backends must advertise the public URL.
- Route lookup (`nauthilus-directorctl route lookup --protocol jmap`) uses the
  shared resolver and shows a hash fallback for attributes without a shard,
  although live JMAP traffic is refused under the default `missing_shard`.
- No JMAP-specific trace span; requests are visible in logs and metrics.
- The listener certificate is loaded at start, like for the mail listeners.

## References

- [RFC 8620: The JSON Meta Application Protocol (JMAP)](https://www.rfc-editor.org/rfc/rfc8620.html)
- [RFC 8621: JMAP for Mail](https://www.rfc-editor.org/rfc/rfc8621.html)
- [RFC 8887: JMAP Subprotocol for WebSocket](https://www.rfc-editor.org/rfc/rfc8887.html)
- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [RFC 7662: OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
