# Future JMAP Support

Status: future design note, not an active implementation milestone

This document captures how JMAP could fit into `nauthilus-director` in a later
architecture phase. It is intentionally separate from
`docs/ARCHITECTURE_ROADMAP.md` because JMAP is not part of the current M0/M1
production path and must not silently expand the near-term protocol scope.

The central rule is simple: future JMAP support is allowed only as
JMAP-to-JMAP directing or proxying. `nauthilus-director` must not translate
between JMAP and IMAP, POP3, LMTP, ManageSieve or any other mailbox protocol.

## 1. What JMAP Is

JMAP is an HTTP-based JSON application protocol for synchronising data between
clients and servers. JMAP Core defines the generic request, response, batching,
session, binary data and change notification model. JMAP Mail defines the mail
data model on top of that core. JMAP over WebSocket defines a long-lived
WebSocket transport for JMAP requests, responses and optional push events.

For this project, JMAP should be treated as a separate frontend protocol family,
not as an IMAP extension. IMAP and JMAP may expose access to the same mailbox
data on a backend server, but they do not share a frontend protocol model:

- IMAP is a line-oriented, stateful TCP protocol with selected mailbox state.
- JMAP is a JSON API over HTTPS, with optional WebSocket transport.
- JMAP exposes structured method calls, account objects, blob transfer,
  capability discovery, change state and push semantics.
- JMAP clients expect service URLs and capabilities from a JMAP Session
  resource, not an IMAP-style capability banner.

## 2. Architectural Position

If implemented, JMAP should become a sibling of the existing mail protocol
families:

```text
internal/protocol/imap/
internal/protocol/pop3/
internal/protocol/lmtp/
internal/protocol/sieve/
internal/protocol/jmap/
```

The JMAP package would own only the frontend JMAP HTTP/WebSocket boundary:
request admission, authentication handoff, route resolution, backend selection,
reverse proxying, safe response metadata handling and protocol-specific
observability.

It must reuse the common director subsystems instead of creating a separate
mail stack:

- listener lifecycle and TLS configuration
- Nauthilus authentication and identity lookup
- director-owned routing fact resolution
- backend registry and selection
- Redis-backed affinity and runtime state
- maintenance and drain semantics
- logging, metrics and tracing policy
- graceful shutdown and connection accounting

JMAP must not be folded into the REST control API. The control API is an
operator API owned by `nauthilus-director` and generated from OpenAPI. JMAP is a
user-facing mail access protocol with its own IETF-defined data model and
method conventions. Even though both use HTTP and JSON, they are different
contracts and need different boundaries.

## 3. Hard Non-Goals

Future JMAP support must not introduce these behaviors:

- No JMAP-to-IMAP translation.
- No IMAP-to-JMAP translation.
- No local mailbox, folder, label, thread, search, sort or blob semantics.
- No local message submission engine.
- No local implementation of JMAP Mail method behavior such as `Email/get`,
  `Email/query`, `Mailbox/set` or `Blob/get`.
- No local contacts, calendar or task store.
- No cross-shard mailbox aggregation inside the director.
- No rewriting of YAML configuration through JMAP or REST mutation commands.
- No treating JMAP as a shortcut around Nauthilus authentication policy.

The director may inspect or alter narrowly scoped protocol metadata only when
that is required to keep the proxy boundary correct, such as public endpoint
URLs in a JMAP Session response. It must not inspect method calls to make
mailbox decisions.

## 4. Target Model

The supported model is:

```text
JMAP client
  -> nauthilus-director JMAP listener
      -> HTTPS / optional WebSocket admission
      -> Nauthilus authentication or identity lookup
      -> director-owned routing fact resolution
      -> Redis-backed active affinity or deterministic initial placement
      -> director-owned JMAP backend selection
      -> HTTP/WebSocket reverse proxying
          -> JMAP backend
```

The backend selected by a JMAP listener must speak JMAP. If a deployment has
only IMAP backends, JMAP belongs in the backend mail platform, not in
`nauthilus-director`.

The initial implementation should assume one authenticated principal maps to
one logical JMAP routing target. Multi-account sharing and delegated access
remain backend authorization concerns. If a backend exposes shared accounts
through JMAP, the director routes the authenticated principal to the backend
that can answer those JMAP requests; it does not aggregate accounts across
multiple backend shards.

## 5. Transport Shape

JMAP is not a raw TCP pre-auth protocol in the same way as IMAP, POP3 or
ManageSieve. A future implementation needs an HTTP-aware listener path for the
user-facing JMAP service.

Candidate frontend surfaces:

- JMAP Session resource and service discovery endpoints.
- JMAP API endpoint for method calls.
- Blob upload endpoint.
- Blob download endpoint.
- EventSource endpoint if exposed by the backend.
- WebSocket endpoint for RFC 8887 JMAP over WebSocket.

The JMAP listener must be separate from `runtime.servers.control` unless a
future architecture decision deliberately introduces a shared HTTP server with
strict host/path isolation. The safe default is a dedicated user-facing JMAP
listener configured under the director protocol listener model.

TLS should be required by default for external JMAP listeners. Cleartext HTTP
should require explicit configuration and should be suitable only for trusted
internal deployments behind a terminating proxy.

## 6. Session Resource Handling

The JMAP Session resource is the main place where a pure reverse proxy may need
special care. A backend can advertise URLs for the API, upload, download,
EventSource and WebSocket surfaces. If those URLs point at backend-private
addresses, clients may bypass the director or fail entirely.

Preferred deployment model:

- JMAP backends are configured to advertise the director's public JMAP base URL.
- The director proxies the Session resource without JSON rewriting.
- The director treats capabilities and account data as backend-owned data.

Optional later model:

- The director may rewrite only explicitly allowed URL fields in the JMAP
  Session resource.
- Rewriting must be deterministic, test-covered and redaction-safe.
- Rewriting must not alter account data, capabilities, mailbox objects,
  message objects, blob references or method responses.

The optional rewrite path should be considered a protocol-front-door concern,
not mailbox semantics.

## 7. Authentication Boundary

JMAP authentication is carried through HTTP authentication, bearer credentials,
cookies or deployment-specific frontend mechanisms. The director must keep the
same authority boundary as the rest of the project:

- Nauthilus remains the authentication authority.
- The director may parse enough HTTP authentication state to extract credential
  material and mechanism identity.
- Passwords, bearer tokens, cookies and authorization headers must never be
  logged, traced, counted as metric labels or exposed in diagnostics.
- OIDC-backed bearer token validation belongs to Nauthilus by default.
- The director receives an internal auth result and then performs its own
  routing fact resolution and backend selection.

The director should prefer per-request authentication for ordinary HTTPS JMAP
requests and connection-scoped authentication for JMAP WebSocket handshakes.
For WebSocket, the authenticated identity from the handshake remains bound to
the connection until the connection closes or policy requires termination.

## 8. Routing and Affinity

JMAP routing must use the same director-owned pipeline as the other protocol
families:

```text
auth result + JMAP listener context
  -> RoutingResolver resolves tenant, normalized account and shard_tag
  -> active affinity may pin or override shard_tag while sessions are open
  -> backend selector resolves shard_tag + protocol=jmap + backend pool
  -> health, maintenance, limits and runtime overrides are applied
  -> concrete JMAP backend identifier is selected
```

Ordinary HTTPS requests can create short-lived request leases. Long-lived
WebSocket or EventSource connections create active session leases. While an
active lease exists for an affinity key, new JMAP requests for that key should
route to the same logical shard unless a hard-down backend, hard maintenance,
explicit administrative move, kick or drain requires otherwise.

The routing key should come from the authenticated principal and director
routing facts, not from untrusted request path data. Backend authorization
remains responsible for deciding whether that principal may access any specific
JMAP account, mailbox, blob or shared object.

## 9. Backend Model

JMAP backends should be configured as protocol-specific backend entries:

```yaml
director:
  backend_pools:
    jmap-default:
      protocol: jmap
      selector: rendezvous_hash
      backends:
        - mailstore-a-jmap

  backends:
    mailstore-a-jmap:
      protocol: jmap
      shard_tag: mailstore-a
      address: "https://10.0.0.11:443"
      tls:
        enabled: true
        server_name: "mailstore-a.internal.example"
```

Backend address and backend TLS identity remain separate. The director must not
disable TLS verification to make IP-address backends convenient. If the backend
certificate name differs from the TCP address, `tls.server_name` must be
configured explicitly.

Health checks for JMAP backends should use a backend-supported low-cost endpoint
or a tightly scoped authenticated probe. They must not mutate mailbox state, and
they must not depend on user credentials unless an explicit health-check
identity is configured.

## 10. Configuration Sketch

All JMAP configuration paths are draft-only until a future implementation spec
declares a stability window.

Possible listener shape:

```yaml
director:
  listeners:
    jmap:
      protocol: jmap
      service_name: jmap
      network: tcp
      address: "0.0.0.0:443"
      authority: default
      backend_pool: jmap-default
      proxy_protocol:
        enabled: false
      tls:
        enabled: true
        cert: "/etc/nauthilus-director/tls/jmap.crt"
        key: "/etc/nauthilus-director/tls/jmap.key"
      jmap:
        public_base_url: "https://mail.example.org"
        session_resource:
          mode: backend_advertised
        websocket:
          enabled: true
          path: "/jmap/ws/"
        request_limits:
          max_body_bytes: 10485760
          max_header_bytes: 65536
```

Potential `session_resource.mode` values:

- `backend_advertised`: require backends to return externally correct URLs.
- `rewrite_urls`: rewrite only explicitly allowed Session resource URL fields.

`backend_advertised` should be the default because it keeps the director from
parsing more JMAP data than necessary.

## 11. Security Defaults

JMAP support must start with restrictive defaults:

- TLS enabled for external listeners.
- Strict request body and header size limits.
- Conservative read, write and idle timeouts.
- Authorization, cookie and bearer material redacted everywhere.
- No logging of method arguments, raw request bodies or blob content.
- No username, account ID, blob ID, session ID, trace ID, request ID, client IP,
  raw backend ID or raw error text as metric labels.
- Cross-origin browser access denied by default unless an explicit CORS policy
  is configured.
- WebSocket origin checks enabled by default for browser-facing deployments.
- WebSocket subprotocol negotiation limited to the JMAP subprotocol when JMAP
  over WebSocket is enabled.
- Backend TLS verification enabled by default.
- Ambiguous authentication, routing or backend state fails closed.

The director should be observable without exposing credentials or mailbox
metadata.

## 12. Operational Semantics

Soft maintenance for a JMAP backend should exclude it from new initial
placements while preserving active request, WebSocket and EventSource leases by
default.

Hard maintenance should exclude all new JMAP placements and may close active
long-lived channels after an explicit grace period. Any forced movement or
termination must be auditable through logs, counters and traces without leaking
account or credential material.

Route lookup remains a director-only diagnostic. A JMAP route lookup must not
call Nauthilus, validate credentials, open a JMAP Session, mutate Redis, refresh
leases or make backend method calls.

## 13. Implementation Phases

Future JMAP work should be split into explicit implementation specs before code
is written.

Candidate phase order:

1. Research and contract phase:
   define the exact supported JMAP surfaces, backend requirements, Session
   resource policy, authentication inputs, CORS policy and E2E fixtures.
2. Listener and reverse-proxy foundation:
   add a JMAP HTTP listener that authenticates through Nauthilus, resolves
   routing facts, selects a JMAP backend and proxies ordinary HTTPS requests.
3. Session resource handling:
   support `backend_advertised` mode first, then add tested URL rewriting only
   if operators need it.
4. Upload, download and EventSource coverage:
   verify binary data paths, request limits, streaming behavior and redaction.
5. WebSocket support:
   implement RFC 8887 admission, authentication binding, session leases,
   observability and graceful shutdown for long-lived connections.
6. Operational controls:
   extend route lookup, drain, move, kick and backend runtime state reporting
   to include `protocol=jmap` without changing mailbox semantics.
7. E2E and compatibility hardening:
   test against real JMAP-speaking backend processes, public sockets and
   generated operator clients where applicable.

The first production JMAP milestone should be intentionally narrow:
JMAP-to-JMAP routing for JMAP Mail access through a backend that already owns
mailbox semantics.

## 14. Open Questions

These questions should be resolved in a future implementation spec:

- Which HTTP authentication schemes are accepted at the JMAP listener?
- Is cookie-backed browser authentication in scope, or only Authorization
  headers and bearer credentials?
- Does the project require JMAP Session URL rewriting, or can deployments
  configure backend-advertised public URLs?
- Which JMAP endpoints and paths are configurable versus fixed by convention?
- How should request leases be timed for ordinary HTTPS JMAP calls?
- Which WebSocket close policies and codes are used for auth expiry, drain,
  hard maintenance and backend failure?
- Are shared accounts across multiple backend shards unsupported, explicitly
  backend-owned, or a later routing model?
- Which E2E backend fixture is authoritative for guardrails?

Until those questions are answered, JMAP remains a future protocol candidate,
not an active milestone.

## 15. References

- [RFC 8620: The JSON Meta Application Protocol (JMAP)](https://www.rfc-editor.org/rfc/rfc8620.html)
- [RFC 8621: The JSON Meta Application Protocol (JMAP) for Mail](https://www.rfc-editor.org/rfc/rfc8621.html)
- [RFC 8887: A JSON Meta Application Protocol (JMAP) Subprotocol for WebSocket](https://www.rfc-editor.org/rfc/rfc8887.html)
- [RFC 9404: JMAP Blob Management Extension](https://www.rfc-editor.org/rfc/rfc9404.html)
- [RFC 9425: JMAP for Quotas](https://www.rfc-editor.org/rfc/rfc9425.html)
