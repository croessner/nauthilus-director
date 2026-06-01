# M5 Backend PROXY Protocol Follow-up

Status: implementation-ready follow-up; required before declaring
HAProxy-backed backend endpoints production-ready.

This document closes the backend-side PROXY protocol gap for the already
implemented IMAP and LMTP backend connection paths. Listener-side PROXY protocol
support exists and is intentionally not redefined here. The missing behavior is
outbound PROXY protocol support from `nauthilus-director` to configured backend
endpoints, including the backend health-check path.

The current configuration model already contains backend HAProxy placeholders
under `director.backends.*.haproxy`. This follow-up turns that configuration
surface into real transport behavior instead of treating it as inert metadata.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `contrib/demo-stack/`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues. Until the older documents are reconciled, this
follow-up is the specific source of truth for backend-side PROXY protocol
behavior.

## Original Gap

The implemented listener path can consume trusted inbound PROXY protocol headers
before TLS or protocol greeting. This lets the Director see the original client
address when it is behind a trusted frontend load balancer.

The implemented backend path does not provide the symmetric outbound behavior:

- IMAP and LMTP backend connectors dial `target.Address` and immediately proceed
  with backend greeting, TLS, capability discovery and backend authentication.
- Backend health checks reuse the same protocol connectors, so light and deep
  health checks also start reading the backend greeting without sending a PROXY
  header.
- `director.backends.*.haproxy.enabled` exists in typed config and generated
  references, but the normalized backend domain object does not carry it into
  connector behavior.
- Operators can point a backend address at a HAProxy or PROXY-aware mailstore,
  but a target that requires PROXY protocol cannot currently be used safely for
  either real sessions or health checks.

That leaves two production gaps:

1. Real backend sessions cannot preserve the frontend client tuple across a
   backend-side HAProxy boundary.
2. Backend health checks cannot prove the same transport path that real sessions
   require when that path expects PROXY protocol.

## Goal

Implement backend-side PROXY protocol as one shared backend transport capability
used by real protocol sessions and backend health checks.

The target connection sequence for a PROXY-enabled backend is:

```text
frontend session or health runner
  -> select backend
  -> TCP connect to backend address
  -> write exactly one PROXY protocol header when backend config enables it
  -> continue with configured backend TLS mode
  -> read backend greeting or perform protocol capability discovery
  -> perform configured backend authentication when required
  -> enter transparent proxy or health-check command sequence
```

For real sessions, the PROXY header must carry the effective frontend client
address after trusted listener PROXY handling. For health checks, the PROXY
header must carry a safe synthetic tuple derived from the health-check TCP
socket itself.

## Delivery Placement

Implement this as an M5 backend transport follow-up. It amends the IMAP backend
connect work from M1 and the LMTP production backend work from M5, and it must be
available to M6 ManageSieve through the same shared backend transport model.

Implementation slices:

1. Backend config and domain propagation for `director.backends.*.haproxy`.
2. Shared outbound PROXY header construction and validation.
3. IMAP backend connector support for session and health-check purposes.
4. LMTP backend connector support for session and health-check purposes.
5. Backend health runner proof that light and deep checks use the same transport
   preface as real sessions.
6. Operator read-back through REST or CLI if backend transport details are
   exposed there.
7. Unit, integration and E2E coverage with PROXY-required backend endpoints.
8. Documentation reconciliation for generated config references and examples.

The slices may be committed separately, but the follow-up is complete only when
real sessions and health checks both succeed through a backend endpoint that
requires PROXY protocol.

## Scope

In scope:

- Preserve the existing stable config path
  `director.backends.<backend>.haproxy.enabled`.
- Interpret `haproxy.enabled: true` as "send HAProxy PROXY protocol to this
  backend endpoint before any backend protocol bytes".
- Propagate backend HAProxy configuration from typed config into the normalized
  backend domain object.
- Send outbound PROXY protocol for IMAP backend sessions when enabled.
- Send outbound PROXY protocol for LMTP backend sessions when enabled.
- Send outbound PROXY protocol for IMAP and LMTP backend health checks when
  enabled.
- Ensure light and deep health checks exercise the same PROXY preface.
- Keep the PROXY preface before implicit TLS, plaintext greeting reads and
  STARTTLS negotiation.
- Use the effective frontend address after trusted inbound PROXY handling for
  session backend connections.
- Use socket-derived health-check source and destination addresses when no
  frontend session exists.
- Fail closed on unsupported address families, missing TCP address data or PROXY
  header write failures.
- Keep logs, metrics and REST responses secret-safe and low-cardinality.
- Add tests that prove no header is sent when the feature is disabled.

Out of scope:

- Changing listener-side PROXY protocol semantics.
- Accepting untrusted client-supplied PROXY source addresses.
- Adding runtime commands that spoof arbitrary PROXY source addresses.
- Writing backend transport changes into YAML through REST or CLI.
- Adding feature-specific Redis state or coordination.
- Treating `haproxy.enabled` as a health endpoint, HTTP proxy, load-balancer
  discovery mechanism or backend selection policy.
- Adding general-purpose L4 load-balancer features to the Director.
- Sending multiple PROXY headers on one backend connection.
- Sending a PROXY header after backend TLS has already started.
- Making route lookup open backend sockets or mutate runtime state.

## Configuration Contract

The existing backend configuration block remains the stable operator entrypoint:

```yaml
director:
  backends:
    mailstore-a-imap:
      protocol: imap
      address: mailstore-a-proxy:143
      haproxy:
        enabled: true
```

Semantics:

- `enabled: false` means the Director sends no backend PROXY protocol preface.
- `enabled: true` means every Director-created TCP connection to that backend
  starts with one PROXY protocol header.
- The header is written before implicit TLS, before reading a cleartext backend
  greeting and before any STARTTLS command.
- The setting applies equally to session connections and health-check
  connections.
- The setting is per backend entry, not per backend pool or per listener.
- Existing config dumps and generated references must keep showing the field.

The implementation may add an optional version field under the existing block:

```yaml
director:
  backends:
    mailstore-a-imap:
      haproxy:
        enabled: true
        version: v1
```

Rules for `version` if it is added:

- Allowed values are `v1` and `v2`.
- Empty or omitted version defaults to `v1` for compatibility with the common
  HAProxy `send-proxy` mode and mail-server deployments that support only the
  text format.
- Unknown values fail typed validation before runtime startup.
- Adding `version` must not rename, remove or invert `haproxy.enabled`.

Do not introduce a replacement `director.backends.*.proxy_protocol` tree in this
follow-up. The current path is already present in stable generated references.
A future vendor-neutral alias may be designed as an additive migration, but it
must not create two independent sources of transport truth.

## Runtime Semantics

Outbound PROXY protocol is backend transport metadata. It does not affect
routing, affinity, health state ownership, maintenance, drain, runtime weight,
backend authentication mode or protocol capability selection.

For real sessions:

- The protocol session owns the frontend connection context.
- The backend connector must receive enough connection metadata to build the
  outbound PROXY header without reaching back into listener internals.
- The PROXY source address is the effective frontend remote address after trusted
  listener PROXY handling. If the listener did not enable PROXY protocol, this is
  the direct client peer address observed by the Director.
- The PROXY destination address is the effective frontend local address after
  trusted listener PROXY handling. If the listener did not enable PROXY protocol,
  this is the Director listener socket address observed by the frontend
  connection.
- The backend connector must not use raw unvalidated PROXY header bytes. It may
  use only the normalized `net.Addr` values exposed after listener validation.

For backend health checks:

- There is no frontend client and no user session.
- The health checker still must send a valid PROXY header when the backend entry
  enables it.
- The health-check PROXY source address is the local TCP address of the
  Director-to-backend health-check socket.
- The health-check PROXY destination address is the remote TCP address of the
  Director-to-backend health-check socket.
- Health checks must not invent usernames, recipients, client IPs or test
  session IDs for PROXY metadata.
- If either socket address is unavailable or not TCP, the health check fails
  closed with a bounded PROXY-related reason class.

The outbound header must be written exactly once per backend TCP connection. It
must be complete and flushed before the backend connector creates buffered
protocol readers that expect greetings or before a TLS client starts the
handshake.

## Backend Connector Boundary

Extend the backend connector boundary so callers can pass explicit connection
purpose and optional frontend address metadata.

The exact Go type names are implementation details, but the boundary should be
shaped around these facts:

```go
type BackendConnectPurpose string

const (
    BackendConnectPurposeSession BackendConnectPurpose = "session"
    BackendConnectPurposeHealth  BackendConnectPurpose = "health"
)

type BackendProxyAddresses struct {
    Source      net.Addr
    Destination net.Addr
}

type BackendConnectRequest struct {
    Target         backend.Backend
    Timeout        time.Duration
    Purpose        BackendConnectPurpose
    ProxyAddresses *BackendProxyAddresses
}
```

Protocol packages may keep narrow interfaces for tests, but they must not
duplicate outbound PROXY protocol construction. IMAP, LMTP, ManageSieve and
later POP3 should all call a shared helper or shared backend transport type.

The normalized `backend.Backend` domain object must contain secret-safe backend
HAProxy configuration. It should remain a value object suitable for selector,
health and route diagnostics. Do not let protocol packages read raw Viper maps
or untyped YAML data to discover whether PROXY is enabled.

## Header Construction

Use the existing pinned PROXY protocol dependency when it safely supports header
rendering. Do not hand-roll wire formatting unless the library lacks a small,
testable API for the required outbound behavior.

Header rules:

- Support IPv4 and IPv6 TCP addresses.
- Reject Unix sockets, unresolved non-TCP addresses and mixed unsupported
  address families when PROXY is enabled.
- Preserve source and destination ports when they are available.
- For session connections, preserve the effective frontend tuple rather than the
  Director-to-backend socket tuple.
- For health-check connections, use the Director-to-backend socket tuple.
- Do not emit TLVs in v1.
- Do not emit secret-bearing TLVs in v2.
- Do not emit usernames, tenant names, account keys, recipients, session IDs,
  trace IDs or bearer material in PROXY metadata.

If a connection cannot produce a valid configured PROXY header, close the backend
connection and return a typed backend transport error before protocol auth or
proxying starts.

## Health Check Semantics

Health checks must prove the same backend transport preface required by real
traffic.

Light checks:

- Connect to the backend.
- Send the outbound PROXY header when enabled.
- Perform the existing protocol greeting, TLS and capability discovery sequence.
- Mark healthy only when that transport path succeeds.

Deep checks:

- Do everything a light check does.
- Continue with the existing credentialed health authentication and protocol
  command sequence.
- Publish healthy only when the PROXY preface, TLS policy, capability discovery
  and deep-auth command path all succeed.

Failure classification:

- PROXY config validation failures are config/startup errors.
- PROXY header write failures during health checks are health failures with a
  bounded reason class such as `proxy_protocol`.
- PROXY header write failures during real sessions are backend connect failures
  with a bounded reason class. They must not leak endpoint addresses or user
  identity into logs or metric labels.

Do not silently bypass PROXY for health checks because there is no frontend
client. A backend that requires PROXY protocol must be checked through that same
requirement.

## REST, CLI and Diagnostics

The minimum implementation may rely on config dump for operator visibility. If
backend transport fields are exposed through `GET /api/v1/backends` or
`nauthilus-directorctl backends show`, they must come from the generated OpenAPI
contract and generated client SDK.

Allowed backend read-back fields are secret-safe:

- backend identifier;
- protocol;
- backend pool;
- shard tag;
- whether outbound backend PROXY protocol is enabled;
- configured outbound PROXY protocol version if a version field exists;
- runtime health and maintenance state already exposed by the backend detail
  model.

Do not expose backend addresses, TLS private key paths, passwords, bearer token
paths, raw peer addresses or health-check credentials through the backend REST
detail unless a separate redaction-aware config inspection endpoint is being
used.

Route lookup remains side-effect-free. It may report that a selected backend
would require outbound PROXY protocol, but it must not open a backend socket,
write a PROXY header, refresh health or mutate Redis state.

## Observability

Add bounded observability for outbound backend PROXY handling without adding
high-cardinality labels.

Acceptable event fields:

- operation: `backend_proxy_protocol`;
- protocol: `imap`, `lmtp`, `sieve` or later protocol names;
- backend pool;
- result: `ok` or `failure`;
- reason class: `ok`, `disabled`, `write_failed`, `unsupported_family`,
  `missing_address`, `config` or similarly bounded values;
- purpose: `session` or `health`;
- version: `v1` or `v2` when configured.

Forbidden metric labels and log fields:

- username;
- user hash;
- recipient;
- session ID;
- trace ID;
- request ID;
- client IP;
- raw frontend address;
- raw backend address;
- raw backend identifier;
- raw error text;
- secret-bearing values.

Metrics must aggregate by bounded dimensions. If backend identifiers are needed
for operator troubleshooting, emit them only in secret-safe structured events
where the existing observability policy permits them, not as Prometheus labels.

## Package Boundaries

Responsibilities:

- `internal/config` owns typed config, defaults, environment expansion and
  validation for backend HAProxy settings.
- `internal/backend` owns normalized backend inventory and exposes backend
  transport policy as part of the backend domain object.
- Shared backend transport code owns outbound PROXY header construction and
  write ordering.
- `internal/protocol/imap` owns IMAP greeting, STARTTLS, backend auth and proxy
  handoff, but not PROXY wire formatting.
- `internal/protocol/lmtp` owns LMTP greeting, STARTTLS, backend auth and
  delivery forwarding, but not PROXY wire formatting.
- The health runner owns scheduling and health-state publication, not protocol
  transport details.

Do not duplicate PROXY header formatting separately in IMAP and LMTP. The shared
implementation must be narrow enough for protocol unit tests to assert exact
first bytes on a fake backend connection.

## Tests

Unit tests:

- Config validation accepts the existing disabled default.
- Config validation accepts `haproxy.enabled: true`.
- Config validation rejects an unknown version if `haproxy.version` is added.
- The backend registry carries HAProxy config into normalized backend values.
- IMAP connector writes no PROXY header when disabled.
- IMAP connector writes a PROXY header before greeting reads when enabled.
- IMAP connector writes the PROXY header before implicit TLS handshake when
  enabled.
- LMTP connector writes no PROXY header when disabled.
- LMTP connector writes a PROXY header before greeting reads when enabled.
- LMTP connector writes the PROXY header before implicit TLS handshake when
  enabled.
- Session connections use effective frontend addresses after listener PROXY
  handling.
- Health-check connections use socket-derived Director-to-backend addresses.
- PROXY write failures close the backend connection and produce bounded errors.
- Unsupported address families fail closed before backend protocol auth.

Health-check tests:

- IMAP light health sends PROXY when enabled.
- IMAP deep health sends PROXY before credentialed health auth.
- LMTP light health sends PROXY when enabled.
- LMTP deep health sends PROXY before backend SASL or OAuth auth.
- A PROXY-required fake backend fails health when no header is sent and succeeds
  after implementation.

REST and CLI tests, if read-back is added:

- Generated OpenAPI DTOs expose only secret-safe backend transport fields.
- `nauthilus-directorctl backends show` uses the generated client model and does
  not duplicate REST DTOs.
- JSON and text output remain deterministic.

E2E tests:

- Start real Director binaries or test processes.
- Put a PROXY-required TCP endpoint between Director and at least one IMAP
  backend.
- Prove a public IMAP login reaches the backend through outbound PROXY protocol.
- Prove backend health becomes healthy only when the PROXY-enabled path succeeds.
- Put a PROXY-required TCP endpoint between Director and at least one LMTP
  backend when the E2E environment supports LMTP delivery.
- Prove LMTP delivery and LMTP backend health use the same PROXY-required path.

Demo-stack proof may use HAProxy `accept-proxy` in front of selected mailstore
endpoints, but the implementation must not be demo-only.

## Acceptance Checklist

- [ ] `director.backends.*.haproxy.enabled` is implemented, not inert metadata.
- [ ] Backend HAProxy config is propagated into `backend.Backend`.
- [ ] Session backend connections send PROXY before TLS or protocol greeting when
      enabled.
- [ ] Health-check backend connections send PROXY before TLS or protocol greeting
      when enabled.
- [ ] Light and deep health checks both exercise the PROXY-required path.
- [ ] IMAP and LMTP use a shared outbound PROXY implementation.
- [ ] No behavior changes occur for backends with `haproxy.enabled: false`.
- [ ] Unsupported PROXY address data fails closed with bounded diagnostics.
- [ ] Logs and metrics do not expose usernames, recipients, session IDs, client
      IPs, raw backend addresses or secret-bearing values.
- [ ] Generated config references and operator examples describe the implemented
      behavior.
- [ ] Public-boundary tests prove real session traffic and health traffic through
      a PROXY-required backend endpoint.
- [ ] `make guardrails` passes before the implementation is considered complete.
