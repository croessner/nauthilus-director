# Production Security Operations

This runbook documents the production control-plane boundary, protected
diagnostics and secret-handling expectations for `nauthilus-director`.

## Control Listener Boundary

The control listener is configured under `runtime.servers.control`. It serves
generated `/api/v1/*` REST routes, `/metrics`, `/healthz`, `/readyz` and, when
enabled, `/debug/pprof/*`.

Production policy:

| Path class | Authentication | Authorization | Notes |
| --- | --- | --- | --- |
| `/healthz`, `/readyz` | none | none | Liveness/readiness only; responses must stay secret-free and topology-free. |
| `/api/v1/*` | required | ordinary control access | Includes status, runtime state, route lookup, config readbacks and reload. |
| `/metrics` | required | ordinary control access | Metrics labels must remain low-cardinality and must not include users, tokens, raw backend identifiers or request IDs. |
| `/api/v1/config/*?include_protected=true` | required | protected access | Returns `403` without partial protected output when the actor lacks protected authorization. |
| `/debug/pprof/*` | required when enabled | protected access | Absent as `404` when pprof is disabled. |

Bind the control listener to a private address by default. Loopback binding is
not a replacement for configured authentication; it is only one layer.
Bearer and OIDC control authentication require
`runtime.servers.control.tls.enabled: true` whenever the listener is bound beyond
loopback. Plain HTTP control access is accepted only for loopback listeners with
`runtime.servers.control.allow_plaintext_loopback: true`; it is intended for
local development, container-internal health checks, or SSH-forwarded workflows,
not for remotely reachable bearer-token transport.

## Authentication Modes

`runtime.servers.control.auth` supports three production modes. Enable only the
modes that are intentionally used in the deployment.

| Mode | Use | Protected access |
| --- | --- | --- |
| OIDC through Nauthilus | Recommended production mode for operator and automation access. | Requires ordinary `required_scopes` and additional `protected_scopes`. |
| Static bearer token file | Compatibility or emergency local access. | Ordinary control access only unless a later typed policy grants more. |
| mTLS | Strong peer authentication for tightly managed hosts. | Ordinary control access only unless a later typed policy maps certificate identity to protected access. |

OIDC control auth validates incoming `Authorization: Bearer` requests by
calling Nauthilus token introspection through the configured authority. The
Director parses only the bearer envelope locally. Inactive tokens, missing
ordinary scopes, missing protected scopes, audience mismatch and introspection
errors fail closed.

This control-plane OIDC path is separate from mail SASL bearer introspection.
Control scopes live under `runtime.servers.control.auth.oidc`; mail SASL
end-user token policy lives under
`auth.authorities.<name>.mechanisms.bearer.introspection`.

Static bearer auth reads `runtime.servers.control.auth.bearer.token_file` from a
mounted secret file and compares the token in constant time. Prefer
`nauthilus-directorctl --auth-bearer-token-file <path>` or
`NAUTHILUS_DIRECTORCTL_BEARER_TOKEN_FILE=<path>` for production shells. Inline
token flags are intended for explicit operator use and tests.

Configuration fields whose names end in `_file` are mounted secret-file
references, not inline secret values. Redis passwords, Nauthilus HTTP/gRPC
caller credentials, backend authentication credentials, health-check
credentials, control static auth files and OIDC client secret files read the
referenced regular file with bounded size checks. Missing, unreadable, empty,
directory or oversized files fail closed with secret-safe diagnostics. Existing
configs that placed literal passwords or tokens in `*_file` fields must move the
literal value into a mounted file and configure the field with that path.

mTLS auth requires `runtime.servers.control.tls.enabled: true`, a configured
control certificate and key, and `runtime.servers.control.tls.client_ca`.
Clients use `nauthilus-directorctl --tls-ca-file <path> --tls-client-cert
<path> --tls-client-key <path>`.
Any control TLS configuration with `require_client_cert: true` must configure
`client_ca`; listeners fail closed instead of accepting arbitrary client
certificates.

## Nauthilus Authority Transport

HTTP and gRPC Nauthilus authority calls can carry Director caller credentials
and end-user password or bearer material. Use TLS for all non-loopback
authority targets. The only plaintext exception is loopback-local development:
set `auth.authorities.<name>.http.allow_plaintext_loopback: true` for an
`http://127.0.0.1/...` endpoint, or
`auth.authorities.<name>.grpc.allow_plaintext_loopback: true` with
`grpc.tls.enabled: false` for a loopback gRPC address. The opt-in is rejected
for wildcard, LAN, or public addresses.

When `auth.authorities.<name>.http.tls.enabled: true`, the HTTP authority client
uses the configured `ca_file`, `server_name`, and explicit
`insecure_skip_verify` compatibility setting. gRPC authority TLS uses the same
trust vocabulary.

## Control CLI Transport

`nauthilus-directorctl` keeps the compiled default
`http://127.0.0.1:9090` for plain local control listeners. That default does
not fit an HTTPS control listener, and a bare `host:port` value is normalized to
HTTP. For TLS-enabled control listeners, pass an explicit `https://` address
and a verification source:

```sh
nauthilus-directorctl \
  --address https://127.0.0.1:9090 \
  --tls-ca-file /etc/nauthilus-director/control-ca.pem \
  --auth-bearer-token-file /run/nauthilus-director/operator-control-token \
  sessions list
```

Inside a production pod, keep the same rule: address the configured HTTPS
listener explicitly and read credentials from mounted files rather than shell
arguments or environment values that contain token bytes:

```sh
kubectl -n mail exec deploy/nauthilus-director -c director -- \
  nauthilus-directorctl \
    --address https://127.0.0.1:9090 \
    --tls-ca-file /etc/nauthilus-director/control-ca.pem \
    --auth-bearer-token-file /run/nauthilus-director/operator-control-token \
    users sessions user@example.org
```

For mTLS, add `--tls-client-cert <path> --tls-client-key <path>` and keep server
verification configured through `--tls-ca-file` or `--tls-server-name`.
`--tls-insecure-skip-verify` is limited to emergency diagnostics and is not a
production access pattern.

For pod or host-local mTLS access, use certificate and key paths only:

```sh
nauthilus-directorctl \
  --address https://127.0.0.1:9090 \
  --tls-ca-file /etc/nauthilus-director/control-ca.pem \
  --tls-client-cert /run/nauthilus-director/control-client.crt \
  --tls-client-key /run/nauthilus-director/control-client.key \
  users list --limit 100
```

The CLI classifies local address or TLS configuration errors, HTTP-to-HTTPS
scheme mismatches, TLS verification failures, connection refusal or timeout,
`401` authentication failures, `403` authorization failures, non-JSON or
malformed control responses and structured runtime API problem responses.
Diagnostics must not print bearer token values, private key contents,
certificate bodies or raw large response bodies.

## OIDC Control Authorization

The default ordinary control scope is `nauthilus-director.admin`. The default
protected scope is `nauthilus-director.protected`.

Operators using OIDC-protected control requests currently provide an access
token through the CLI bearer-token input, usually by writing an externally
acquired token to a short-lived file owned by the operator process. The CLI
sends the token as a bearer credential and never prints it.

Example placeholder flow:

```sh
CTL='nauthilus-directorctl --address https://127.0.0.1:9090 --tls-ca-file /etc/nauthilus-director/control-ca.pem'
TOKEN_FILE='/run/nauthilus-director/operator-control-token'

$CTL --auth-bearer-token-file "$TOKEN_FILE" status
$CTL --auth-bearer-token-file "$TOKEN_FILE" runtime summary
$CTL --auth-bearer-token-file "$TOKEN_FILE" config dump --non-default --protected
```

Use a token with the protected scope only for the bounded operation that needs
protected config or profile access. Store short-lived operator tokens outside
shell history, tickets and long-lived logs.

## Mail SASL Bearer Tokens

Mail-protocol `XOAUTH2` and `OAUTHBEARER` credentials carry end-user bearer
tokens. The Director validates them by calling Nauthilus' discovered HTTP OIDC
introspection endpoint as the configured SASL introspection client. This path is
used even when password-oriented Nauthilus authority calls use gRPC.

`auth.authorities.<name>.oidc.client_credentials.*` is Director-to-Nauthilus
caller auth. `auth.authorities.<name>.mechanisms.bearer.introspection.*`
validates incoming mail SASL end-user bearer tokens. The required end-user token
scope belongs to `mechanisms.bearer.introspection.required_scope`; the
caller-token request scopes in `oidc.client_credentials.scopes` do not authorize
mail SASL bearer sessions.

The original end-user bearer token may remain in memory only long enough for
policy-gated backend replay. Backend replay requires an allowed original
mechanism and the configured backend TLS policy; it must not bypass TLS,
allowed-mechanism checks or fail-closed backend auth behavior. End-user bearer
tokens, token hashes, account keys, configured claim values and raw
introspection errors must not appear in logs, traces, metrics, CLI output or
test failure output.

## Protected Config

Redaction is the default for local and remote config output:

```sh
nauthilus-director config dump -d --format yaml
nauthilus-director config dump -n --format yaml
nauthilus-directorctl config dump --non-default --format yaml
```

Protected output is explicit:

```sh
nauthilus-director config dump -n --protected --format yaml
nauthilus-directorctl config dump --non-default --protected --format yaml
```

Remote protected output requires protected authorization. A `403` response is a
closed denial; no partial protected document is printed. Do not paste protected
config output into shared systems without a separate operational review.

## Diagnostic Profiles

pprof is disabled by default with `observability.profiles.pprof.enabled:
false`. Disabled pprof paths return `404`.

When an incident requires pprof:

1. Enable only the profile classes needed for the incident.
2. Restart during a controlled window; profile enablement is restart-scoped.
3. Access profiles only through the authenticated control listener.
4. Require protected authorization for every profile request.
5. Store collected profile files as sensitive incident artifacts and expire
   them after use.

Profile payloads can contain stack frames, timing, allocation paths and command
line detail. Audit events for profile access are bounded and do not record
profile bodies, tokens, private keys, protected config values or raw
certificates.

## Secret Safety

Use mounted files for secret-bearing paths:

| Secret class | Example path |
| --- | --- |
| Control bearer token | `/etc/nauthilus-director/control-token` |
| Nauthilus OIDC client secret | `/etc/nauthilus-director/nauthilus-oidc-client-secret` |
| Nauthilus SASL introspection client secret | `/etc/nauthilus-director/nauthilus-introspection-client-secret` |
| Redis password | `/etc/nauthilus-director/redis-password` |
| TLS private keys | `/etc/nauthilus-director/*.key` |
| Client certificates and CA bundles | `/etc/nauthilus-director/*.pem` |

Environment placeholders may point to file paths, for example
`${NAUTHILUS_DIRECTOR_REDIS_PASSWORD_FILE}`. Placeholder expansion happens
before typed validation and fails closed when a required variable is missing.
Do not store secret bytes directly in unit files, environment files, image
layers, shell history or documentation examples.
