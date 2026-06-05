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

Static bearer auth reads `runtime.servers.control.auth.bearer.token_file` from a
mounted secret file and compares the token in constant time. Prefer
`nauthilus-directorctl --auth-bearer-token-file <path>` or
`NAUTHILUS_DIRECTORCTL_BEARER_TOKEN_FILE=<path>` for production shells. Inline
token flags are intended for explicit operator use and tests.

mTLS auth requires `runtime.servers.control.tls.enabled: true`, a configured
control certificate and key, and `runtime.servers.control.tls.client_ca`.
Clients use `nauthilus-directorctl --tls-ca-file <path> --tls-client-cert
<path> --tls-client-key <path>`.

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
| Redis password | `/etc/nauthilus-director/redis-password` |
| TLS private keys | `/etc/nauthilus-director/*.key` |
| Client certificates and CA bundles | `/etc/nauthilus-director/*.pem` |

Environment placeholders may point to file paths, for example
`${NAUTHILUS_DIRECTOR_REDIS_PASSWORD_FILE}`. Placeholder expansion happens
before typed validation and fails closed when a required variable is missing.
Do not store secret bytes directly in unit files, environment files, image
layers, shell history or documentation examples.
