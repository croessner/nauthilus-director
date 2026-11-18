# MCP diagnostics endpoint

`nauthilus-director` can expose its read-only diagnostics to AI assistants and
other [Model Context Protocol](https://modelcontextprotocol.io/) clients. The
endpoint answers the questions an operator asks the control API every day —
which backend would this user get, why is this backend out, which sessions does
this user hold — without giving the assistant any way to change runtime state.

The endpoint is disabled by default. This document explains how it fits
together, how to configure Nauthilus and the director, and what operators can
expect from it.

## What the endpoint offers

Every tool is one read operation of the OpenAPI control API. The tool calls the
same handler the REST server uses and returns the same JSON bytes, so an answer
over MCP never differs from `nauthilus-directorctl` or a REST call.

| Tool | Control API operation | Scope |
| --- | --- | --- |
| `runtime_summary` | `GET /api/v1/runtime/summary` | `nauthilus-director.diagnostics.runtime` |
| `listeners_list`, `listener_detail` | `GET /api/v1/listeners[/{name}]` | `nauthilus-director.diagnostics.runtime` |
| `backends_list`, `backend_detail` | `GET /api/v1/backends[/{identifier}]` | `nauthilus-director.diagnostics.runtime` |
| `config_non_default` | `GET /api/v1/config/non-default?format=json` | `nauthilus-director.diagnostics.runtime` |
| `sessions_list`, `session_detail` | `GET /api/v1/sessions[/{session_id}]` | `nauthilus-director.diagnostics.users` |
| `users_list`, `user_detail`, `user_sessions` | `GET /api/v1/users...` | `nauthilus-director.diagnostics.users` |
| `user_affinity`, `user_backend_pin`, `user_hold` | `GET /api/v1/users/{user_key}/...` | `nauthilus-director.diagnostics.users` |
| `route_lookup` | `POST /api/v1/route/lookup` | `nauthilus-director.diagnostics.users` |

Tool input schemas are derived from the embedded OpenAPI document at startup.
`config_non_default` always returns redacted values; protected config is not
reachable through MCP. `route_lookup` keeps its control API guarantees: it never
calls Nauthilus, never authenticates and never creates or refreshes a session,
and it refuses input whose keys name passwords, tokens, SASL, scripts or mailbox
data.

Moves, kicks, drains, maintenance, weight changes, reaping, reconciliation and
reload are not tools. They remain control API and `nauthilus-directorctl`
operations with their own authentication.

Listener tools describe the instance that answers. Session, user, affinity and
backend runtime state comes from the shared Redis state and is the same on
every instance.

## How authentication works

The endpoint is an OAuth 2.0 protected resource (RFC 9728). Nauthilus is the
authorization server; the director is the resource server.

1. An MCP client calls the endpoint without a token. The director answers
   `401` with `WWW-Authenticate: Bearer resource_metadata="…"`.
2. The client reads the protected resource metadata at
   `/.well-known/oauth-protected-resource/<path>`, which names the Nauthilus
   issuer and the two diagnostics scopes.
3. The operator signs in at Nauthilus through the MCP client. The client
   requests an access token for the resource (RFC 8707 `resource` parameter)
   and one or both diagnostics scopes.
4. The director introspects every bearer token at Nauthilus with the OIDC
   client credentials of `runtime.servers.mcp.authority`. It accepts the token
   only when all of these hold:
   - Nauthilus reports it active and it has a future `exp`;
   - it was issued to a client listed in `runtime.servers.mcp.allowed_clients`;
   - it names a person: `sub` is set and differs from the client id, so service
     tokens are refused;
   - the person belongs to one of `runtime.servers.mcp.required_groups`, read
     from the claim `groups_claim` (default `groups`). Nauthilus does not
     evaluate group rights for resources it does not host, so the director
     enforces them itself;
   - its audience is the resource, alone or together with the issuing client,
     and nothing else;
   - it carries at least one diagnostics scope.
5. A tool whose scope the token lacks answers `403` with
   `error="insufficient_scope"` and the scope it needs, so the client can step
   up.

Token failures answer `401 invalid_token` without saying why. If Nauthilus
cannot be reached the endpoint answers `503` with `Retry-After`; it never falls
back to accepting a token.

## Nauthilus configuration

Prefer a confidential client dedicated to the endpoint that owns the MCP
resource and admits the MCP client. It needs no usable grant:

```yaml
identity:
  oidc:
    clients:
      - client_id: director-mcp
        client_secret: ${OIDC_CLIENT_SECRET_DIRECTOR_MCP}
        token_endpoint_auth_method: client_secret_post
        grant_types: [authorization_code]
        redirect_uris: []
        scopes: [openid]
        token_introspection:
          resources:
            - https://director.example.org/mcp
          clients:
            - support-cli
```

Configure it on the director under `runtime.servers.mcp.introspection_client`
(`client_id`, `auth_method`, `client_secret_file` or `client_private_key_file`).
Without it the director introspects with the authority's OIDC client
credentials, which then must own the resource instead.

The MCP client (`support-cli` in this example) is a static client that may
request the `nauthilus-director.diagnostics.runtime` and
`nauthilus-director.diagnostics.users` scopes, and whose access tokens carry
the user's groups in the `groups` claim. Grant the user scope only to
people who may see user keys and session placement. See the Nauthilus
documentation on OIDC introspection for the client and scope options.

## Director configuration

A production endpoint behind a TLS-terminating reverse proxy:

```yaml
runtime:
  servers:
    mcp:
      enabled: true
      address: 127.0.0.1:9097
      tls_termination: trusted_reverse_proxy
      resource: https://director.example.org/mcp
      authority: default
      allowed_clients: [support-cli]
      required_groups: [admin]
      introspection_client:
        client_id: director-mcp
        auth_method: client_secret_post
        client_secret_file: /etc/nauthilus-director/mcp/client-secret
      trusted_proxies: [127.0.0.1/32]
      limits:
        timeout: 15s
        max_concurrent: 8
        max_concurrent_per_principal: 2
        max_request_bytes: 65536
        max_response_bytes: 1048576
        failed_auth_per_minute: 30
      audit:
        enabled: true
```

The authority named by `authority` must have `oidc.enabled` and `oidc.issuer`.
Without `introspection_client` it also needs `oidc.client_credentials.enabled`
and an introspection endpoint client-auth method with its secret or key file. The issuer is published
unchanged in the protected resource metadata.

For a local test on one host, a plain http loopback resource needs no proxy:

```yaml
runtime:
  servers:
    mcp:
      enabled: true
      address: 127.0.0.1:9097
      resource: http://127.0.0.1:9097/mcp
      authority: default
      allowed_clients: [support-cli]
      required_groups: [admin]
```

Plain http is refused for any non-loopback resource host. All MCP settings are
read at startup; changing them requires a restart.

## Reverse proxy

Terminate TLS at the proxy and forward the endpoint path and the metadata path
to the MCP listener:

- `/<path>` (for example `/mcp`) — the MCP endpoint;
- `/.well-known/oauth-protected-resource/<path>` — the RFC 9728 metadata.

The proxy must set `X-Forwarded-Proto: https` and append the client address to
`X-Forwarded-For`; it may set `X-Forwarded-Host`. The director accepts these
headers only from `trusted_proxies`, takes the right-most untrusted
`X-Forwarded-For` hop as client address, and refuses requests whose scheme or
host does not match the resource. A request from any other peer is refused with
`403`. Requests with an `Origin` header outside `allowed_browser_origins` are
refused; the endpoint never sends CORS headers.

## Limits

| Setting | Effect |
| --- | --- |
| `limits.timeout` | Bounds one tool call (at most `1m`); a cut call answers `internal_error`. |
| `limits.max_concurrent` | In-flight requests over all principals (at most 64). |
| `limits.max_concurrent_per_principal` | In-flight requests of one person through one client. |
| `limits.max_request_bytes` | Larger bodies are refused with `413` before the SDK sees them. |
| `limits.max_response_bytes` | Larger results are replaced by a `response_too_large` tool error; narrow the filters or the page size. |
| `limits.failed_auth_per_minute` | Failed bearer attempts per client IPv4 address or IPv6 /64; afterwards `429`. Missing tokens are not counted. |

## Audit and metrics

Every request emits an `mcp.request` event:

- `nauthilus_director_mcp_requests_total{operation,status_class,result}` counts
  it. `operation` is the tool name or `transport` for requests refused before a
  tool runs.
- With `audit.enabled: true` (default) it is logged at info level with
  `actor_id` (client and subject), tool, result, HTTP status, refusal reason
  and problem code. With audit disabled the record is logged at debug level.
  Internal failures are logged at warn level.

Bearer tokens, tool arguments and results are never logged. The client address
appears only as `client_ip_present`, following the director log policy.

## Treat answers as data

Results contain user keys, backend, pool, listener and shard names that come
from configuration and runtime state. The endpoint tells the model to treat
every string in a result as untrusted data, never as instructions. Operators
should apply the same rule when an assistant quotes a result.
