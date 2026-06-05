# Nauthilus OIDC Operations

This runbook covers OIDC for two different Director paths:

1. Director-to-Nauthilus caller authentication for authority calls.
2. Control-plane OIDC validation for operator and automation requests.

OIDC with Nauthilus-issued client-credentials tokens is the recommended
production caller-auth mode. Basic Auth and static bearer files remain explicit
compatibility or emergency modes.

## Authority Caller Auth Modes

`auth.authorities.<name>` defines how the Director calls Nauthilus.

| Transport | Recommended production caller auth | Compatibility modes |
| --- | --- | --- |
| HTTP | `auth.authorities.<name>.oidc.client_credentials.enabled: true` | `http.basic_auth` |
| gRPC | `grpc.caller_auth.oidc.enabled: true` plus authority OIDC client credentials | `grpc.caller_auth.basic`, `grpc.caller_auth.bearer` |

When HTTP authority OIDC is enabled, `/api/v1/*` authority requests send a
bearer caller token and do not also send Basic Auth. When gRPC authority OIDC is
enabled, `AuthService` RPCs send `authorization: Bearer` metadata and do not
also send Basic metadata.

The gRPC transport does not have a token-acquisition RPC. Even for gRPC
authority calls, the Director obtains client-credentials tokens from the
Nauthilus HTTP OIDC token endpoint discovered from the issuer metadata.

## Nauthilus Discovery

Configure either `issuer` or `discovery_url`:

```yaml
auth:
  authorities:
    default:
      oidc:
        enabled: true
        authority_mode: nauthilus
        issuer: https://auth.example.org
        discovery_url: ""
```

The Director discovers Nauthilus metadata from the issuer's
`/.well-known/openid-configuration` unless an explicit discovery URL is
configured. Discovery must provide usable `token_endpoint` and
`introspection_endpoint` values and must advertise the configured client auth
methods. Missing metadata fails closed when OIDC is enabled.

Direct `token_endpoint` overrides are compatibility settings. Prefer discovery
unless a deployment has a documented reason to pin a token endpoint.

## Client Credentials

Recommended secret-file configuration:

```yaml
auth:
  authorities:
    default:
      oidc:
        client_credentials:
          enabled: true
          client_id: nauthilus-director
          client_secret_file: /etc/nauthilus-director/nauthilus-oidc-client-secret
          token_endpoint_auth_method: client_secret_basic
          introspection_endpoint_auth_method: client_secret_basic
          scopes:
            - nauthilus:authenticate
            - nauthilus:lookup_identity
            - nauthilus:list_accounts
          refresh_before_expiry: 1m
```

Supported token endpoint auth methods are `client_secret_basic`,
`client_secret_post` and `private_key_jwt`. For `private_key_jwt`, use a mounted
private key file and configure the assertion algorithm and key ID expected by
Nauthilus:

```yaml
auth:
  authorities:
    default:
      oidc:
        client_credentials:
          token_endpoint_auth_method: private_key_jwt
          introspection_endpoint_auth_method: private_key_jwt
          client_private_key_file: /etc/nauthilus-director/nauthilus-oidc-client-key.pem
          client_key_id: director-key-1
          client_assertion_alg: RS256
```

Do not put client secrets or private key material directly in examples, unit
files or image layers.

## Scopes

Authority caller tokens need the Nauthilus backchannel scopes for the authority
operations the Director can perform:

| Operation | Scope |
| --- | --- |
| Authenticate | `nauthilus:authenticate` |
| Lookup identity | `nauthilus:lookup_identity` |
| List accounts | `nauthilus:list_accounts` |

If a deployment uses one shared authority token for all operations, configure
all scopes required by the enabled authority client.

Control-plane OIDC uses different scopes under
`runtime.servers.control.auth.oidc`:

```yaml
runtime:
  servers:
    control:
      auth:
        oidc:
          enabled: true
          authority: default
          validation: nauthilus
          required_scopes:
            - nauthilus-director.admin
          protected_scopes:
            - nauthilus-director.protected
```

The ordinary scope authorizes normal control reads and mutations. The protected
scope is additionally required for protected config output and pprof.

## Token Cache And Refresh

The Director token cache is in-memory only. It is per Director process and per
authority. Tokens are not stored in Redis, not shared across processes and not
preserved across restart.

The cache refreshes before token expiry using
`refresh_before_expiry`. A refresh failure can continue with an existing
unexpired token. If no unexpired token is available, authority calls fail
closed until token acquisition succeeds.

Token values, client secrets, private keys and authorization headers must not
appear in logs, metrics, traces, CLI output or test output.

## End-User Mail Bearer Tokens

Mail-protocol `XOAUTH2` and `OAUTHBEARER` credentials are not Director caller
auth. The Director parses those SASL envelopes only enough to extract the
authentication identity, mechanism identity and bearer material, then forwards
that credential material to Nauthilus through the selected authority transport.

The Director does not locally validate, introspect, cache or log end-user mail
bearer tokens.

## Proof Commands

| Command | Behavior proved |
| --- | --- |
| `make e2e` | Deterministic public-socket proof for OIDC caller-token acquisition, Bearer authority requests, insufficient-scope denial, bad-client-secret denial and mail SASL bearer forwarding through fake Nauthilus fixtures. |
| `make e2e-interop` | Docker-capable real Dovecot/Postfix protocol proof with fake Nauthilus requiring OIDC Bearer caller auth instead of Basic Auth. |
| `contrib/demo-stack/scripts/send-mail.sh alice@example.test` and `contrib/demo-stack/scripts/fetch-mail.sh alice@example.test` | Demo-stack SMTP-to-LMTPS delivery and IMAPS read path while the paired demo configs use OIDC as the primary Director-to-Nauthilus caller-auth mode. |
| `contrib/demo-stack/scripts/prove-affinity.sh` | Demo-stack public IMAPS plus SMTP/LMTP proof through the control API using the OIDC-primary authority config. |
| `contrib/demo-stack/scripts/prove-pop3.sh` and `contrib/demo-stack/scripts/prove-managesieve.sh` | POP3 and ManageSieve protocol regressions over public ports using the same OIDC-primary authority config. |
| `make docker-smoke` | Optional production image smoke check; skips with an explicit environment message when Docker is unavailable. |
| `make systemd-verify` | Optional static systemd unit verification; skips with an explicit environment message when `systemd-analyze` is unavailable. |

## Migration From Basic Auth

Use this workflow when moving from earlier Basic-auth demo or development
authority configs to OIDC caller auth.

1. Register a Nauthilus OIDC client for the Director. Allow
   `client_credentials` and the required backchannel scopes.
2. Store the client secret or private key as a mounted file readable by the
   Director service user.
3. Configure `auth.authorities.<name>.oidc.enabled: true` and
   `client_credentials.enabled: true`.
4. For HTTP authority transport, keep `http.basic_auth` present only as a
   documented compatibility fallback. OIDC-enabled HTTP calls send bearer
   caller auth instead of Basic Auth.
5. For gRPC authority transport, enable `grpc.caller_auth.oidc.enabled: true`
   and disable other gRPC caller-auth methods so validation rejects ambiguous
   configuration.
6. Validate config with `nauthilus-director config dump -n --format yaml`.
7. Restart the process, because authority authentication belongs to the
   process-owned auth configuration.
8. Prove a real protocol login or delivery path and confirm Nauthilus sees an
   OIDC-authenticated Director caller.
9. Remove or rotate Basic Auth secrets after the deployment no longer needs the
   compatibility path.

Rollback is a config restart, not a runtime mutation. Restore the previous
authority caller-auth config from version control or a reviewed backup, restart,
then rotate any failed OIDC secret material.

## Failure Modes

| Failure | Operator symptom | Safe response |
| --- | --- | --- |
| Discovery unavailable | Startup, reload validation or first token acquisition fails closed for OIDC-enabled authority. | Check issuer/discovery URL reachability from the Director host, TLS trust roots and Nauthilus OIDC availability. |
| Token endpoint unavailable | Protocol auth paths that need Nauthilus fail once no unexpired cached caller token is available. | Check Nauthilus token endpoint health and network/TLS path; do not fall back silently. |
| Bad client secret or private key | Token endpoint returns an authentication error; no caller token is cached. | Verify mounted secret file path, ownership and Nauthilus client registration; rotate the secret if exposed. |
| Expired token plus refresh failure | Existing unexpired cache cannot be used; authority calls fail closed. | Repair Nauthilus or network path and let the process acquire a new token. |
| Insufficient authority scope | Nauthilus rejects the backchannel request. | Add the missing backchannel scope to the Nauthilus client and restart after config validation. |
| Control token audience mismatch | Nauthilus introspection returns inactive for the operator token. | Issue the control token for the Director control OIDC client audience expected by Nauthilus introspection. |
| Control token missing protected scope | Normal control commands work; protected config or pprof returns `403`. | Use a short-lived token with the protected scope only for the protected operation. |
| Introspection inactive or denied | Control requests return `401` or `403` without revealing token detail. | Check token lifetime, audience, client registration, introspection auth method and Nauthilus logs. |
