# Nauthilus OIDC Operations

This runbook covers OIDC for three different Director paths:

1. Director-to-Nauthilus caller authentication for authority calls.
2. Control-plane OIDC validation for operator and automation requests.
3. Mail SASL `XOAUTH2` and `OAUTHBEARER` end-user bearer-token validation.

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
configured. A direct `discovery_url` still requires the matching `issuer` as a
local issuer pin and must use HTTPS unless it points to loopback HTTP for local
development. Discovery must provide usable `token_endpoint` and
`introspection_endpoint` values, return the pinned issuer, and advertise the
configured client auth methods. Missing or mismatched metadata fails closed
when OIDC caller auth, control-plane OIDC validation or SASL bearer
introspection requires it.

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

`auth.authorities.<name>.oidc.client_credentials.*` configures the Director as
the OAuth client for Nauthilus backchannel calls. Its
`introspection_endpoint_auth_method` is used when control-plane OIDC validation
introspects operator tokens through this authority. It is not the mail SASL
bearer introspection endpoint-auth setting.

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

These caller-token request scopes are independent from the end-user token scope
required for mail SASL bearer introspection. Do not use
`auth.authorities.<name>.oidc.client_credentials.scopes` as the mail SASL
bearer policy surface.

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

Mail-protocol `XOAUTH2` and `OAUTHBEARER` credentials are end-user bearer
tokens. They are not Director caller-auth tokens and they are not validated
through the password-shaped Nauthilus AuthService contract.

Configure mail SASL bearer validation under
`auth.authorities.<name>.mechanisms.bearer.introspection`:

```yaml
auth:
  authorities:
    default:
      mechanisms:
        bearer:
          enabled: true
          names:
            - xoauth2
            - oauthbearer
          validation: nauthilus_introspection
          token_max_bytes: 16384
          introspection:
            enabled: true
            issuer: https://auth.example.org
            discovery_url: ""
            client_id: nauthilus-director-sasl
            client_secret_file: /etc/nauthilus-director/nauthilus-introspection-client-secret
            auth_method: client_secret_basic
            required_scope: email
            account_claim: ""
```

The Director parses the SASL envelope only enough to extract bounded mechanism
metadata and bearer material. It then calls the discovered HTTP OIDC
`introspection_endpoint` as a configured confidential introspection client.
This HTTP introspection path is used even when password-oriented authority calls
use gRPC.

`required_scope` names the end-user token scope that must be present in the
introspection response. It defaults to `email`. `account_claim` optionally names
the non-secret response claim used as the Director account key for routing,
affinity and placement; when empty, the Director uses its conservative
account-claim chain.

### Routing Bearer Logins

A token names the account but does not carry the directory routing facts a
password login receives, above all the shard attribute
(`director.routing.auth_attributes.shard_tag`, `mailShard` by default). IMAP,
POP3 and ManageSieve listeners therefore follow every successful introspection
with one no-credential identity lookup for the token account over the
authority transport: HTTP `POST /api/v1/auth/json?mode=no-auth` or gRPC
`AuthService.LookupIdentity`, with the listener protocol (`imap`, `pop3`,
`sieve`), method `recipient_lookup`, the client and TLS facts of the session
and the listener's `authority_context`. Nauthilus must answer that lookup with
the same attributes it returns for a password login on the protocol; the
director client needs the `nauthilus:lookup_identity` scope when OIDC caller
auth is enabled. The routing attributes (`director.routing.auth_attributes`
shard tag and tenant) come only from the lookup: token claims with those names
are dropped, so a token cannot choose its own shard.

| Lookup outcome | Client sees |
| --- | --- |
| Same account with shard attribute | Login succeeds and is routed to that shard. |
| Same account without shard attribute | Login succeeds and is hashed like a password login without the attribute; the lookup metric carries `reason_class=bearer_shard_missing`. |
| Different account | Authentication failure (`reason_class=bearer_account_mismatch`). |
| Account unknown | Authentication failure (`reason_class=bearer_identity_rejected`). |
| Timeout, transport error, temporary failure | Temporary failure; the login is never routed by hash instead. |

Each bearer login costs one extra authority round trip; introspection and
lookup share `runtime.timeouts.auth`. Before `v1.1.2` these listeners routed on
token claims alone and hashed accounts whose token carried no shard attribute,
which could place a user on a mail store that does not hold the mailbox.
Password logins still hash when Nauthilus omits the shard attribute, so keep
the attribute populated for every mailbox account.

The original end-user bearer token may be retained only in short-lived
credential state after successful introspection and only long enough for
policy-gated backend replay. Backend replay is allowed only when backend auth
policy explicitly permits the original mechanism and the configured backend TLS
policy is satisfied. It is not a compatibility bypass for TLS or allowed
mechanism policy.

The Director does not locally validate JWTs, cache introspection responses,
persist end-user bearer tokens, log bearer material or expose account keys,
token hashes or claim values as metric labels.

### Native Mail Clients And The Introspection Allowlist

The default token binding, `audience_resource`, accepts a token only when its
audience matches `required_audience` or its RFC 8707 resource matches
`required_resource`. That fits a webmail client whose client id is the required
audience, or clients that request the mail resource. Native mail clients such as
Thunderbird register themselves through dynamic client registration (for
example the Nauthilus profile `mail-client-v1`) and receive tokens whose
audience is their own, random client id; autoconfiguration cannot make them
request a resource. The default binding therefore refuses them on IMAP, POP3,
ManageSieve and JMAP.

For these deployments a listener can opt into
`token_binding: introspection_allowlist`:

```yaml
director:
  listeners:
    imaps:
      imap:
        bearer:
          token_binding: introspection_allowlist
          introspection_client:
            client_id: director-mail-introspection
            auth_method: client_secret_basic
            client_secret_file: /etc/nauthilus-director/mail-introspection-secret
```

The same keys exist under `pop3.bearer` and `sieve.bearer`; JMAP uses
`jmap.auth.bearer.token_binding` next to its existing
`jmap.auth.bearer.introspection_client`. The mode is rejected at startup
without `introspection_client.client_id`.

Why this is an equivalent binding: Nauthilus answers `active: true` to an
introspecting client only for tokens issued to that client itself, for tokens
bound to a resource that client owns, and for plain user tokens whose issuing
client or dynamic-client profile is on that client's `token_introspection`
allowlist (`clients`, `dynamic_client_profiles`); service tokens are never
active for it. With a client dedicated to the mail listener, the provider
therefore performs the audience check that the director would otherwise do,
using an allowlist instead of a single audience. The director keeps a local
guard on top: in this mode it accepts a token when it matches a configured
audience or resource, or when it is a plain user token, meaning its only
audience is its issuing client (`azp`, or the single `aud` without `azp`), it
has no `resource` claim and no `client_id` service discriminator. The
`client_id` claim as service-token discriminator is a Nauthilus convention
(service tokens carry it, user tokens do not); other providers need not follow
it. Tokens bound to another resource are refused even if the provider reports
them active.

`required_resource` matches an RFC 8707 resource in the token audience, which
is how Nauthilus encodes resources (`aud` = issuing client plus resources, no
`resource` claim), or in a `resource` claim for providers that send one. Before
`v1.1.2` only the `resource` claim was checked, so Nauthilus resource tokens
were refused.
`required_scope` and `account_claim` are enforced exactly as before, and the
identity lookup still binds the token account to the directory.

Requirements and risks:

- Register a confidential introspection client used only by the director mail
  listeners and give it its own secret or key; never reuse a webmail, JMAP
  backend or other resource-server client, because every token that client may
  introspect becomes a valid mail login. The director refuses an
  `introspection_client.client_id` equal to the authority's
  `mechanisms.bearer.introspection.client_id`.
- Nauthilus reports tokens issued to the introspecting client itself as active
  without consulting the allowlist. The dedicated client must therefore never
  obtain user tokens: confidential, used only for introspection (at most the
  `client_credentials` grant), no redirect URIs and no interactive grants
  (authorization code, device code, refresh tokens).
- Its allowlist must name only mail clients: the dynamic-client profile of
  native mail clients and, when webmail logs in through the same listener, the
  webmail client. Every token of the listener is introspected with this client,
  so a webmail client missing from the allowlist is refused even though its
  audience matches `required_audience`.
- The binding is only as narrow as the allowlist and the dynamic registration
  policy behind it. Anyone who can register a client under an allowlisted
  profile can obtain tokens that the listener accepts for the user who
  consented; keep registration limited to that profile's redirect and scope
  rules and require the mail scope.
- Keep the default `audience_resource` on listeners that do not need native
  clients.

## Proof Commands

| Command | Behavior proved |
| --- | --- |
| `make e2e` | Deterministic public-socket proof for OIDC caller-token acquisition, Bearer authority requests, insufficient-scope denial, bad-client-secret denial and mail SASL bearer introspection through fake Nauthilus fixtures. |
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

Mail SASL bearer introspection is a separate rollout step. Register a
confidential Nauthilus introspection client for the Director, mount its secret
or private key, configure `mechanisms.bearer.introspection.*`, restart, then
prove `XOAUTH2` or `OAUTHBEARER` through a public protocol socket. Do not move
the required end-user token scope into the caller-auth `client_credentials`
scope list.

Rollback is a config restart, not a runtime mutation. Restore the previous
authority caller-auth config from version control or a reviewed backup, restart,
then rotate any failed OIDC secret material.

## Failure Modes

| Failure | Operator symptom | Safe response |
| --- | --- | --- |
| Discovery unavailable | Startup, reload validation or first token acquisition fails closed for OIDC-enabled authority. | Check issuer/discovery URL reachability from the Director host, TLS trust roots and Nauthilus OIDC availability. |
| Direct discovery rejected | Startup, reload validation or first OIDC use fails before fetching metadata. | Configure `issuer` together with `discovery_url`, and use HTTPS unless the URL is loopback HTTP for local development. |
| Token endpoint unavailable | Protocol auth paths that need Nauthilus fail once no unexpired cached caller token is available. | Check Nauthilus token endpoint health and network/TLS path; do not fall back silently. |
| Bad client secret or private key | Token endpoint returns an authentication error; no caller token is cached. | Verify mounted secret file path, ownership and Nauthilus client registration; rotate the secret if exposed. |
| Expired token plus refresh failure | Existing unexpired cache cannot be used; authority calls fail closed. | Repair Nauthilus or network path and let the process acquire a new token. |
| Insufficient authority scope | Nauthilus rejects the backchannel request. | Add the missing backchannel scope to the Nauthilus client and restart after config validation. |
| Control token audience mismatch | Nauthilus introspection returns inactive for the operator token. | Issue the control token for the Director control OIDC client audience expected by Nauthilus introspection. |
| Control token unbound locally | Control requests return `403` even though the token is active and scoped. | Set `runtime.servers.control.auth.oidc.required_audience` or `required_resource` to the local token binding and issue tokens with a matching `aud` or `resource` claim. |
| Control token missing protected scope | Normal control commands work; protected config or pprof returns `403`. | Use a short-lived token with the protected scope only for the protected operation. |
| Control introspection inactive or denied | Control requests return `401` or `403` without revealing token detail. | Check token lifetime, audience, client registration, `oidc.client_credentials.introspection_endpoint_auth_method` and Nauthilus logs. |
| Mail SASL bearer identity lookup failed | Active tokens fail with a temporary error, or with an authentication failure when the lookup names another or no account. | Check that Nauthilus answers `mode=no-auth` / `LookupIdentity` for the listener protocol with the token account (the `account_claim` value), that the lookup returns the same canonical account, the caller scope `nauthilus:lookup_identity`, and the `reason_class` of the `recipient_lookup` Nauthilus auth metric. |
| Native mail client token refused | `XOAUTH2`/`OAUTHBEARER` from Thunderbird or another dynamically registered client fails with an audience or resource mismatch while webmail works. | The listener uses the default `audience_resource` binding; set `token_binding: introspection_allowlist` with a dedicated `introspection_client` whose Nauthilus `token_introspection` allowlist contains the mail-client profile (and the webmail client). |
| Mail SASL bearer introspection denied | `XOAUTH2` or `OAUTHBEARER` auth is rejected or temporarily fails without token detail. | Check `mechanisms.bearer.introspection.required_audience` or `required_resource`, `required_scope`, `account_claim`, endpoint client-auth method, Nauthilus introspection logs and backend replay policy. |
