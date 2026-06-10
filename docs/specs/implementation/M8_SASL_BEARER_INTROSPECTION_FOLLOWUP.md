# M8 SASL Bearer Introspection Follow-up

Status: completed.

This document defines a focused post-M8 repair and follow-up for
`XOAUTH2` and `OAUTHBEARER` handling in `nauthilus-director`.

The follow-up separates two OIDC use cases that have different security
meaning and must not share one configuration contract:

- Director-to-Nauthilus caller authentication, where the director obtains a
  client-credentials token so it may call Nauthilus backchannel APIs.
- Mail-protocol SASL bearer validation, where the director receives an
  end-user OAuth bearer token from `XOAUTH2` or `OAUTHBEARER` and asks
  Nauthilus' OIDC introspection endpoint whether that token is active and which
  account key it represents.

The implementation must start from the root production codebase and must not
preserve any transient partial implementation that conflated these flows.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M4_OBSERVABILITY_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/specs/implementation/M7_POP3_PROXY_SPEC.md`
- `docs/specs/implementation/M8_PRODUCTION_HARDENING_SPEC.md`
- `docs/specs/implementation/M8_LISTENER_AUTHORITY_CONTEXT_FOLLOWUP.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/man/nauthilus-director.yaml.5`
- sibling Nauthilus OIDC discovery, token and introspection contracts
- sibling PostfixToHTTP OIDC separation between backend caller auth and SASL
  bearer validation
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues. Nauthilus remains the authentication and OIDC
authority. The director remains responsible for listener handling, session
lifecycle, backend selection, routing, affinity and proxy behavior.

## Original Gap

M8 added OIDC client-credentials caller authentication for Director-to-Nauthilus
backchannel calls. That is the correct home for:

```yaml
auth:
  authorities:
    default:
      oidc:
        enabled: true
        issuer: https://auth.example.org
        client_credentials:
          enabled: true
          client_id: nauthilus-director
          token_endpoint_auth_method: client_secret_basic
          scopes:
            - nauthilus:authenticate
            - nauthilus:lookup_identity
            - nauthilus:list_accounts
```

Those settings describe the director as an OAuth client when it calls
Nauthilus. The resulting access token authorizes the director itself. It is not
the end-user token received through mail SASL.

The missing behavior is separate:

- IMAP, LMTP, ManageSieve and POP3 may receive `XOAUTH2` and `OAUTHBEARER`
  SASL envelopes.
- Those envelopes carry end-user bearer tokens.
- The director must not validate those tokens locally, cache those tokens, or
  send them through the password-oriented Nauthilus AuthService contract.
- The director must keep the original end-user bearer token available after
  successful introspection for the backend authentication step when backend
  policy delegates bearer mechanisms to credential replay.
- The director must call Nauthilus' OIDC introspection endpoint, discovered from
  configured OIDC metadata, and map the active introspection response into the
  existing `AuthResult` shape.

Current config drift to repair:

- `auth.authorities.<name>.oidc.required_scopes` is attached to the caller-auth
  OIDC subtree even though required end-user token scopes belong only to SASL
  bearer introspection.
- `auth.authorities.<name>.oidc.client_credentials.introspection_endpoint_auth_method`
  is attached to the client-credentials subtree even though introspection client
  authentication belongs to the SASL bearer introspection flow.
- `auth.authorities.<name>.oidc.client_credentials.scopes` must remain token
  request scopes for the director's own caller token and must not be reused as
  required end-user token scopes.

## Goal

Add a dedicated SASL bearer introspection configuration and implementation path
for each configured Nauthilus authority:

```yaml
auth:
  authorities:
    default:
      mechanisms:
        bearer:
          enabled: true
          names: [xoauth2, oauthbearer]
          validation: nauthilus_introspection
          token_max_bytes: 16384
          introspection:
            enabled: true
            discovery_url: https://auth.example.org/.well-known/openid-configuration
            client_id: nauthilus-director-sasl
            client_secret_file: /etc/nauthilus-director/nauthilus-introspection-client-secret
            auth_method: client_secret_basic
            required_scope: email
            account_claim: dovecot_account
      oidc:
        enabled: true
        issuer: https://auth.example.org
        client_credentials:
          enabled: true
          client_id: nauthilus-director
          client_secret_file: /etc/nauthilus-director/nauthilus-oidc-client-secret
          token_endpoint_auth_method: client_secret_basic
          scopes:
            - nauthilus:authenticate
            - nauthilus:lookup_identity
            - nauthilus:list_accounts
```

The exact final field names may be adjusted during implementation if they fit
the typed model better, but the semantic split is not optional:

- `auth.authorities.<name>.oidc.client_credentials.*` is caller auth for
  Director-to-Nauthilus API calls.
- `auth.authorities.<name>.mechanisms.bearer.introspection.*` is validation of
  incoming mail SASL end-user bearer tokens.

## Delivery Shape

Implement this follow-up as six slices:

1. Typed config split and validation for SASL bearer introspection.
2. Shared OIDC discovery and endpoint-auth helper reuse without mixing config
   ownership between client credentials and introspection.
3. Protocol-session integration for IMAP, LMTP, ManageSieve and POP3.
4. Backend-auth reconciliation for the hybrid master-user plus bearer-token
   model.
5. Observability, redaction and docs regeneration.
6. Public-boundary E2E proof and final closeout.

The implementation may reuse low-level OIDC helpers such as discovery document
fetching, endpoint-auth request preparation and `private_key_jwt` assertion
creation. It must not reuse the caller-auth `client_credentials` config object
as the SASL bearer introspection config object.

## Scope

In scope:

- Add a dedicated typed config subtree for SASL bearer introspection under
  `auth.authorities.<name>.mechanisms.bearer`.
- Keep `auth.authorities.<name>.mechanisms.bearer.enabled`,
  `names` and `token_max_bytes` as the mechanism advertisement and parser
  boundary.
- Change `validation` to a value that names the real boundary, such as
  `nauthilus_introspection`.
- Discover OIDC metadata from `issuer` or `discovery_url` configured in the new
  introspection subtree.
- Require a discovered `introspection_endpoint` when bearer mechanisms are
  enabled with `nauthilus_introspection`.
- Support endpoint client authentication for the introspection request:
  `client_secret_basic`, `client_secret_post` and `private_key_jwt`.
- Use the discovered `introspection_endpoint` as the `aud` value for
  `private_key_jwt` introspection client assertions.
- Clear any existing `Authorization` header before applying introspection
  endpoint client authentication.
- Validate active introspection responses fail closed.
- Require one end-user token scope from the introspection response. The config
  field is `required_scope`; its default is `email`.
- Add `account_claim` as an optional field that names the introspection response
  claim used as the director account key.
- Provide a conservative default account-claim resolution chain when
  `account_claim` is empty.
- Map active introspection responses into `AuthResult` with `Account`,
  optional `SessionID` and bounded `Attributes`.
- Keep tenant and shard routing facts flowing through the existing
  `AuthResult.Attributes` and routing resolver configuration.
- Reject credential-bearing frontend mechanisms before Nauthilus is called
  unless the frontend connection has active TLS.
- Bound SASL input and bearer token size with the existing mechanism limits.
- Keep endpoint discovery, introspection, logs, traces and metrics secret-safe.
- Update generated config references, target config and manpage documentation
  after typed config changes.

Out of scope:

- Local JWT or JWKS validation of end-user mail SASL bearer tokens in v1.
- Redis, disk or cross-process caching of end-user bearer tokens or
  introspection responses.
- Reusing `auth.authorities.<name>.oidc.client_credentials.scopes` as required
  end-user token scopes.
- Keeping `required_scopes` under `auth.authorities.<name>.oidc` as the SASL
  bearer policy surface.
- Sending mail SASL bearer tokens to Nauthilus AuthService password-style
  `Authenticate` calls.
- Letting Nauthilus choose director backends or routing targets.
- Runtime REST or CLI mutation of the static introspection configuration.
- Adding a separate management process or a non-Nauthilus introspection
  provider abstraction.

## Config Semantics

Caller auth remains under `auth.authorities.<name>.oidc.client_credentials`:

- The director is the OAuth client.
- The token endpoint issues a token for director backchannel calls.
- `scopes` are requested for the director's caller token.
- `token_endpoint_auth_method` controls how the director authenticates to the
  token endpoint.
- The access token is cached in-process per authority and never logged.

SASL bearer introspection belongs under
`auth.authorities.<name>.mechanisms.bearer.introspection`:

- The end user is represented by the incoming SASL bearer token.
- The director is only the confidential introspection client.
- `required_scope` names the end-user token scope that must appear in the
  introspection response. If omitted, default to `email`.
- `account_claim` optionally names the claim that carries the account key used
  for placement, affinity and backend routing.
- `auth_method` controls how the director authenticates to the introspection
  endpoint.
- Secret-bearing introspection client material must use protected config fields.

Validation rules:

- If bearer mechanisms are enabled and include `xoauth2` or `oauthbearer`,
  startup must fail closed unless `validation` selects
  `nauthilus_introspection` and introspection config is complete.
- If introspection is enabled, either `issuer` or `discovery_url` must be set.
- Discovery must find an `introspection_endpoint`.
- `required_scope` defaults to `email`; an explicitly configured empty value is
  invalid.
- `account_claim`, when set, must be a non-empty printable claim name and must
  not be one of the known secret-bearing response names such as `access_token`,
  `refresh_token`, `id_token` or `token`.
- Secret-based endpoint auth requires exactly one of `client_secret` or
  `client_secret_file`.
- `private_key_jwt` endpoint auth requires `client_private_key_file`; supported
  assertion algorithms remain the local OIDC helper allowlist.
- Direct `introspection_endpoint` overrides may be added only as an explicit
  compatibility setting with tests and documentation. Discovery remains the
  default.

Migration rules:

- Remove or deprecate `auth.authorities.<name>.oidc.required_scopes` for mail
  SASL bearer behavior.
- Move any `introspection_endpoint_auth_method` behavior out of
  `client_credentials`.
- Keep existing control-plane OIDC scope fields under
  `runtime.servers.control.auth.oidc` because those govern control API
  authorization, not mail SASL bearer validation.

## Startup and Discovery

During startup or safe reload, each enabled authority must build its
introspection client before listener sockets accept bearer-capable traffic.

The startup path must:

- Normalize and validate the typed config.
- Fetch or resolve the discovery document for the introspection config.
- Verify `issuer` when both a configured issuer and discovery response issuer
  are present.
- Require `introspection_endpoint`.
- Prepare endpoint-auth material without logging secrets.
- Fail closed if discovery or local validation fails.

This intentionally differs from lazy end-user token validation. A deployment
that advertises `XOAUTH2` or `OAUTHBEARER` should not start successfully when it
cannot discover the Nauthilus introspection endpoint needed to validate those
mechanisms.

## Protocol Semantics

For IMAP, LMTP, ManageSieve and POP3:

- Continue to parse `XOAUTH2` and `OAUTHBEARER` only far enough to extract the
  SASL identity, bearer token and bounded mechanism metadata.
- Reject malformed envelopes with bounded protocol errors.
- Reject bearer auth before TLS unless the listener is implicit TLS or has
  completed STARTTLS.
- Call the authority's SASL bearer introspector, not the password
  authenticator.
- Preserve the normalized mechanism name in request context and observability.
- Keep bearer material in short-lived credential objects after successful
  introspection until the backend auth handoff has either replayed it or failed
  closed.
- Clear bearer material after the backend auth handoff is complete or after the
  session aborts.
- Do not log usernames as metric labels, raw SASL blobs, raw bearer tokens or
  introspection response secrets.

An inactive token, missing required scope or policy rejection maps to an auth
rejection. Discovery failures, malformed active responses or introspection
transport failures map to temporary failure unless the protocol has a stricter
existing fail-closed response shape.

## Introspection Response Mapping

The response must be decoded as an RFC 7662-style JSON object with provider
extensions allowed. At minimum:

- `active` must be true.
- The required scope must be present in `scope`, whether the response encodes
  scopes as a space-separated string or a string list.
- An account key must be resolved.

When `account_claim` is configured, that claim is authoritative and must be
present with a non-empty string value.

When `account_claim` is empty, use a conservative default chain. The initial
chain should include account-oriented claim names before generic subject names,
for example:

```text
account
account_key
mail_account
dovecot_account
username
preferred_username
email
sub
```

The selected account key becomes `AuthResult.Account`. Non-secret scalar claims
may become bounded `AuthResult.Attributes` so existing routing attributes such
as tenant and shard tag continue to work. Secret-bearing claims must be dropped.

## Backchannel Transport Semantics

The authority's primary transport still controls password-oriented Nauthilus
operations:

- HTTP transport uses `/api/v1/auth/json`.
- gRPC transport uses `nauthilus.auth.v1.AuthService`.

SASL bearer introspection always uses the discovered HTTP OIDC introspection
endpoint. This is true even when the authority's password transport is gRPC,
because OIDC discovery, token and introspection endpoints are HTTP endpoints.

Director-to-Nauthilus caller authentication remains independent:

- HTTP and gRPC authority calls may be authorized with the director's
  client-credentials token from `auth.authorities.<name>.oidc.client_credentials`.
- The introspection request may use its own client ID, secret or private key.
- Sharing the same OIDC issuer is allowed, but sharing the same config object is
  not.

## Backend Authentication

After successful introspection, the director has two distinct pieces of state:

- A trusted account key and attributes returned by Nauthilus introspection.
- The original end-user bearer token received from the frontend SASL mechanism.

The account key drives routing, affinity and placement. The bearer token must
remain available for immediate backend authentication when backend policy
delegates bearer mechanisms to replay. It may not be persisted, cached, logged
or converted into another credential type.

The default hybrid model is:

- Password frontend credentials may continue to use backend `master_user` auth.
- In backend `master_user` mode, credential kind selects the backend auth
  branch: password credentials use the configured master-user login; bearer
  credentials delegate to credential replay after successful OIDC
  introspection.
- Bearer frontend credentials must not be converted into master-user password
  auth or discarded immediately after introspection.
- Bearer frontend credentials use backend credential replay only when the
  backend auth policy explicitly allows `xoauth2` or `oauthbearer`, preserves
  the mechanism where required, and enforces the configured backend TLS policy.
- If a backend cannot authenticate the bearer credential safely, the session
  must fail closed before proxying authenticated traffic.

This keeps the useful master-user model for password logins while preserving
the end-user bearer-token semantics for OAuth-bearing sessions.

## Observability

Metrics labels must remain low-cardinality and must not include usernames,
account keys, token hashes, session IDs, client IPs, trace IDs, raw backend
identifiers, raw errors, claim values or bearer material.

Allowed labels for the bearer introspection boundary are limited to stable
classifiers such as:

- authority name
- listener name
- protocol
- mechanism
- transport class
- result
- reason class

Logs and traces may record bounded booleans and classifiers, such as whether a
required scope was present, whether an account claim was configured, and whether
the token was active. They must not record raw token material, secret-bearing
response claims or unbounded account identifiers.

## Required Tests

Config tests:

- Accept complete `nauthilus_introspection` config for bearer mechanisms.
- Reject bearer mechanisms without complete introspection config.
- Reject incomplete discovery, endpoint auth, secret and private-key settings.
- Verify `required_scope` defaults to `email`.
- Reject `account_claim` values that are empty or secret-bearing.
- Verify caller-auth `client_credentials.scopes` and introspection
  `required_scope` are independent.

OIDC helper tests:

- Discovery requires `introspection_endpoint`.
- `client_secret_basic`, `client_secret_post` and `private_key_jwt` apply client
  authentication to introspection requests correctly.
- `private_key_jwt` uses the introspection endpoint as audience.
- Existing `Authorization` headers are cleared before endpoint auth is applied.
- Secret files and bearer tokens stay out of errors and logs.

Protocol unit tests:

- IMAP, LMTP, ManageSieve and POP3 call the bearer introspection boundary for
  `XOAUTH2` and `OAUTHBEARER`.
- Password mechanisms continue to call the existing password authenticator.
- Bearer mechanisms before TLS fail closed without reaching introspection.
- Oversized and malformed SASL bearer envelopes fail safely.

Backend-auth tests:

- Password sessions can still use master-user backend auth.
- Bearer sessions do not use master-user password auth.
- In `master_user` backend mode, bearer sessions delegate to credential replay
  after OIDC introspection.
- Bearer sessions use credential replay only when policy allows the original
  mechanism and backend TLS requirements are satisfied.
- The original end-user bearer token remains available for replay and is
  cleared after replay or abort.
- Unsafe backend replay policy fails closed before backend auth bytes are sent.

E2E tests:

- Fake HTTP authority with OIDC discovery and introspection proves IMAP
  `XOAUTH2` and `OAUTHBEARER` authenticate through the public socket.
- Equivalent public proof exists for POP3 and ManageSieve.
- LMTP peer bearer auth proves the same shared boundary where LMTP bearer peer
  auth is enabled.
- gRPC password authority proof remains green while bearer auth uses the HTTP
  OIDC introspection endpoint.
- Process output and route lookup output omit bearer token sentinels.

Documentation checks:

- Run `make generate-docs` after typed config/default changes.
- Run `make check-docs`.
- Run focused package tests while iterating.
- Run `make guardrails` before commit or pull request.

## Acceptance Criteria

- Caller-auth OIDC client credentials and mail SASL bearer introspection have
  separate typed config surfaces.
- `auth.authorities.<name>.oidc.client_credentials.*` no longer contains
  introspection-specific policy such as required end-user scopes.
- `XOAUTH2` and `OAUTHBEARER` validation calls Nauthilus' discovered
  introspection endpoint and does not use password AuthService calls.
- The required end-user token scope defaults to `email` and is enforced only in
  the SASL bearer introspection path.
- Operators can configure an account claim for the account key used by routing
  and affinity.
- End-user bearer tokens are retained only in short-lived credential state long
  enough for policy-gated backend replay; they are not cached, logged, traced or
  exposed as metrics.
- The hybrid backend-auth model is documented and implemented: master-user for
  password frontend credentials, explicit policy-gated bearer replay for bearer
  frontend credentials, including when the backend auth mode is `master_user`.
- Public-boundary tests prove behavior for the supported bearer-capable
  protocols.
- Generated config docs, manpages, architecture docs and this spec agree.

## Completion Evidence

- `make generate-docs`: PASS. Generated config references and manpages are
  current after the bearer-introspection typed config changes.
- `make check-docs`: PASS. Config metadata, defaults, paths and manpage output
  are reproducible.
- `GOCACHE=/private/tmp/nauthilus-director-go-cache NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY=/private/tmp/nauthilus-director-e2e/nauthilus-director go test -mod=vendor -count=1 ./test/e2e -run 'TestServerBinarySASLBearer|TestServerBinaryPublicPOP3ProductionFlow|TestServerBinaryPublicSieveProductionFlow|TestServerBinaryPublicPOP3GRPCAuthorityFlow|TestServerBinaryPublicLMTPBearerPeerIntrospectionFlow'`:
  PASS. This is the focused real-binary public proof for IMAP, POP3,
  ManageSieve, mixed gRPC-password/HTTP-OIDC bearer auth, and LMTP peer bearer
  auth.
- `make test`: PASS. Redis-backed integration tests ran where the local Valkey
  fixture was available; environment-specific Redis tests without configured
  `REDIS_ADDR` remained skipped by their existing guard.
- `make race`: PASS.
- `make e2e`: PASS. Fake-service E2E completed with the real server binary,
  fake IMAP, LMTP, ManageSieve and POP3 backends, OIDC bearer caller auth,
  SASL bearer public proof, route lookup and observability checks. The
  guardrails-internal E2E invocation still skips real-binary tests when
  `NAUTHILUS_DIRECTOR_E2E_SERVER_BINARY` is unset; the focused command above
  supplies that binary and is the public-boundary proof.
- `make build-check`: PASS.
- `make guardrails`: PASS. Final repository gate completed with `make fix`,
  `make vet`, `make lint`, `make test`, `make race`, `make e2e` and
  `make build-check`.
- `make e2e-interop`: PASS. Full Docker-backed interop completed with OIDC
  bearer caller auth, the real server binary, six Dovecot IMAP backends,
  Dovecot LMTP, ManageSieve and POP3 backends, swaks-to-Postfix submitter,
  curl IMAP delivery proof, health ownership, cluster affinity and runtime
  control.
- `git diff --check`: PASS.
- `git status --short`: recorded in final closeout. Ignored `temp/` artifacts
  remain unstaged.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Config split | Caller auth and SASL bearer introspection use separate typed config surfaces | `auth.authorities.<name>.oidc.client_credentials` remains caller auth; `auth.authorities.<name>.mechanisms.bearer.introspection` owns mail SASL bearer validation | Complete | Generated config docs and manpage include the split |
| Discovery | Startup discovers Nauthilus OIDC metadata and requires `introspection_endpoint` for bearer mechanisms | Bearer-capable listener startup builds an introspector from discovery metadata and fails closed when required discovery or endpoint-auth material is missing | Complete | Shared OIDC helpers keep caller-token and SASL-bearer operation classes separate |
| Scope policy | Required end-user token scope belongs only to SASL bearer introspection | `required_scope` defaults to `email`, is enforced on active introspection responses, and is independent from caller-token request scopes | Complete | Missing scope rejects auth without falling back to password AuthService |
| Account key | Optional configured claim controls account-key extraction | Configured `account_claim` is authoritative; the default chain resolves account-like claims before generic subject claims; missing account fails closed | Complete | Secret-bearing claim names are rejected and omitted from attributes |
| Protocols | IMAP, LMTP, ManageSieve and POP3 use a shared bearer introspection boundary | Public E2E covers IMAP `XOAUTH2`/`OAUTHBEARER`, POP3 `AUTH XOAUTH2`/`AUTH OAUTHBEARER`, ManageSieve `AUTHENTICATE XOAUTH2`/`AUTHENTICATE OAUTHBEARER`, and LMTP peer bearer auth | Complete | gRPC password authority remains green while bearer auth uses HTTP OIDC introspection |
| Backend auth | Hybrid master-user plus bearer replay semantics are explicit | Password credentials continue to use master-user auth; bearer credentials replay the original mechanism only when policy and backend TLS requirements allow it | Complete | Tests prove bearer replay is not converted into master-user password auth |
| Proof | Public-boundary tests and guardrails pass | Focused real-binary public proof, `make e2e`, `make guardrails`, `make e2e-interop`, `make check-docs` and `git diff --check` pass | Complete | Final response records exact commands and `git status --short` |
