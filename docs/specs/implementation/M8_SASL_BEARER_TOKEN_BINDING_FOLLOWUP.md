# M8 SASL Bearer Token Binding Follow-up

Status: completed for release `v1.1.2`.

This follow-up adds an explicit, opt-in token binding mode for listeners whose
users log in with native mail clients, and extends the per-listener
introspection client of JMAP (`c1e0a98`) to IMAP, POP3 and ManageSieve.

## Problem

Every bearer-capable listener requires `required_audience` or
`required_resource` (`validateOIDCTokenBinding`) and accepts only tokens that
match one of them. In production the IMAP authority policy names the webmail
client id as audience and JMAP names the RFC 8707 resource of the mail host.

Native mail clients register through Nauthilus dynamic client registration
(profile `mail-client-v1`). Their tokens carry their own random client id as
audience and no resource, because autoconfiguration cannot tell a client to
request one. The director refused those logins on IMAP, POP3, ManageSieve and
JMAP although Nauthilus had issued the tokens for mail access.

Nauthilus already binds tokens at the provider: an introspecting client gets
`active: true` only for tokens issued to itself, for resource tokens of
resources it owns, and for plain user tokens whose issuing client or
dynamic-client profile is on its `token_introspection` allowlist
(`clients`, `dynamic_client_profiles`). Service tokens are never active for it.

## Decision

A listener may set `token_binding: introspection_allowlist`. The default,
`audience_resource`, keeps the established behaviour unchanged.

| Setting | Location |
| --- | --- |
| IMAP | `director.listeners.<name>.imap.bearer.token_binding` |
| POP3 | `director.listeners.<name>.pop3.bearer.token_binding` |
| ManageSieve | `director.listeners.<name>.sieve.bearer.token_binding` |
| JMAP | `director.listeners.<name>.jmap.auth.bearer.token_binding` |

The allowlist binding is sound only when the introspecting client is dedicated
to the listener, because the provider allowlist of that client becomes the
audience policy. Validation therefore refuses the mode without
`introspection_client.client_id`. `required_scope` stays mandatory.

### Accepted tokens

With `introspection_allowlist` an active token is accepted when either

- its audience matches the configured `required_audience` or its resource
  matches `required_resource` (the default rule), or
- it is a plain user token: it has no `client_id` claim (service tokens carry
  one), no `resource` claim, a non-empty audience, and every audience value
  equals the issuing client, which is `azp` or, without `azp`, the single
  audience value. This mirrors how Nauthilus classifies plain tokens for its
  allowlist. The `client_id` claim as service-token discriminator is a
  Nauthilus-specific provider assumption.

`required_resource` matches an RFC 8707 resource in the audience list
(section 2 of RFC 8707; Nauthilus issues `aud` = issuing client plus resources
and no `resource` claim) or in a `resource` claim sent by other providers. A
Nauthilus resource token (`aud` = [azp, resource]) is never a plain token, so a
token for a resource other than `required_resource` is refused in both modes.
Audience arrays are compared value by value without splitting on whitespace.

A token bound to any other resource is refused locally even when the provider
reports it active. The scope check, the account claim and the identity lookup
of `M8_SASL_BEARER_IDENTITY_ROUTING_FOLLOWUP.md` apply unchanged.

For IMAP, POP3 and ManageSieve the audience and resource stay the authority
values (`auth.authorities.<name>.mechanisms.bearer.introspection`), so the
authority validation still requires one of them. JMAP owns its token policy;
with the allowlist binding its `required_audience` and `required_resource` are
optional.

### Per-listener introspection client

`imap.bearer.introspection_client`, `pop3.bearer.introspection_client` and
`sieve.bearer.introspection_client` have the fields and rules of
`jmap.auth.bearer.introspection_client` and share its implementation
(`config.ListenerIntrospectionClientConfig`): `client_id`, `auth_method`
(default `client_secret_basic`), `client_secret_file` or
`client_private_key_file` with `client_key_id` and `client_assertion_alg`.
It replaces every authority client credential for that listener; the endpoint
and the token policy stay the authority's. Secrets are file paths only, checked
for readability at listener start with path-free errors and re-read for every
introspection. Credentials without `client_id` are refused.

The token binding is not configurable on the authority. It travels internally
in `BearerIntrospectionConfig.TokenBinding`, which has no config path.

## Security Reasoning

The provider-side check is equivalent to the local audience check when the
introspection client is dedicated: the provider decides "was this token issued
for a client that may log in here" using an allowlist instead of one audience.
Operators must

- register a confidential introspection client used only by the director mail
  listeners and never reuse a webmail, JMAP backend or other resource-server
  client; validation refuses a dedicated `client_id` equal to the authority's
  mail SASL introspection client;
- keep that client unable to obtain user tokens (introspection and at most
  `client_credentials`, no redirect URIs, no interactive grants), because
  Nauthilus reports tokens issued to the introspecting client itself as active
  without consulting the allowlist;
- keep its allowlist to mail clients, including the webmail client if webmail
  logs in through the same listener (every token of the listener is
  introspected with this client);
- keep dynamic registration for the allowlisted profile restricted, because
  anyone able to register under that profile obtains tokens the listener
  accepts for consenting users.

Listeners that do not serve native clients keep `audience_resource`.

## Evidence

- Config: `internal/config/listener_bearer_test.go` (defaults, allowlist without
  dedicated client refused, unknown values, orphan credentials, policy keeps the
  authority audience and scope, JMAP audience optional only with the allowlist
  binding).
- Introspection: `internal/nauthilus/bearer_token_binding_test.go` (foreign
  plain token refused by default and accepted with the binding, configured
  audience and resource still accepted, resource-bound, service and ambiguous
  tokens refused, scope enforced, no local audience needed only with the
  binding).
- Listener wiring: `TestMailboxListenerUsesDedicatedIntrospectionClientAndBinding`.
- E2E with the real binary and the fake authority:
  `TestServerBinaryBearerIntrospectionAllowlistBinding` proves a DCR-style token
  with a foreign audience, visible only to the dedicated client, logs in only on
  the listener with the allowlist binding, is refused with
  the generic `Authentication failed` under the default binding (IMAP no longer
  echoes introspection refusal reasons to unauthenticated clients), and that a
  token without the required scope is refused. The JMAP lane uses the
  Nauthilus token layout (resource in `aud`, no `resource` claim).
