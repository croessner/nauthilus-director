# M8 SASL Bearer Identity Routing Follow-up

Status: completed for release `v1.1.2`.

This follow-up closes the bearer-routing decision that
`docs/ARCHITECTURE_ROADMAP.md` section 23 kept open after
`M8_SASL_BEARER_INTROSPECTION_FOLLOWUP.md`: IMAP, POP3 and ManageSieve logins
with `XOAUTH2` or `OAUTHBEARER` now route on the authority's directory facts
for the token account instead of on the token claims alone.

## Defect

RFC 7662 introspection proves which account a token belongs to (for example
through `account_claim: dovecot_account`). It does not carry the directory
routing facts that a password login receives from Nauthilus `Authenticate`,
above all the shard attribute named by
`director.routing.auth_attributes.shard_tag` (`mailShard` by default).

Until `v1.1.1` the IMAP, POP3 and ManageSieve listeners routed a bearer login
on the introspection result only. Without a shard attribute the shared
resolver chain (`auth_attribute`, then the rendezvous hash over every shard tag
in the backend registry) silently hashed the account. In a deployment with more
than one mail store a bearer login could therefore land on a store that does
not hold the mailbox; with master-user backend login and mailbox autocreation
on that store the user saw an empty or foreign mailbox. Active or retained
affinity from an earlier password login hid the defect until the binding
expired.

The JMAP listener was not affected: since `v1.1.0` it follows introspection
with an identity lookup.

## Decision

After every successful bearer introspection on an IMAP, POP3 or ManageSieve
listener, the director performs exactly one no-credential identity lookup for
the token account and routes with the merged result. The behaviour is not
configurable; it is the fixed default because there is no safe reason to route
a mailbox login on token claims alone.

The lookup is performed by `nauthilus.BindBearerIdentity`, a decorator around
the listener's bearer introspector that the listener manager installs for the
three mailbox protocols. Protocol handlers are unchanged: they keep calling
`Introspect` and map its outcome with their existing tempfail and rejection
responses.

### Lookup request

The lookup reuses the frontend request context of the introspection, so
Nauthilus sees the same facts it sees for a password login on that listener:

| Field | Value |
| --- | --- |
| `username` | the account from the token (`account_claim` or the default claim chain) |
| `protocol` | the listener protocol: `imap`, `pop3` or `sieve` |
| `method` | `recipient_lookup` (the value JMAP and LMTP recipient lookups send) |
| client and local address, IMAP `ID` client ID, TLS facts | copied from the frontend session |
| listener `authority_context` headers or gRPC metadata | applied by the authority client as for every call |

HTTP authorities receive `POST /api/v1/auth/json?mode=no-auth`, gRPC
authorities `AuthService.LookupIdentity`. Nauthilus selects its backend search
by `protocol`, so the directory configuration that already serves password
logins for that protocol serves the lookup as well.

### Result handling

| Lookup outcome | Login outcome |
| --- | --- |
| Authenticated, same account (both sides normalized with `authbinding.CanonicalAccount`) | Success. Lookup attributes replace token claims of the same name; the shard and tenant routing attributes (`director.routing.auth_attributes`) come only from the lookup, token claims of those names are dropped; other token-only claims stay. Account and session ID stay those of the token. |
| Authenticated, different account | Refused as an authentication failure (reason `bearer_account_mismatch`). The token account is authoritative for identity. |
| Authenticated without account | Temporary failure (`malformed_response`). |
| Rejected (account unknown to the directory) | Refused as an authentication failure (reason `bearer_identity_rejected`). |
| Temporary failure, transport error or timeout | Temporary failure. |
| Introspection rejected or failed | Unchanged; no lookup is sent. |

Refusals carry no authority status text to the client. Temporary failures use
each protocol's existing bearer tempfail mapping: IMAP `NO [UNAVAILABLE]`,
POP3 `-ERR Authentication service temporarily unavailable`, ManageSieve
`NO (TRYLATER)`. No failure path reaches the routing resolver, so a lookup
failure can never fall back to the hash.

When the lookup succeeds without the shard attribute, routing is unchanged,
even if the token carries a claim of that name: the resolver chain hashes exactly as it
does for a password login whose `Authenticate` response lacks the attribute.
The lookup observation reports this case with reason class
`bearer_shard_missing` so operators can find accounts that are routed by hash.

Password logins are not changed. They route on the `Authenticate` attributes
and also fall back to the rendezvous hash when Nauthilus omits the shard
attribute; a deployment that must never hash needs complete shard attributes
in the directory.

### Cost

One additional authority round trip per successful bearer login, sent over
the configured authority transport. Introspection and lookup share the
listener's `runtime.timeouts.auth` budget. No token, introspection result or
lookup result is cached.

### Startup contract

A listener of protocol `imap`, `pop3` or `sieve` that enables `xoauth2` or
`oauthbearer` requires an authority client that implements identity lookup;
both the HTTP and the gRPC clients do. Startup fails with
`sasl bearer identity lookup unavailable` otherwise. LMTP peer bearer auth
authenticates the submitter, not a mailbox, and keeps the plain introspector.
JMAP keeps its own request authenticator, which already performs the lookup.

### Observability

Each lookup emits one `nauthilus.auth` event and increments the Nauthilus auth
counter and histogram with `mechanism=recipient_lookup`, the authority
transport, the listener protocol, `result` and one of the reason classes `ok`,
`bearer_shard_missing`, `bearer_account_mismatch`, `bearer_identity_rejected`,
`temporary_failure`, `transport`, `timeout` or `malformed_response`. The log
field `operation` is `bearer_identity`. Accounts, tokens and claim values are
never logged or used as labels.

### Route lookup

Route lookup stays a director-only diagnostic that never calls Nauthilus. For a
bearer user it explains the route from caller-supplied attributes; operators
pass the directory's shard attribute to see the route a bearer login takes.

## Differences to JMAP

JMAP performs the same lookup inside its request authenticator. The account
rule is aligned in `v1.1.2`: a lookup naming another canonical account than the
token (case-insensitive) refuses the request with 401 and reason class
`bearer_account_mismatch`, an unknown account answers 401 and a lookup failure
503; JMAP never adopts the lookup's account. The remaining difference is
deliberate: JMAP refuses a missing shard attribute with 403 by default
(`jmap.routing.missing_shard`) instead of hashing. Evidence:
`TestBearerLookupMustConfirmTokenAccount` and the alias-token step of
`TestServerBinaryPublicJMAPProxyFlow`.

## Evidence

- Unit: `internal/nauthilus/bearer_identity_test.go` (lookup input, attribute
  merge, mismatch, rejection, tempfail, missing account, shard-missing signal,
  no lookup for refused tokens).
- Unit per protocol: `internal/protocol/{imap,pop3,sieve}/bearer_routing_test.go`
  run the production resolver chain and prove that an account whose hash
  lands on one shard routes to the lookup shard, and that lookup failures and
  refusals never reach routing.
- Listener wiring: `internal/listener/bearer_identity_test.go`.
- E2E with the real binary and the fake authority:
  `TestServerBinaryBearerLoginsRouteOnIdentityLookupShard` picks accounts whose
  public route lookup reports the hash choice on shard A, gives them shard B in
  the directory, and proves IMAP, POP3 and ManageSieve bearer sessions reach
  the shard B backends while a failed lookup tempfails without a backend
  connection. The IMAP bearer lanes and the POP3 gRPC lane assert the lookup
  protocol, method and listener context metadata.
