# SASL EXTERNAL Client Certificate Authentication

Status: implemented on `features`; release publication and manifest rollout are pending.

This specification defines certificate-backed SASL `EXTERNAL` authentication
for IMAP, POP3, and ManageSieve listeners. The Director verifies the TLS client
certificate, derives an authentication identity from its `rfc822Name` subject
alternative name, asks the configured Nauthilus authority for the canonical
account, and uses backend master-user authentication because no reusable user
credential exists.

An S/MIME certificate is usable only when its certificate profile is also
valid for TLS client authentication. A certificate restricted to the
`emailProtection` extended key usage does not satisfy the TLS client-certificate
boundary; the presented leaf must be accepted for `clientAuth` by Go's TLS
verification against the configured client CA.

## Source Documents

This specification is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/specs/implementation/M7_POP3_PROXY_SPEC.md`
- `docs/specs/implementation/M8_PRODUCTION_HARDENING_SPEC.md`
- `docs/specs/implementation/M8_LISTENER_AUTHORITY_CONTEXT_FOLLOWUP.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/config/metadata.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/man/nauthilus-director.yaml.5`
- `test/e2e/README.md`
- `test/e2e/interop/README.md`
- RFC 4422 and the protocol-specific SASL profiles
- `Makefile`

If this specification conflicts with a security or architecture rule, the
stricter rule wins and the durable documentation must be reconciled before
implementation continues.

## Goal

Add a shared, fail-closed SASL `EXTERNAL` boundary with these properties:

- `EXTERNAL` is configured per listener and authority and is advertised only
  while TLS is active with a successfully verified client certificate.
- The external authentication identity comes from exactly one non-empty leaf
  certificate `rfc822Name` SAN. Common Name is never an authentication
  fallback.
- The full verified TLS context, including issuer, serial number, SHA-256
  fingerprint, and subject data, is sent to Nauthilus through its existing
  credential-free identity lookup boundary.
- Nauthilus resolves the certificate identity to the canonical account and
  routing attributes. The Director never treats the presented email address as
  the canonical backend account without that authority decision.
- An optional SASL authorization identity is accepted only when policy permits
  it and Nauthilus resolves it to the same canonical account as the certificate
  identity. Ambiguity or mismatch fails closed.
- Backend authentication uses the configured master-user path with the
  canonical account. Credential replay is never used for `EXTERNAL`.

## Configuration Contract

Authority policy is explicit and disabled by default:

```yaml
auth:
  authorities:
    default:
      mechanisms:
        external:
          enabled: false
          identity_source: san_email
          allow_authorization_id: false
```

Listener activation uses the existing protocol mechanism lists and TLS trust
surface:

```yaml
director:
  listeners:
    imaps:
      tls:
        mode: implicit
        client_ca: /etc/nauthilus-director/mail-client-ca.pem
        require_client_cert: false
      imap:
        auth_mechanisms: [plain, external]
        capabilities: [IMAP4rev1, ID, SASL-IR, AUTH=PLAIN, AUTH=EXTERNAL]
```

The same `external` mechanism token is valid in POP3 and ManageSieve listener
mechanism lists. `client_ca` is mandatory whenever one of those listeners
enables `external`. `require_client_cert` may remain false so password or bearer
clients can share the listener; clients without a verified certificate simply
do not see or use `EXTERNAL`.

Validation rules:

- `identity_source` accepts only `san_email`.
- A listener may configure `external` only when its selected authority enables
  the external mechanism policy.
- The listener TLS mode must be `implicit` or `starttls` and `tls.client_ca`
  must be non-empty.
- Every backend reachable through an `EXTERNAL`-capable IMAP, POP3, or
  ManageSieve listener must use `auth.mode: master_user` with complete
  master-user material.
- `credential_replay` is not an alternative for `EXTERNAL` because the
  mechanism provides no user secret.
- Existing listeners that do not configure `external` retain their current
  behavior.

## Certificate and Authorization Identity Semantics

The shared certificate identity resolver must:

1. Require active TLS and an available `tls.ConnectionState`.
2. Require at least one verified chain and a non-nil leaf peer certificate.
3. Read only `leaf.EmailAddresses`, trim values, remove exact duplicates, and
   require exactly one remaining identity.
4. Build a Nauthilus `LookupIdentity` request with the SAN email as `username`,
   `method: external`, the current mail protocol, and the existing bounded TLS
   request context.
5. Require an authenticated Nauthilus result with a non-empty canonical
   account.
6. Treat an empty authorization identity, or one exactly equal to the
   certificate identity, as the certificate identity.
7. Reject a distinct authorization identity unless
   `allow_authorization_id: true`.
8. When distinct authorization identities are allowed, resolve the requested
   identity through a second Nauthilus identity lookup and require both lookups
   to return exactly the same canonical account.

The resolver must not lower-case, rewrite, or infer identities from Common
Name, DNS SAN, URI SAN, Subject DN, issuer text, serial number, or fingerprint.
Those certificate facts remain policy context for Nauthilus, not local account
mapping fallbacks.

The Director delegates key-usage and extended-key-usage enforcement to the TLS
handshake. It does not reinterpret an email-signing-only certificate as a TLS
client certificate.

## Protocol Semantics

IMAP:

- Advertise `AUTH=EXTERNAL` only after implicit TLS or STARTTLS has completed
  and the current client certificate is verified.
- Accept SASL-IR and continuation forms. `=` represents an empty authorization
  identity.
- Reject `AUTHENTICATE EXTERNAL` before verified TLS without contacting
  Nauthilus.

POP3:

- Include `EXTERNAL` in the `SASL` CAPA value only after verified TLS.
- Accept initial-response and continuation forms with the same bounded parser.
- Reject unavailable or mismatched external identity with the existing bounded
  authentication failure response.

ManageSieve:

- Include `EXTERNAL` in the `SASL` capability value only after verified TLS.
- Accept quoted initial-response and continuation forms through the existing
  parser boundary.
- Preserve the existing `ENCRYPT-NEEDED` behavior before TLS and return bounded
  authentication failures after TLS.

LMTP keeps its existing mTLS peer-auth behavior unchanged. This specification
does not add SASL `EXTERNAL` to LMTP or change recipient identity lookup.

## Backend Authentication

Successful frontend certificate authentication produces a canonical Nauthilus
account but no credential. IMAP, POP3, and ManageSieve therefore pass that
canonical account to their existing master-user backend authentication path.
The external frontend identity and optional authorization identity must never
be replayed as the backend username unless they are the canonical account
returned by Nauthilus.

Runtime backend selection remains Director-owned. Nauthilus supplies identity
and routing attributes only and never selects a concrete backend.

## Observability and Secret Safety

- Use the bounded mechanism label `external` and existing result/reason
  classes.
- Do not add SAN email, canonical account, Subject DN, issuer, serial,
  fingerprint, authzid, session ID, client IP, or raw certificate bytes as
  metric labels.
- Existing TLS fields may be forwarded to Nauthilus but must not be emitted as
  raw structured log or trace values by this feature.
- Errors distinguish unavailable certificate, ambiguous certificate identity,
  denied authorization identity, authority rejection, and temporary authority
  failure only through bounded reason classes.

## Delivery Shape

Implementation is split into bounded prompt packages:

1. Typed config, defaults, normalization, and fail-closed validation.
2. Shared SASL payload and verified-certificate identity service.
3. IMAP, POP3, and ManageSieve protocol integration.
4. Canonical-account backend master-user enforcement.
5. Public-socket E2E, generated docs, observability, and final review.
6. Release-candidate publication and versioned-manifest rollout after all
   repository and release guardrails pass.

## Required Proof

Focused tests must cover:

- empty and explicit authorization identities;
- a single verified `rfc822Name` SAN;
- no certificate, an unverified chain, no email SAN, and multiple email SANs;
- a distinct authzid with policy disabled;
- a distinct authzid resolving to the same canonical account when enabled;
- a distinct authzid resolving to another or no account;
- no `EXTERNAL` advertisement before TLS or with an unverified certificate;
- successful and rejected flows for IMAP, POP3, and ManageSieve;
- fail-closed startup for an external listener without client CA, enabled
  authority policy, identity lookup, or master-user backends;
- LMTP regression coverage.

Public E2E must generate an ephemeral CA, server certificate, and client
certificates with `clientAuth` EKU plus email SANs. It must start real Director
and fake authority/backend processes, use public protocol sockets, and prove
success plus the negative cases practical at the socket boundary. Test private
keys and certificates stay inside the temporary E2E directory.

Final validation requires `make generate-docs`, `make check-docs`, focused
tests, `make test`, `make race`, `make e2e`, `make build-check`,
`make guardrails`, `make release-guardrails`, `git diff --check`, and a clean
release checkout.

## Release and Rollout Contract

Release publication is permitted only after all required checks pass from a
clean checkout whose `HEAD` is the release commit. The next release candidate
must be derived from repository tags and release metadata, not guessed.

The Kubernetes deployment must be changed only through the authoritative,
versioned manifest repository. The release image must come from the GitHub
Actions publication under `ghcr.io/croessner/nauthilus-director`, be pinned by
digest, and flow through the manifest repository's documented validation,
shadow, production, and smoke targets. Direct `kubectl` image patching or
ad-hoc config mutation is forbidden. The previous manifest commit and digest
form the rollback boundary.

## Acceptance Criteria

- IMAP, POP3, and ManageSieve implement standards-shaped SASL `EXTERNAL`.
- `EXTERNAL` is usable and advertised only with a verified client certificate.
- Certificate identity uses one `rfc822Name` SAN and never falls back to CN.
- Nauthilus resolves canonical accounts and optional authzid equivalence.
- Authorization identity mismatch and all ambiguous states fail closed.
- Backend login uses canonical-account master-user auth without credential
  replay.
- Configuration, generated references, manpage, observability, and public E2E
  match the behavior.
- LMTP behavior does not regress.
- Release and rollout, if performed, use guarded publication and versioned
  manifests with a proven rollback boundary.

## Completion Evidence

- The durable specification was written before implementation, and the bounded
  prompt package remains under the ignored `temp/` scratch boundary.
- Config validation covers IMAP, POP3, and ManageSieve authority policy, TLS
  client CA, identity source, identity-lookup availability, and master-user
  backend requirements.
- Shared tests cover empty and explicit authzid input, verified and unverified
  certificates, missing and ambiguous email SANs, canonical account binding,
  authorization identity equivalence, and temporary authority failures.
- Protocol tests prove state-dependent advertisement for IMAP, POP3, and
  ManageSieve. POP3 and ManageSieve tests prove canonical-account master-user
  backend authentication; the public-socket E2E proves the full IMAP path from
  verified client certificate through Nauthilus lookup, placement, backend
  authentication, and proxy traffic.
- Generated configuration references, operator security guidance, failure-mode
  guidance, and the E2E inventory describe the implemented behavior.
- `make guardrails` and `git diff --check` pass on `features`. Release
  guardrails, tag publication, immutable image verification, and the separate
  versioned-manifest rollout remain release tasks.
