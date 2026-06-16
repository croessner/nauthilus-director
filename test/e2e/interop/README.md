# Real Interoperability Lane

`make e2e-interop` is the real-server interoperability lane for IMAP regression
coverage, LMTP delivery proof, ManageSieve script-management proof and POP3
mailbox-read proof. It is separate from the deterministic fake-service
guardrail lane run by `make e2e`, and it must not replace
fake-service coverage for edge cases, forced failures, routing, active affinity,
runtime control, or secret-safe observability.

The lane should skip with a stable non-error message when Docker is not
available or when the matching production protocol entrypoint does not exist.
It must use pinned container images or digests so local and CI runs do not
drift silently.

Multi-protocol backend-node pinning belongs in this lane when the real-peer
topology exposes matching IMAP, ManageSieve and LMTP services for one backend
node. The proof must use public control APIs or `nauthilus-directorctl` to set
one `users backend-pin set --backend-node` pin, then use the operator mail-flow
shape: send a unique message through the public delivery/submission path, fetch
that same message through public IMAP and verify that delivery used the pinned
node's LMTP service while fetch used the pinned node's IMAP service. If Docker
or a required real protocol peer is unavailable, the lane must emit a stable
explicit skip reason and the closeout must report that skip instead of claiming
the interop proof passed.

Director-to-Nauthilus calls in this lane use a fake Nauthilus issuer that
publishes OIDC discovery and token endpoints, then requires `Authorization:
Bearer` on the Nauthilus-compatible HTTP authority endpoint. The fake authority
records discovery, token and backchannel requests so the interop lane proves
OIDC caller auth is primary and Basic Auth is not used.

The LMTP scenario runs `swaks` and `curl` from a short-lived pinned tool
container. `swaks` submits into the real Postfix SMTP listener, and
`curl --url imap...` verifies the delivered test message through the real
Dovecot IMAP backend.

The lane uses the Dovecot project-provided `dovecot/dovecot:2.4.4` image by
default and the pinned `chrroessner/postfix:3.11.1` image for the LMTP
submitting peer. Dovecot's own Docker documentation describes versioned image
names and the `-dev` test flavor; the script pins that tag instead of using
`latest`.

The current lane has five scenarios:

- a single production `nauthilus-director` process with fake Nauthilus
  OIDC-authenticated HTTP authority and one real Dovecot IMAP backend, proving
  frontend `LOGIN`, configured backend credential replay and post-auth proxy
  handoff through the public director listener
- three production `nauthilus-director` processes sharing one Redis-compatible
  Valkey state service and proxying to six real Dovecot IMAP backends: two
  backends with no configured `shard_tag`, two explicit `test_shard1` backends
  and two explicit `test_shard2` backends. This scenario proves deep health
  checks, Redis health-owner distribution across Director instances, active
  user affinity across Director instances, parallel new connections for one
  user, default-shard placement for untagged backends, route lookup with active
  affinity, `nauthilus-directorctl sessions kill`, `users kick`, `users move
  --strategy new_sessions_only`, hard backend drain and affinity clear through
  the public control API
- one production `nauthilus-director` process proxying LMTP to real Dovecot
  LMTPS backends and IMAP to the matching real Dovecot IMAP backends. A pinned
  Postfix container accepts a `swaks` SMTP submission and relays through
  Director to Dovecot LMTP. The same scenario verifies the delivered message
  with `curl --url imap...`, and also proves configured, backend-mediated
  `CHUNKING` capability exposure, BDAT delivery, same-backend recipient
  handling, different-backend temporary failure before message body, and a
  delivery-scoped LMTP hold influencing concurrent IMAP placement through
  public sockets and `nauthilus-directorctl`. The Director does not copy
  backend transcripts into frontend `LHLO`; listener config expresses the
  desired `CHUNKING` surface, and fresh health state for every LMTP backend in
  the pool must prove the capability before the frontend advertises it. Backend
  BDAT transport is still selected per chosen backend capability; the
  deterministic fake-service lane owns transcript-level edge coverage such as
  DATA-to-BDAT conversion, DATA fallback, backend BDAT rejection, LMTP SIZE
  forwarding and suppression, denied capability behavior and frontend-only
  PIPELINING without backend command batching.
- one production `nauthilus-director` process proxying public ManageSieve
  STARTTLS traffic to real Dovecot ManageSieve backends. The scenario proves
  frontend auth through fake Nauthilus OIDC caller auth, Dovecot master-user backend auth,
  `LISTSCRIPTS`, `PUTSCRIPT`, `SETACTIVE` and `GETSCRIPT` through the Director,
  safe route lookup for `protocol=sieve`, and same-account backend-node
  consistency between an active ManageSieve session and a later IMAP session
- one production `nauthilus-director` process proxying public POP3 STARTTLS
  traffic to a real Dovecot POP3 backend. The scenario seeds the real mailbox
  through Director LMTP, verifies the delivery through real Dovecot IMAP, then
  proves POP3 `CAPA`, `USER`/`PASS`, `STAT`, `LIST`, `UIDL`, `RETR` and `QUIT`
  through the Director plus same-account backend-node consistency between an
  active POP3 session and a later IMAP session. When the pinned Dovecot image
  does not expose a ready POP3 port, the POP3 scenario skips with a stable
  message while the existing IMAP, LMTP and ManageSieve lanes continue

The cluster scenario optionally confirms backend identity through `doveadm who`
inside the Dovecot containers when that command is available. The Director
state, Redis health-owner/state hashes and CLI output remain the required proof
because the lane must also work with pinned images that do not expose optional
Dovecot inspection commands.

If a future interop stack includes a real Nauthilus container, it must use the
current 3.0.0 beta line until that compatibility constraint is lifted.

Credentials, SASL bearer material, authorization headers, private keys, session
secrets, and raw protocol credential envelopes must not be printed in Docker
test logs.
