# Real IMAP Interoperability Lane

`make e2e-interop` is the real-server IMAP interoperability lane. It is
separate from the deterministic fake-service guardrail lane run by `make e2e`,
and it must not replace fake-service coverage for edge cases, forced failures,
routing, active affinity, runtime control, or secret-safe observability.

The lane should skip with a stable non-error message when Docker is not
available or when the matching production protocol entrypoint does not exist.
It must use pinned container images or digests so local and CI runs do not
drift silently.

The IMAP lane uses the Dovecot project-provided `dovecot/dovecot:2.4.3-dev`
image by default. Dovecot's own Docker documentation describes versioned image
names and the `-dev` test flavor; the script pins that tag instead of using
`latest`.

The current lane has two scenarios:

- a single production `nauthilus-director` process with fake Nauthilus
  authentication and one real Dovecot IMAP backend, proving frontend `LOGIN`,
  configured backend credential replay and post-auth proxy handoff through the
  public director listener
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
