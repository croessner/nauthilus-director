# Real IMAP Interoperability Lane

`make e2e-interop` is the M1 real-server interoperability lane. It is separate
from the deterministic fake-service guardrail lane run by `make e2e`, and it
must not replace fake-service coverage for edge cases, forced failures,
routing, active affinity, or secret-safe observability.

The lane should skip with a stable non-error message when Docker is not
available or when the matching production protocol entrypoint does not exist.
It must use pinned container images or digests so local and CI runs do not
drift silently.

The M1 IMAP lane uses the Dovecot project-provided
`dovecot/dovecot:2.4.3-dev` image by default. Dovecot's own Docker
documentation describes versioned image names and the `-dev` test flavor; the
script pins that tag instead of using `latest`.

The current scenario runs the director with fake Nauthilus authentication and a
real Dovecot IMAP backend. It verifies one successful frontend IMAP `LOGIN`,
configured backend credential replay and post-auth proxy handoff through the
public director listener. If a future interop stack includes a real Nauthilus
container, it must use the current 3.0.0 beta line until that compatibility
constraint is lifted.

Credentials, SASL bearer material, authorization headers, private keys, session
secrets, and raw protocol credential envelopes must not be printed in Docker
test logs.
