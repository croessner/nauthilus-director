# Docker Interoperability Lane

Docker interoperability is a future additive smoke lane, separate from the
deterministic fake-service guardrail lane run by `make e2e`. It may later be
wired through a target such as `make e2e-interop` or `make e2e-docker`, but it
must not replace fake-service coverage for edge cases, forced failures,
routing, active affinity, or secret-safe observability.

The lane should skip with a stable non-error message when Docker is not
available or when the matching production protocol entrypoint does not exist.
It must use pinned container images or digests so local and CI runs do not
drift silently.

Postfix-backed scenarios should use pinned `chrroessner/postfix` images when
Postfix behavior is part of the externally visible contract. IMAP, POP3, LMTP,
and ManageSieve backend interoperability should use pinned Dovecot
project-provided Docker assets once those production protocol entrypoints
exist.

The interoperability lane should validate real server behavior, packaging
assumptions, listener exposure, TLS settings, backend-auth settings, and the
same Redis or Redis-compatible service expectations as the guardrail lane when
active affinity or runtime overrides are part of a scenario.

Credentials, SASL bearer material, authorization headers, private keys, session
secrets, and raw protocol credential envelopes must not be printed in Docker
test logs.
