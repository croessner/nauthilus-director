# Fake LMTP Backend

This scaffold is reserved for the deterministic LMTP backend used by the E2E
guardrail lane once the production LMTP listener exists.

The fake should listen on a public test socket and expose protocol-level
observations for greeting, LHLO, STARTTLS, authenticated peer state where
configured, recipient acceptance, per-recipient status, DATA forwarding, and
connection close behavior. It should support deterministic recipient routing
tests where one transaction must stay on a single selected backend.

Logs and observations must not include recipient bodies, plaintext passwords,
bearer tokens, SASL blobs, raw authorization headers, private keys, or session
secrets.

