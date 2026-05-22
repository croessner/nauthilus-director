# Fake IMAP Backend

This scaffold is reserved for the deterministic IMAP backend used by the E2E
guardrail lane once the production IMAP listener exists.

The fake should listen on a public test socket and expose protocol-level
observations for greeting, STARTTLS, backend authentication, selected account,
proxy transition, and connection close behavior. It should be able to force
slow greetings, authentication rejection, connection drops, and backend
maintenance-style failures so fake-service E2E keeps edge-case coverage.

Logs and observations must not include plaintext passwords, bearer tokens, SASL
blobs, raw authorization headers, private keys, or session secrets.

