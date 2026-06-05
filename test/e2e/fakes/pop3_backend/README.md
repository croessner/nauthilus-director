# Fake POP3 Backend

This package contains the deterministic POP3 backend used by the E2E guardrail
lane for public-socket POP3 and POP3S proof.

The fake listens on a public loopback socket, emits a bounded POP3 greeting and
CAPA response, accepts backend `USER`/`PASS` or `AUTH` handoff, and proxies
deterministic mailbox commands such as `STAT`, `LIST`, `UIDL`, `RETR`, `DELE`,
`RSET` and `QUIT`. Command status overrides allow tests to force backend
failures without relying on a real POP3 server.

Observations are intentionally redacted. They expose mechanism and command
classes plus boolean sentinel matches, but not plaintext passwords, bearer
tokens, SASL blobs, raw authorization headers, private keys, session secrets,
message numbers, UIDLs or message content.
