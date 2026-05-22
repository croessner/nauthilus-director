# Fake POP3 Backend

This scaffold is reserved for the deterministic POP3 backend used by the E2E
guardrail lane once the production POP3 listener exists.

The fake should listen on a public test socket and expose protocol-level
observations for greeting, STLS, USER/PASS or SASL authentication, selected
account, proxy transition, and connection close behavior. It should be able to
force authentication rejection, slow responses, and backend connection failures
without relying on a real POP3 server.

Logs and observations must not include plaintext passwords, bearer tokens, SASL
blobs, raw authorization headers, private keys, or session secrets.

