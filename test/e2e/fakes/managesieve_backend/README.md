# Fake ManageSieve Backend

This scaffold is reserved for the deterministic ManageSieve backend used by
the E2E guardrail lane once the production ManageSieve listener exists.

The fake should listen on a public test socket and expose protocol-level
observations for greeting, capability exchange, STARTTLS, backend
authentication, selected account, proxy transition, and connection close
behavior. It should be able to force backend failures and slow responses so
edge cases remain deterministic.

Logs and observations must not include Sieve script contents, script names,
plaintext passwords, bearer tokens, SASL blobs, raw authorization headers,
private keys, or session secrets.

