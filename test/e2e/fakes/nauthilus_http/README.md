# Fake Nauthilus HTTP Authority

This scaffold is reserved for the deterministic HTTP authority used by the E2E
guardrail lane.

The fake must listen on a public test socket and model the structured
`/api/v1/auth/json` boundary closely enough to assert that the director sends
`protocol`, selects HTTP through `auth.authorities.<name>.transport`, and omits
director-owned fields such as `service`, `listener`, `session_id`,
`backend_identifier`, and `routing_hint`.

Request observations must be secret-safe. The fake may count requests and
record mechanism names, protocol names, status classes, and selected test
attributes, but it must not log passwords, bearer tokens, SASL blobs, raw
authorization headers, private keys, or session secrets.

