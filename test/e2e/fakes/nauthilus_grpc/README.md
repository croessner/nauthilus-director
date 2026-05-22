# Fake Nauthilus gRPC Authority

This scaffold is reserved for the deterministic gRPC authority used by the E2E
guardrail lane.

The fake must listen on a public test socket and model the
`nauthilus.auth.v1.AuthService` methods needed by the director: authenticate,
identity lookup, and list-accounts. It should return the same logical account
and routing attributes as the HTTP fake so E2E scenarios can prove transport
selection without changing director routing semantics.

Request observations must be secret-safe. The fake may record method names,
mechanisms, protocol names, status classes, and non-secret routing attributes,
but it must not log passwords, bearer tokens, SASL blobs, raw metadata secrets,
private keys, or session secrets.

