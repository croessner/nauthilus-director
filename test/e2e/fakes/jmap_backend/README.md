# Fake JMAP Backend

This package contains the deterministic JMAP backend used by the JMAP unit
tests and the E2E guardrail lane.

The fake listens on a public loopback socket, optionally requires a PROXY v1 or
v2 preface, terminates TLS and answers the JMAP session resource, the API,
upload, download (with HTTP ranges and the download security headers),
event-source and `/jmap/healthz` endpoints with fixed data. It never
interprets JMAP method calls.

Every non-health request is recorded with the backend connection number and the
client address the PROXY header named for that connection, so tests can prove
that two frontend clients never share a backend connection. Recorded
Authorization values stay in memory for equality assertions and are never
printed.
