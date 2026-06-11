# Fake LMTP Backend

This package contains the deterministic LMTP backend used by the E2E guardrail
lane for public-socket LMTP and LMTPS proof.

The fake listens on a public test socket and exposes protocol-level
observations for greeting, LHLO, STARTTLS, backend authentication commands,
recipient acceptance, per-recipient status, DATA forwarding, BDAT forwarding,
BDAT chunk commands and connection close behavior. It supports deterministic
recipient routing tests where one transaction must stay on a single selected
backend, including mixed same-backend final outcomes, incomplete final status
sets, rejected non-final BDAT chunks and backend capability variants for
`CHUNKING`, `8BITMIME` and `SIZE` mediation. The fake records protocol
transcripts, backend `MAIL FROM` parameters and payload mode, and can detect
whether frontend `PIPELINING` accidentally caused backend command batching. It
does not queue, retry, bounce or persist message bodies.

Logs and observations must not include recipient bodies, plaintext passwords,
bearer tokens, SASL blobs, raw authorization headers, private keys, or session
secrets.
