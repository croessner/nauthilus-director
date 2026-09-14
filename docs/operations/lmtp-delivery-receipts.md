# Native LMTP delivery receipts

A delivery observer may need the native Dovecot session from the final LMTP
reply to bind delivery to protected Sieve events. Generic `Message accepted`
responses confirm acceptance but cannot supply this provenance.

Enable `director.listeners.<name>.lmtp.preserve_backend_delivery_receipt: true`
only for a trusted internal listener whose clients require this receipt. The
default is false. The Director accepts exactly one `250 2.0.0` final response
with a 16–128 character native session token followed by `Saved`. It returns
the original token and `Saved`, removing any optional recipient prefix. No
arbitrary backend prose or failed-delivery text is forwarded. Unknown receipt
formats remain successful sanitized replies; callers requiring a native receipt
must treat them as unconfirmed rather than inventing a session or redelivering
already accepted mail.

This applies to final DATA and BDAT delivery results in recipient order, never
to greeting, RCPT or intermediate BDAT replies. Routing, affinity, backend TLS,
and authentication remain unchanged. Native tokens are not logged or exported
as metric labels. The backend pool must provide the extensions used by clients;
in particular 8BITMIME requires fresh capability proof for every pool member.
The listener refreshes that proof on every LHLO, including after startup health
becomes available and after a backend loses an extension. Missing or failed
proof suppresses the extension.

Validation must cover real delivery and Sieve action correlation through the
load balancer, not just a 220 greeting or 250 RCPT response. Preserve the observer
and its queue-byte/session checks. Verify local copies and external actions
before retiring any direct-backend path.
