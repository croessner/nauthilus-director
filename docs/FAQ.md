# Frequently Asked Questions

This FAQ answers operator-facing questions that combine multiple runtime
controls. It is intentionally practical: commands mutate only runtime state
unless the text explicitly calls out an external system.

## Table of Contents

- [What should I check first when a Director instance looks wrong?](#what-should-i-check-first-when-a-director-instance-looks-wrong)
- [How do I explain why a user would route to a shard or backend?](#how-do-i-explain-why-a-user-would-route-to-a-shard-or-backend)
- [How do I move a user from one shard to another?](#how-do-i-move-a-user-from-one-shard-to-another)
- [When do I add a backend pin during a migration?](#when-do-i-add-a-backend-pin-during-a-migration)
- [What does each user migration command do?](#what-does-each-user-migration-command-do)
- [Which move strategy should I use?](#which-move-strategy-should-i-use)
- [What if the hold expires before the migration is complete?](#what-if-the-hold-expires-before-the-migration-is-complete)
- [How do I test a new backend before general traffic reaches it?](#how-do-i-test-a-new-backend-before-general-traffic-reaches-it)
- [How do I take one backend out for planned maintenance?](#how-do-i-take-one-backend-out-for-planned-maintenance)
- [How do I drain a frontend listener during a deploy?](#how-do-i-drain-a-frontend-listener-during-a-deploy)
- [How do I close one bad connection without kicking the whole user?](#how-do-i-close-one-bad-connection-without-kicking-the-whole-user)
- [How do I list runtime state without accidentally walking everything?](#how-do-i-list-runtime-state-without-accidentally-walking-everything)
- [How do I inspect configuration without leaking secrets?](#how-do-i-inspect-configuration-without-leaking-secrets)
- [How do I clean up after an interrupted operator workflow?](#how-do-i-clean-up-after-an-interrupted-operator-workflow)

## What should I check first when a Director instance looks wrong?

Start with the addressed control API and the runtime summary. These commands are
cheap and do not enumerate every runtime object:

```bash
CTL='nauthilus-directorctl --address http://director-control:9090'

$CTL status
$CTL runtime summary
$CTL backends list
$CTL listeners list
```

Use `status` to distinguish process health and readiness from routing state.
Use `runtime summary` for aggregate session and repair counters. Then narrow the
question to a backend, listener, user or session:

```bash
$CTL backends show mailstore-a-imap
$CTL listeners show imap
$CTL users show alice@example.org
$CTL users sessions alice@example.org
```

## How do I explain why a user would route to a shard or backend?

Use route lookup before changing runtime state. It is the safest first
diagnostic because it does not authenticate credentials, create sessions,
refresh leases, connect to a backend or mutate Redis:

```bash
$CTL route lookup \
  --protocol imap \
  --user alice@example.org \
  --backend-pool imap-default \
  --include-affinity
```

For delivery placement, diagnose the recipient path:

```bash
$CTL route lookup \
  --protocol lmtp \
  --recipient alice@example.org \
  --backend-pool lmtp-default \
  --include-affinity
```

If the answer is surprising, inspect the runtime facts that can affect
placement:

```bash
$CTL users affinity show alice@example.org
$CTL users backend-pin show alice@example.org
$CTL users hold show alice@example.org
$CTL users sessions alice@example.org
```

Remember the boundary: route lookup explains placement; it is not an auth test
and not a mailbox login.

## How do I move a user from one shard to another?

Use a bounded placement hold to close the reconnect race, close active user
sessions, move the mailbox data outside the director, then set the director
runtime shard target before releasing the hold.

Example values:

```bash
CTL='nauthilus-directorctl --address http://director-control:9090'
USER='alice@example.org'
OLD_SHARD='mailstore-a'
NEW_SHARD='mailstore-b'
TARGET_BACKEND='mailstore-b-imap'
```

Inspect the current runtime state before changing anything:

```bash
$CTL users show "$USER"
$CTL users sessions "$USER"
$CTL users affinity show "$USER"
$CTL users backend-pin show "$USER"
$CTL route lookup --protocol imap --user "$USER" --backend-pool imap-default
```

For a large mailbox, pre-copy most data before the cutover window. This step is
owned by the mailbox platform, not by `nauthilus-director`:

```bash
mailbox-sync --user "$USER" --from "$OLD_SHARD" --to "$NEW_SHARD" --mode initial
mailbox-verify --user "$USER" --from "$OLD_SHARD" --to "$NEW_SHARD"
```

Start the cutover by holding new placements for this user:

```bash
$CTL users hold set "$USER" \
  --duration 15m \
  --reason "migrate alice from mailstore-a to mailstore-b"
```

The hold is only a placement gate. It does not choose a shard, choose a backend,
kill sessions, clear affinity or rewrite configuration.

Ask active sessions to close through the controlled runtime path:

```bash
$CTL users kick "$USER" \
  --reason "begin shard migration cutover"
```

Wait until the user has no active sessions:

```bash
while $CTL users sessions "$USER" | grep -q '^session_id='; do
  sleep 2
done
```

Run the final mailbox delta copy while placement is still held:

```bash
mailbox-freeze --user "$USER" --shard "$OLD_SHARD"
mailbox-sync --user "$USER" --from "$OLD_SHARD" --to "$NEW_SHARD" --mode delta
mailbox-verify --user "$USER" --from "$OLD_SHARD" --to "$NEW_SHARD"
```

Update the authoritative routing source for the user, for example the directory
attribute or identity database that Nauthilus exposes as the shard fact:

```bash
identity-set-shard --user "$USER" --shard "$NEW_SHARD"
```

Then set the director runtime move target:

```bash
$CTL users move "$USER" \
  --to-shard "$NEW_SHARD" \
  --strategy kick_existing \
  --reason "mailbox data is ready on mailstore-b"
```

Release the placement hold:

```bash
$CTL users hold clear "$USER" \
  --reason "migration complete"
```

Waiting and future sessions re-check runtime state after the hold clears and
place on the new shard.

Verify the result:

```bash
$CTL route lookup --protocol imap --user "$USER" --backend-pool imap-default
$CTL users affinity show "$USER"
$CTL users sessions "$USER"
```

Do not use `users backend-pin` as the cross-shard move primitive. A backend pin
is same-shard only. Use `users move --to-shard` for the shard transition.

## When do I add a backend pin during a migration?

Add a backend pin only when the user must land on a concrete backend inside the
already selected shard. This is useful for controlled commissioning, repair or
validation of one backend.

For a shard migration, first move the user to the new shard. Then, while the
hold is still active, optionally pin the user to a backend in that same shard:

```bash
$CTL users backend-pin set "$USER" \
  --backend "$TARGET_BACKEND" \
  --strategy new_sessions_only \
  --reason "pin alice to validated target backend during cutover"
```

The target backend must belong to the selected shard for the relevant protocol
and backend pool. If the user's selected shard is still `mailstore-a`, a pin to
`mailstore-b-imap` is not a move. It remains diagnostic and does not select the
cross-shard backend.

Clear temporary commissioning pins explicitly when they are no longer needed:

```bash
$CTL users backend-pin clear "$USER" \
  --reason "target backend validation complete"
```

## What does each user migration command do?

- `users hold set`: blocks new placement for one user for a bounded duration.
- `users kick`: asks active sessions for that user to close through heartbeat
  observed runtime control.
- `users move`: changes the runtime shard target for future placement.
- `users backend-pin`: optionally constrains placement to one concrete backend
  after the selected shard already matches that backend.
- `users hold clear`: removes only the placement hold and wakes waiting
  placement attempts.
- `users affinity clear`: clears inactive affinity and pending override state.
  Use it only after the durable routing source is already correct and no active
  sessions remain.

## Which move strategy should I use?

- `new_sessions_only` preserves active sessions and applies the target after
  active affinity drains.
- `kick_existing` marks active sessions for controlled closure and makes new
  sessions use the target once the control generation is active.
- `drain_existing` can create an audited temporary split where new sessions use
  the target while old sessions drain on the previous shard.

For a clean mailbox cutover, `hold set`, `kick`, final sync, `move
--strategy kick_existing`, and `hold clear` is the normal sequence.

## What if the hold expires before the migration is complete?

The hold is deliberately bounded. If it expires before the move or backend pin
is ready, waiting and future sessions continue through normal placement. Choose
a duration that covers the planned cutover window. If the operation is still in
progress, set a fresh audited hold before the old one expires.

## How do I test a new backend before general traffic reaches it?

Keep the backend out of normal weighted placement, then use a same-shard
backend pin for one controlled test user. A backend pin bypasses only the
weight-zero placement exclusion for the pinned backend; health, maintenance,
runtime out, drain, connection limits and protocol or pool mismatches still
fail closed.

```bash
BACKEND='mailstore-c-imap'
USER='canary@example.org'

$CTL backends weight "$BACKEND" \
  --weight 0 \
  --reason "commission backend without general placement"

$CTL users backend-pin set "$USER" \
  --backend "$BACKEND" \
  --strategy kick_existing \
  --reason "canary test on commissioned backend"
```

Verify with route lookup and a real protocol login or delivery test:

```bash
$CTL route lookup \
  --protocol imap \
  --user "$USER" \
  --backend-pool imap-default \
  --include-affinity

$CTL users sessions "$USER"
$CTL backends show "$BACKEND"
```

When the canary is complete, either clear the pin and restore normal weight, or
leave the backend at weight `0` until a later rollout step:

```bash
$CTL users backend-pin clear "$USER" \
  --reason "canary backend test complete"

$CTL backends weight "$BACKEND" \
  --weight 100 \
  --reason "enable general placement"
```

## How do I take one backend out for planned maintenance?

Choose the least disruptive control that matches the maintenance goal:

- `backends out`: exclude the backend from new placement without implying
  session termination.
- `backends maintenance enable --mode soft`: mark soft maintenance, excluding
  new initial placements while preserving existing sessions and active pins by
  default.
- `backends drain --mode soft`: start an audited drain while active sessions
  close naturally.
- `backends drain --mode hard --grace-seconds <n>`: request active-session
  closure after an explicit grace period.

Typical soft maintenance:

```bash
BACKEND='mailstore-a-imap'

$CTL backends maintenance enable "$BACKEND" \
  --mode soft \
  --reason "planned storage maintenance"

$CTL sessions list --backend "$BACKEND" --limit 100
$CTL backends show "$BACKEND"
```

If the backend must stop receiving any new placement immediately:

```bash
$CTL backends out "$BACKEND" \
  --reason "remove backend from placement during maintenance"
```

For disruptive work after a declared grace period:

```bash
$CTL backends drain "$BACKEND" \
  --mode hard \
  --grace-seconds 60 \
  --reason "storage maintenance requires disconnect after grace"
```

Bring the backend back explicitly:

```bash
$CTL backends maintenance disable "$BACKEND" \
  --reason "maintenance complete"

$CTL backends in "$BACKEND" \
  --reason "backend ready for placement"
```

Use `backends runtime clear` only when the intent is to remove runtime
overrides for that backend. It is broader than disabling one maintenance flag.

## How do I drain a frontend listener during a deploy?

Listener controls are process-local in v1. They affect only the Director
instance addressed by `--address`, so repeat the command for each process behind
the external load balancer.

For a graceful local listener drain:

```bash
$CTL listeners drain imap \
  --mode soft \
  --reason "deploy director instance"
```

Soft drain closes the accept socket for new frontend connections and leaves
active local sessions running. For a hard drain, specify an explicit grace:

```bash
$CTL listeners drain imap \
  --mode hard \
  --grace-seconds 30 \
  --reason "stop director instance after grace"
```

After the instance is updated and ready, resume the listener from the current
typed configuration snapshot:

```bash
$CTL listeners resume imap \
  --reason "director instance back in service"
```

## How do I close one bad connection without kicking the whole user?

Use a session-scoped kill when one session is the problem. Use `users kick` only
when every active session for the user should reconnect or close.

Find the session:

```bash
$CTL users sessions alice@example.org
$CTL sessions show session-123
```

Kill only that session:

```bash
$CTL sessions kill session-123 \
  --reason "stuck client session"
```

Kick all sessions for one user:

```bash
$CTL users kick alice@example.org \
  --reason "force reconnect after account maintenance"
```

Both paths are runtime controls. They do not move mailbox data and do not edit
configuration.

## How do I list runtime state without accidentally walking everything?

Prefer bounded pages during incident triage:

```bash
$CTL sessions list --protocol imap --limit 100
$CTL sessions list --backend mailstore-a-imap --limit 100
$CTL users list --limit 100
```

If the output shows `more=true`, continue with the returned `next_cursor`:

```bash
$CTL sessions list --cursor '<next_cursor_from_previous_page>' --limit 100
```

Use `--all` only for deliberate operator exports or small test environments:

```bash
$CTL users list --all
```

The runtime summary is the better first command when you only need aggregate
counts:

```bash
$CTL runtime summary
```

## How do I inspect configuration without leaking secrets?

Config dumps are read from the running Director. Redaction is the default:

```bash
$CTL config dump --defaults
$CTL config dump --non-default
$CTL config dump --non-default --format json
```

Protected output requires an explicit `--protected` request and may be rejected
by the server:

```bash
$CTL config dump --non-default --protected --format yaml
```

Do not use protected output in chat, ticket comments or shell history unless the
operational process explicitly allows it.

## How do I clean up after an interrupted operator workflow?

Inspect first. Each clear command has a narrow meaning:

```bash
$CTL users hold show alice@example.org
$CTL users backend-pin show alice@example.org
$CTL users affinity show alice@example.org
$CTL users sessions alice@example.org
```

Clear only the state that belongs to the interrupted workflow:

```bash
$CTL users hold clear alice@example.org \
  --reason "aborted migration cleanup"

$CTL users backend-pin clear alice@example.org \
  --reason "aborted canary cleanup"
```

Use `users affinity clear` only when the affinity is inactive and the durable
routing source is already correct:

```bash
$CTL users affinity clear alice@example.org \
  --reason "clear inactive stale affinity after routing update"
```

Do not use `affinity clear` as a substitute for `users move`, `users kick` or
mailbox data migration. It removes inactive runtime affinity or pending override
state; it is not a migration workflow by itself.
