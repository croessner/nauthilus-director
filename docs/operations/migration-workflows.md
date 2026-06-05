# Migration Workflows

This runbook shows reversible runtime-only workflows for production
migrations. The Director controls placement, active affinity, pins, holds,
drains and reload. It does not move mailbox data and it does not rewrite YAML
through REST or CLI runtime commands.

Common setup:

```sh
CTL='nauthilus-directorctl --address http://127.0.0.1:9090'
USER='alice@example.org'
```

Add authentication and TLS flags required by the control listener.

## Preflight For Every Migration

Collect a secret-safe baseline:

```sh
$CTL status
$CTL runtime summary
$CTL users show "$USER"
$CTL users sessions "$USER"
$CTL users affinity show "$USER"
$CTL users backend-pin show "$USER"
$CTL users hold show "$USER"
$CTL route lookup --protocol imap --user "$USER" --backend-pool imap-default --include-affinity
```

Use route lookup as a diagnostic only. It does not authenticate credentials,
create sessions, refresh leases, connect to backends or mutate Redis.

## Move One User To A New Backend Node

Use this when mailbox data is being moved to a different shard or backend node.
The mailbox platform owns the data copy. The Director owns placement gates and
runtime routing state.

1. Set a bounded placement hold:

   ```sh
   $CTL users hold set "$USER" \
     --duration 15m \
     --reason "pause placement during mailbox move"
   ```

2. Ask active sessions to close:

   ```sh
   $CTL users kick "$USER" \
     --reason "close sessions before mailbox move"
   ```

3. Wait until no active sessions remain:

   ```sh
   $CTL users sessions "$USER"
   ```

4. Move mailbox data and update the durable routing source outside the
   Director. Examples are deliberately placeholders:

   ```sh
   mailbox-sync --user "$USER" --from mailstore-a --to mailstore-b --mode delta
   identity-set-shard --user "$USER" --shard mailstore-b
   ```

5. Set the runtime shard move:

   ```sh
   $CTL users move "$USER" \
     --to-shard mailstore-b \
     --strategy kick_existing \
     --reason "mailbox data is ready on mailstore-b"
   ```

6. Clear inactive stale affinity only when the durable routing source is
   correct and no active sessions remain:

   ```sh
   $CTL users affinity clear "$USER" \
     --reason "clear inactive affinity after mailbox move"
   ```

7. Clear the placement hold:

   ```sh
   $CTL users hold clear "$USER" \
     --reason "mailbox move complete"
   ```

8. Verify:

   ```sh
   $CTL route lookup --protocol imap --user "$USER" --backend-pool imap-default --include-affinity
   $CTL users affinity show "$USER"
   $CTL users sessions "$USER"
   ```

Rollback: set a new hold, close sessions, restore mailbox data and durable
routing to the old shard, run `users move --to-shard <old-shard>`, clear
inactive stale affinity if safe, then clear the hold.

## Drain A Backend For Maintenance

Use soft maintenance when active sessions can continue and new initial
placements should avoid the backend.

```sh
BACKEND='mailstore-a-imap'

$CTL backends maintenance enable "$BACKEND" \
  --mode soft \
  --reason "planned backend maintenance"

$CTL sessions list --backend "$BACKEND" --limit 100
$CTL backends show "$BACKEND"
```

Use soft drain when the backend should stop receiving new placement and active
sessions should close naturally:

```sh
$CTL backends drain "$BACKEND" \
  --mode soft \
  --reason "drain backend before maintenance"
```

Use hard drain only with an explicit grace when active sessions must close:

```sh
$CTL backends drain "$BACKEND" \
  --mode hard \
  --grace-seconds 60 \
  --reason "backend maintenance requires disconnect after grace"
```

Return the backend explicitly:

```sh
$CTL backends maintenance disable "$BACKEND" \
  --reason "maintenance complete"

$CTL backends in "$BACKEND" \
  --reason "backend ready for placement"
```

Rollback: disable maintenance, bring the backend in, and clear only runtime
overrides that were created by this workflow:

```sh
$CTL backends runtime clear "$BACKEND" \
  --reason "rollback maintenance runtime overrides"
```

## Use A Placement Hold During Mailbox Movement

A placement hold blocks new placement for one user for a bounded duration. It
does not choose a shard, choose a backend, close sessions, clear affinity,
clear pins or edit YAML.

```sh
$CTL users hold set "$USER" \
  --duration 10m \
  --reason "pause placement while mailbox metadata is updated"

$CTL users hold show "$USER"
$CTL route lookup --protocol imap --user "$USER" --include-affinity
```

If the operation takes longer than expected, set a fresh audited hold before the
old one expires. Clear the hold when the durable routing source and runtime
state are ready:

```sh
$CTL users hold clear "$USER" \
  --reason "placement may resume"
```

## Pin A User For Targeted Commissioning

Use a backend pin only when the selected shard and active or retained
backend-node binding already match the target backend. A backend pin is not a
cross-shard move.

```sh
BACKEND='mailstore-c-imap'
USER='canary@example.org'

$CTL backends weight "$BACKEND" \
  --weight 0 \
  --reason "commission backend without general placement"

$CTL users backend-pin set "$USER" \
  --backend "$BACKEND" \
  --strategy kick_existing \
  --reason "canary test on target backend"

$CTL route lookup --protocol imap --user "$USER" --backend-pool imap-default --include-affinity
```

Clear the pin and restore normal placement when the test is complete:

```sh
$CTL users backend-pin clear "$USER" \
  --reason "canary pin complete"

$CTL backends weight "$BACKEND" \
  --weight 100 \
  --reason "enable general placement"
```

Rollback: clear the pin first. If active sessions were kicked, let clients
reconnect through normal placement or set a new hold before changing routing
state again.

## Drain A Listener During A Director Deploy

Listener drain is process-local in v1. Repeat it for each Director process
behind an external load balancer.

```sh
$CTL listeners drain imap \
  --mode soft \
  --reason "deploy director instance"

$CTL listeners drain sieve \
  --mode soft \
  --reason "deploy director instance"
```

After the instance is upgraded and ready, resume listeners from the current
typed config snapshot:

```sh
$CTL listeners resume imap --reason "director instance ready"
$CTL listeners resume sieve --reason "director instance ready"
```

Listener drain state is not a YAML setting and is not persisted as a config
edit.

## Use Safe Reload During A Migration

Use safe reload only for reloadable config classes such as new listeners,
removed listeners, backend registry changes and backend-pool changes for new
sessions:

```sh
$CTL reload
```

If reload is rejected, the old accepted config snapshot remains active. Do not
try to repair a rejected reload by editing runtime state. Either roll back the
config change and reload again, or schedule a restart for restart-required
classes.

## Runtime Cleanup Versus Config Edits

Runtime cleanup commands have narrow meanings:

| Command | Removes | Does not remove |
| --- | --- | --- |
| `users hold clear` | One placement hold. | Sessions, affinity, pins, moves or YAML. |
| `users backend-pin clear` | One concrete backend pin. | Shard move, sessions, affinity or YAML. |
| `users affinity clear` | Inactive affinity and pending override state. | Active sessions, mailbox data or durable routing source. |
| `backends runtime clear` | Runtime overrides for one backend. | Static backend config, health facts or sessions by itself. |

Use config edits for durable topology, auth, Redis, listener security and
backend definitions. Use runtime commands for bounded operational state.
