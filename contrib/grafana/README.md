# Grafana dashboards

This directory contains importable Grafana dashboards for
`nauthilus-director` operator observability.

## Nauthilus Director Operator Overview

Dashboard:

- `dashboards/nauthilus-director-operator.json`

The dashboard is a Grafana Classic JSON dashboard that can be imported directly
or provisioned from a file provider. It intentionally uses a Prometheus
datasource variable and target variables for `job` and `instance`, so the same
dashboard works for one director process or a fleet of director instances.

The dashboard is organized around the implemented Prometheus metric surface:

- Fleet status, exporter state, optional Go/process collectors and sink health.
- Frontend sessions, listener lifecycle, pre-auth outcomes, proxy bytes and
  proxy lifetime distributions.
- Nauthilus auth, routing resolver, backend selection, backend connect, backend
  auth and affinity observations.
- Backend health, backend active-session aggregates and operator runtime
  controls.
- REST, Redis and runtime-control request rates, failures and latency
  distributions.
- LMTP transaction, recipient-route, recipient-status, DATA and BDAT delivery
  metrics.
- A dashboard-local label inventory that documents the safe metric dimensions.

## Implemented metric labels

The reviewed Prometheus allowlist is:

`backend_pool`, `direction`, `listener`, `maintenance_mode`, `mechanism`,
`method`, `operation`, `protocol`, `reason_class`, `redis_mode`, `result`,
`route`, `service`, `shard_tag`, `status_class`, `tls_mode`, `transport`.

High-cardinality or secret-bearing fields are intentionally excluded from metric
labels, including usernames, recipients, client IPs, request IDs, session IDs,
trace/span IDs, raw backend identifiers, backend nodes, raw Redis keys, raw
errors, SASL blobs, tokens and passwords.

## Metric family inventory

Histograms also expose their Prometheus `_bucket`, `_sum` and `_count` series.

| Metric family | Type | Labels |
| --- | --- | --- |
| `nauthilus_director_active_sessions` | gauge | `protocol`, `service`, `listener`, `backend_pool`, `tls_mode` |
| `nauthilus_director_affinity_operations_total` | counter | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_backend_active_sessions` | gauge | `protocol`, `backend_pool`, `shard_tag` |
| `nauthilus_director_backend_auth_total` | counter | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class`, `mechanism` |
| `nauthilus_director_backend_connect_total` | counter | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_backend_connect_duration_seconds` | histogram | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_backend_drain_operations_total` | counter | `operation`, `result`, `reason_class`, `maintenance_mode` |
| `nauthilus_director_backend_health_state` | gauge | `protocol`, `backend_pool`, `shard_tag`, `result` |
| `nauthilus_director_backend_health_transitions_total` | counter | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_backend_maintenance_operations_total` | counter | `operation`, `result`, `reason_class`, `maintenance_mode` |
| `nauthilus_director_backend_proxy_protocol_total` | counter | `protocol`, `backend_pool`, `operation`, `result`, `reason_class` |
| `nauthilus_director_backend_runtime_operations_total` | counter | `operation`, `result`, `reason_class` |
| `nauthilus_director_backend_selection_total` | counter | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_backend_selection_duration_seconds` | histogram | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_listener_lifecycle_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `tls_mode`, `operation`, `result`, `reason_class` |
| `nauthilus_director_lmtp_backend_status_total` | counter | `protocol`, `backend_pool`, `shard_tag`, `operation`, `status_class`, `result`, `reason_class` |
| `nauthilus_director_lmtp_bdat_streams_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `shard_tag`, `operation`, `status_class`, `result`, `reason_class` |
| `nauthilus_director_lmtp_bdat_stream_duration_seconds` | histogram | `protocol`, `service`, `listener`, `backend_pool`, `shard_tag`, `operation`, `status_class`, `result`, `reason_class` |
| `nauthilus_director_lmtp_data_streams_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `shard_tag`, `operation`, `status_class`, `result`, `reason_class` |
| `nauthilus_director_lmtp_data_stream_duration_seconds` | histogram | `protocol`, `service`, `listener`, `backend_pool`, `shard_tag`, `operation`, `status_class`, `result`, `reason_class` |
| `nauthilus_director_lmtp_recipient_routes_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `shard_tag`, `operation`, `result`, `reason_class` |
| `nauthilus_director_lmtp_recipient_status_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `shard_tag`, `operation`, `status_class`, `result`, `reason_class` |
| `nauthilus_director_lmtp_same_backend_policy_failures_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `shard_tag`, `operation`, `result`, `reason_class` |
| `nauthilus_director_lmtp_transactions_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `tls_mode`, `operation`, `result`, `reason_class` |
| `nauthilus_director_lmtp_transaction_duration_seconds` | histogram | `protocol`, `service`, `listener`, `backend_pool`, `tls_mode`, `operation`, `result`, `reason_class` |
| `nauthilus_director_metrics_enabled` | gauge | none |
| `nauthilus_director_nauthilus_auth_total` | counter | `protocol`, `service`, `listener`, `transport`, `mechanism`, `result`, `reason_class` |
| `nauthilus_director_nauthilus_auth_duration_seconds` | histogram | `protocol`, `service`, `listener`, `transport`, `mechanism`, `result`, `reason_class` |
| `nauthilus_director_observability_events_total` | counter | `operation`, `result` |
| `nauthilus_director_observability_sink_failures_total` | counter | `operation`, `reason_class` |
| `nauthilus_director_preauth_commands_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `tls_mode`, `result`, `reason_class` |
| `nauthilus_director_process_up` | gauge | none |
| `nauthilus_director_proxy_bytes_total` | counter | `direction`, `result`, `reason_class` |
| `nauthilus_director_proxy_lifetime_duration_seconds` | histogram | `operation`, `result`, `reason_class` |
| `nauthilus_director_redis_operations_total` | counter | `operation`, `redis_mode`, `result`, `reason_class` |
| `nauthilus_director_redis_operation_duration_seconds` | histogram | `operation`, `redis_mode`, `result`, `reason_class` |
| `nauthilus_director_reload_total` | counter | `operation`, `result`, `reason_class` |
| `nauthilus_director_rest_requests_total` | counter | `method`, `route`, `operation`, `status_class`, `result` |
| `nauthilus_director_rest_request_duration_seconds` | histogram | `method`, `route`, `operation`, `status_class`, `result` |
| `nauthilus_director_routing_resolver_total` | counter | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_routing_resolver_duration_seconds` | histogram | `protocol`, `backend_pool`, `shard_tag`, `result`, `reason_class` |
| `nauthilus_director_runtime_operations_total` | counter | `operation`, `result`, `reason_class` |
| `nauthilus_director_runtime_operation_duration_seconds` | histogram | `operation`, `result`, `reason_class` |
| `nauthilus_director_sessions_total` | counter | `protocol`, `service`, `listener`, `backend_pool`, `tls_mode`, `result`, `reason_class` |

