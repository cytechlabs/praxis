# Database health metrics — removed in 1.0 (PRA-301)

The `db_health_status` and `db_health_response_time_seconds` Prometheus gauges, and
the `DatabaseHealthCheck` collector that produced them, were **removed** in PRA-301.

They were never wired into a scraped path: the collector only updated when run
explicitly, and nothing (no API route, no scheduler job) ran it in normal operation,
so the series were always absent/stale in a real scrape. Shipping documented
zero/never-updated series is misleading, so the collector, its ad-hoc scripts, and
the recording-rule / dashboard / alert guidance that referenced these metrics were
retired.

Building dashboards, recording rules, and Alertmanager rules is out of scope for the
1.0 exporter contract (see PRA-301 non-goals). Grafana/alerting are downstream,
operator-owned concerns.

## What the backend actually exposes

The supported 1.0 backend scrape contract lives on the single listener at
`backend:9090` and is documented in
[`database-connection-pooling.md`](./database-connection-pooling.md#metrics-pra-301-supported-contract):

- `db_operations_total{operation_type}` — Counter (per-session, outcome-labelled)
- `db_operation_latency_seconds` — Histogram (per-session duration)
- `db_connections_in_use` — Gauge (current checked-out connections)
- `db_connections_created_total` — Counter (physical connections created)

Backend liveness/connectivity for the fleet is handled by the scheduled fleet
connectivity health check (a background job), not by scraped DB-health gauges.
