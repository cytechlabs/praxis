# Database Connection Pooling

## Overview
This document describes the database connection pooling configuration for the Praxis application, including pool settings, metrics, and best practices.

## Configuration

### Connection Pool Settings
```python
pool_size=20        # Maximum number of permanent connections
max_overflow=10     # Maximum number of additional temporary connections
pool_timeout=30     # Seconds to wait before timing out on getting a connection
pool_recycle=1800   # Seconds before a connection is recycled (30 minutes)
pool_pre_ping=True  # Verify connection validity before using it
```

### Environment Variables
The following environment variables can be used to configure the database connection:
```
POSTGRES_SERVER: Database server hostname (default: "db")
POSTGRES_USER: Database username (default: "postgres")
POSTGRES_PASSWORD: Database password (default: "postgres")
POSTGRES_DB: Database name (default: "praxis")
POSTGRES_PORT: Database port (default: "5432")
```

## Metrics (PRA-301 supported contract)

The backend exposes a single Prometheus scrape listener on `backend:9090`
(`http://127.0.0.1:9090/metrics` from inside the backend container). The listener is
started explicitly from the FastAPI startup lifecycle for the supported
**single-worker** 1.0 deployment — it is not a multi-worker aggregation. Every
metric below is emitted by normal production code paths (`get_db` request sessions
and `DatabaseSessionManager`); labels are low-cardinality and non-sensitive (no
user/system IDs, hostnames, SQL text, or exception strings).

### Available Metrics

| Metric | Type | Labels | Changes when |
| --- | --- | --- | --- |
| `db_operations_total` | Counter | `operation_type` = `success` \| `error` | +1 per DB session at close, labelled with the session outcome |
| `db_operation_latency_seconds` | Histogram | — | observed once per DB session: open-to-close duration |
| `db_connections_in_use` | Gauge | — | current connections checked out of the pool (checkout +1 / checkin −1) — a true current gauge that returns to baseline |
| `db_connections_created_total` | Counter | — | +1 each time a new physical connection is established over the process lifetime |

Removed in PRA-301: `db_connections_current{pool_type=...}` (a lifetime counter
mislabelled as a current gauge — replaced by `db_connections_in_use` +
`db_connections_created_total`), and the `db_health_status` /
`db_health_response_time_seconds` gauges (never wired to a scraped path; the DB
health checker they belonged to was unused and has been removed).

### Viewing Metrics
1. Access the bundled Prometheus UI (loopback-only): `http://localhost:9091`
2. Raw backend metrics (inside the backend container): `http://127.0.0.1:9090/metrics`

### Example Queries
```
# Connections currently checked out
db_connections_in_use

# Rate of new physical connections
rate(db_connections_created_total[5m])

# Session latency (95th percentile)
histogram_quantile(0.95, rate(db_operation_latency_seconds_bucket[5m]))

# Error rate
rate(db_operations_total{operation_type="error"}[5m])
```

## Error Handling
The connection pool implements several error handling mechanisms:

1. **Connection Validation**
   - Pre-ping validation before connection use
   - Automatic invalid connection removal
   - Connection recycling to prevent stale connections

2. **Transaction Management**
   - Automatic rollback on errors
   - Session cleanup in all cases
   - Connection return to pool guaranteed

3. **Timeout Handling**
   - Connection acquisition timeout (30s)
   - Configurable operation timeouts
   - Automatic cleanup of timed-out connections

## Best Practices

### Using Database Sessions
```python
from app.db.session import get_db

# Correct usage with context manager
def example_operation():
    with get_db() as db:
        result = db.execute(query)
        return result

# Avoid direct session creation
# Don't do this:
# session = SessionLocal()
```

### Connection Pool Management
1. Monitor pool utilization using Prometheus metrics
2. Adjust pool size based on application needs
3. Set appropriate timeouts for your use case
4. Use connection recycling for long-running applications

### Performance Optimization
1. Keep transaction times short
2. Use bulk operations when possible
3. Monitor connection usage patterns
4. Implement retry logic for transient failures

## Monitoring and Maintenance

### Regular Monitoring Tasks
1. Check connection pool utilization
2. Monitor operation latencies
3. Track error rates
4. Review connection lifecycle metrics

### Maintenance Commands

Connection-pool metrics are exposed as Prometheus metrics on the backend's
metrics port and scraped by the bundled Prometheus:

```bash
# Scrape the backend metrics endpoint directly (over the Docker network)
docker compose exec backend python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9090/metrics').read().decode())"

# Or open the bundled Prometheus UI (loopback-only)
#   http://127.0.0.1:9091
```

### Bundled Prometheus (infrastructure telemetry) — PRA-300

The bundled Prometheus is **infrastructure telemetry for the Praxis control plane**.
It is **not** the paid Praxis Command Metrics feature, and 1.0 intentionally ships no
Grafana, no Alertmanager, no recording/alert rules, no host/DB/Vault/Caddy/broker
exporters, no external/HA Prometheus, and **no public metrics ingress**.

- **Image**: pinned to `prom/prometheus:v3.13.1` (current Prometheus 3.x LTS; never
  `latest`). Bump policy: pin to a current stable/LTS tag and re-run
  `promtool check config` on `prometheus.yml` before changing it.
- **Access**: UI is loopback-only at `http://127.0.0.1:9091` (published as
  `127.0.0.1:9091:9090`). The container sits only on `backend_net` and scrapes the
  single target `backend:9090`.
- **Persistence / retention**: the TSDB lives in the named volume
  `praxis_prometheus_data` mounted at `/prometheus`, so time series **survive normal
  container recreation** (`docker compose up -d`, image bumps). Default retention is
  ~15 days. To wipe it deliberately:
  `docker compose down && docker volume rm praxis_prometheus_data`.
- **Health / startup**: the service is health-aware — it waits for the backend
  exporter to be healthy before starting, and reports healthy only once its own
  readiness endpoint (`/-/ready`) responds. Verify:

```bash
# validate the scrape config (deterministic; no running stack needed)
docker run --rm --entrypoint promtool \
  -v "$PWD/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  prom/prometheus:v3.13.1 check config /etc/prometheus/prometheus.yml

# production-parity: confirm Prometheus is up and scraping backend:9090
docker compose up -d db vault backend prometheus
docker compose ps prometheus                     # -> healthy
curl -fsS http://127.0.0.1:9091/-/ready          # -> Prometheus Server is Ready.
curl -fsS 'http://127.0.0.1:9091/api/v1/targets' # -> backend:9090 health "up"
```

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Check pool_timeout setting
   - Monitor active connections
   - Review long-running transactions

2. **Pool Exhaustion**
   - Monitor max_overflow usage
   - Check for connection leaks
   - Review pool size settings

3. **Stale Connections**
   - Verify pool_recycle setting
   - Check for network issues
   - Monitor connection errors

### Debugging
1. Enable SQL logging for debugging
2. Use metrics dashboard for visualization
3. Review application logs for connection issues
4. Monitor database server logs
