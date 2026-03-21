# Security Platform

Docker-first security analytics platform with Kafka ingestion, enrichment, detection, scoring, correlation, case management, analyst activity tracking, and a live SOC-style frontend.

## Overview

The platform ingests raw security events, normalizes and enriches them, produces detections and risk scores, correlates related findings, stores alert and case state, and exposes both REST and WebSocket interfaces for the frontend.

Canonical Kafka flow:

- `events.raw`
- `events.parsed`
- `events.routed`
- `events.enriched`
- `detections.rules`
- `detections.anomaly`
- `risk.scores`
- `alerts.correlated`
- `alerts.generated`

Legacy topics are still emitted for compatibility:

- `raw_logs`
- `parsed_events`
- `auth_events`
- `stream_events`
- `security_alerts`
- `risk_alerts`

## Services

Application services:

- `ingestion_service`: authenticated log ingestion API.
- `parser_service`: event normalization and schema shaping.
- `event_router`: event domain routing.
- `threat_intel_service`: IP enrichment, TOR/proxy/reputation context, and geolocation lookups.
- `detection_engine`: rules-based detections driven by `configs/rules.yaml`.
- `anomaly_engine`: anomaly detections over enriched traffic.
- `risk_engine`: risk scoring aggregation.
- `correlation_engine`: alert grouping and correlated alert generation.
- `alert_service`: alert persistence and downstream publishing.
- `investigation_api`: alerts, investigations, cases, auth, workflow actions, activity, watchlist, and WebSocket streaming.
- `geolocation_service`: cached IP geolocation API used by the platform and frontend.
- `frontend`: static ThreatPulse dashboard served by nginx in Docker or by `python -m http.server` locally.

Supporting infrastructure:

- `kafka`
- `zookeeper`
- `postgres`
- `redis`
- `neo4j`
- `clickhouse`
- `prometheus`
- `grafana`

## Frontend

The frontend is a plain HTML/CSS/ES module application in [`frontend/`](/C:/Users/kouro/PycharmProjects/PythonProject5/frontend) with no bundler. It supports:

- dashboard overview metrics
- alert triage and investigation workbench
- case queue and case workspace
- analyst activity stream
- admin live view with presence, investigation activity, SLA watch, and rule tuning
- demo mode fallback when live API access is not configured

Architecture details are documented in [`frontend_trace.txt`](/C:/Users/kouro/PycharmProjects/PythonProject5/frontend_trace.txt).

## Repository Layout

A current tree summary lives in [`Repository_Structure`](/C:/Users/kouro/PycharmProjects/PythonProject5/Repository_Structure).

Key folders:

- [`configs/`](/C:/Users/kouro/PycharmProjects/PythonProject5/configs): rule tuning, Prometheus config, ClickHouse bootstrap SQL, honeypot and TOR data files.
- [`frontend/`](/C:/Users/kouro/PycharmProjects/PythonProject5/frontend): static dashboard.
- [`services/`](/C:/Users/kouro/PycharmProjects/PythonProject5/services): Python microservices and Dockerfiles.
- [`shared/`](/C:/Users/kouro/PycharmProjects/PythonProject5/shared): cross-service utilities, auth, topics, metrics, persistence helpers, presence, playbooks, and watchlist support.
- [`scripts/`](/C:/Users/kouro/PycharmProjects/PythonProject5/scripts): smoke and UI verification helpers.
- [`tests/`](/C:/Users/kouro/PycharmProjects/PythonProject5/tests): backend and integration coverage.

## Setup

1. Copy `.env.example` to `.env`.
2. Change the secrets before exposing the stack anywhere:
   - `POSTGRES_PASSWORD`
   - `SECURITY_API_KEY`
   - `JWT_SECRET`
   - `NEO4J_PASSWORD`
   - `GRAFANA_PASSWORD`
3. Start the platform:

```powershell
docker compose up --build
```

The compose file binds most ports to `127.0.0.1`, so the stack is local-only by default.

## Main URLs

- Frontend: `http://localhost:8080`
- Local frontend dev server: `http://localhost:4173`
- Ingestion API: `http://localhost:8000/log`
- Investigation API: `http://localhost:8001`
- Investigation WebSocket: `ws://localhost:8001/ws`
- Legacy WebSocket alias: `ws://localhost:8001/ws/alerts`
- Geolocation API: `http://localhost:8002/lookup`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Neo4j Browser: `http://localhost:7474`
- Kafka external listener: `localhost:29092`

## Auth

API access supports:

- `X-API-Key: <SECURITY_API_KEY>`
- JWTs issued by `POST /auth/token` on `investigation_api`

The WebSocket expects the JWT as the first message after connection.

Frontend login uses the built-in users defined in [`shared/users.py`](/C:/Users/kouro/PycharmProjects/PythonProject5/shared/users.py). Current local accounts include:

- `admin / admin123`
- `analyst / analyst123`

Additional seeded analyst users are also defined there.

## Common API Areas

The investigation API is the main integration surface. It includes routes for:

- alerts and event snapshots
- entity investigation by IP, account, and device
- case creation and workflow updates
- alert actions such as assign, note, false-positive, status, and block-IP
- analyst activity and presence
- watchlist management
- token issuance and WebSocket streaming

For implementation details, inspect [`services/investigation_api/api.py`](/C:/Users/kouro/PycharmProjects/PythonProject5/services/investigation_api/api.py).

## Configuration

Important config files:

- [`configs/rules.yaml`](/C:/Users/kouro/PycharmProjects/PythonProject5/configs/rules.yaml): detection thresholds and rule tuning.
- [`configs/prometheus.yml`](/C:/Users/kouro/PycharmProjects/PythonProject5/configs/prometheus.yml): Prometheus scrape targets.
- [`configs/clickhouse_init.sql`](/C:/Users/kouro/PycharmProjects/PythonProject5/configs/clickhouse_init.sql): ClickHouse bootstrap schema.
- [`configs/honeypot_accounts.txt`](/C:/Users/kouro/PycharmProjects/PythonProject5/configs/honeypot_accounts.txt): honeypot accounts.
- [`configs/tor_exit_nodes.txt`](/C:/Users/kouro/PycharmProjects/PythonProject5/configs/tor_exit_nodes.txt): TOR exit list.

## Local Development

Python dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Run tests:

```powershell
.\.venv\Scripts\python.exe -m pytest tests
```

Serve the frontend locally without Docker:

```powershell
npm start
```

That serves [`frontend/`](/C:/Users/kouro/PycharmProjects/PythonProject5/frontend) on port `4173`.

## Verification

Backend smoke test:

```powershell
.\scripts\smoke_test.ps1
```

Frontend verification helper:

```powershell
node .\scripts\manual_verify.js
```

The Playwright helper checks demo mode startup, API persistence, dashboard population, login, case creation, search routing, investigation rendering safety, and logout behavior.

## Notes

- Public IPs geolocate; private and loopback addresses are intentionally left unmapped.
- The frontend stores connection settings in `localStorage` under `cybermap.apiBaseUrl`, `cybermap.apiKey`, and related keys.
- The dashboard can run in demo mode and also expose built-in scenarios through the `Show Demo` flow.
- The investigation layer prefers Neo4j for graph traversal and falls back to alert-derived relationships if graph data is sparse.
