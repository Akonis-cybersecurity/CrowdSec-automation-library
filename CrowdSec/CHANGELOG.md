# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-04-30 - 1.0.0

### Added
- `CrowdSecAlertTrigger`: polls `GET /v1/alerts` (Watcher JWT auth) and forwards new alerts to Sekoia intake
- `CrowdSecDecisionTrigger`: streams `GET /v1/decisions/stream` (Bouncer API key auth) and forwards new/deleted decisions to Sekoia intake
- `GetDecisions` action: retrieve active decisions via `GET /v1/decisions` (Bouncer auth)
- `GetAlerts` action: search alerts via `GET /v1/alerts` (Watcher auth)
- `GetAlertById` action: retrieve a single alert by ID via `GET /v1/alerts/{id}` (Watcher auth)
- `DeleteDecision` action: delete a single decision by ID via `DELETE /v1/decisions/{id}` (Watcher auth)
- `DeleteDecisions` action: bulk-delete decisions via `DELETE /v1/decisions` (Watcher auth)
- `DeleteAlerts` action: bulk-delete alerts via `DELETE /v1/alerts` (Watcher auth)
- `DeleteAlertById` action: delete a single alert by ID via `DELETE /v1/alerts/{id}` (Watcher auth)
- `GetAllowlists` action: list all allowlists via `GET /v1/allowlists` (Watcher auth)
- `GetAllowlist` action: retrieve a named allowlist via `GET /v1/allowlists/{name}` (Watcher auth)
- `CheckAllowlist` action: check an IP/range via `GET /v1/allowlists/check/{ip_or_range}` (Watcher auth)
- `BulkCheckAllowlist` action: bulk-check IPs/ranges via `POST /v1/allowlists/check` (Watcher auth)
- Dual authentication: Bouncer (X-Api-Key) for read-only decision endpoints; Watcher (JWT auto-refresh) for full access
