# Spec: `telemetry-contract` — Canonical Telemetry, Schema & Pack Contract

- **Module ID:** `telemetry-contract`
- **Depends on:** — *(Foundation module in `CAPABILITY-MAP.md`)*
- **Consumed by:** `hub-core`, `hub-tenancy-gateway`, `hub-probes-alerting`, `hub-ui`, `site-collector`

---

## Assumptions

1. Every customer tenant is identified by an immutable, DNS-safe lowercase slug (`customer`) assigned on `central-monitoring-hub`; overlapping RFC1918 subnets (e.g., multiple customers running `192.168.1.0/24`) are disambiguated by `(customer, site, collector_id, instance)`.
2. All telemetry transport across WAN links uses outbound HTTPS (`TCP/443` via NS8 Traefik) with high-entropy bearer tokens (`cms_v1_<secret>`), requiring zero inbound firewall port-forwards at customer sites.
3. Grafana dashboards in `shared/dashboards/` use fixed datasource UIDs `prometheus` and `loki` plus template variables `$customer` and `$site` so the exact same JSON models work for both the MSP Main Org (Org 1, cross-tenant) and isolated Customer Orgs (forced single-tenant via `prom-label-proxy` and `X-Scope-OrgID`).
4. Local automated contract validation runs on the Windows engineering host (`Python 3.14.10`, `pytest 9.2.0`, `jsonschema 4.26.0`, `Node.js v26.13.1`, `npm 11.20.0`, `git 2.56.0.windows.4`; no local `go` compiler is installed).

---

## Objective

Define the single, immutable data, API, schema, alerting, and dashboard contract (`shared/`) between `central-monitoring-hub`, `central-monitoring-collector`, and standalone Grafana Alloy agents (Linux, Windows, Docker). By locking down label regexes, HTTP ingest wire protocols, consistent error envelopes, NS8 Draft-07 JSON Schemas, Prometheus alert rule packs, and Grafana starter dashboards upfront, all downstream Hub and Collector modules can be built and verified independently without drift or cross-tenant data leakage.

---

## Tech Stack

- **Schema Standard:** JSON Schema Draft-07 (`http://json-schema.org/draft-07/schema#`), 100% self-contained per file (no external file `$ref`s) for direct compatibility with NethServer 8 `/usr/local/agent` `validate-input.json` and `validate-output.json`.
- **Metrics Ingest Protocol:** Prometheus Remote Write v1 (`Content-Type: application/x-protobuf`, `Content-Encoding: snappy`, `X-Prometheus-Remote-Write-Version: 0.1.0`) over `POST /api/v1/write`.
- **Logs Ingest Protocol:** Grafana Loki Push API (`POST /loki/api/v1/push`, supporting both Snappy-compressed `application/x-protobuf` `logproto.PushRequest` and `application/json` streams) with multi-tenancy (`auth_enabled: true`, `X-Scope-OrgID`).
- **Alert Rules:** Prometheus v2.54+ / Alertmanager v0.27+ rule group YAML (`shared/rules/*.yml`).
- **Dashboards:** Grafana OSS v11.2+ JSON Dashboard schema v39+ (`shared/dashboards/*.json`).
- **Standalone Onboarding Templates:** Grafana Alloy v1.4+ River configuration & idempotent OS installers (`shared/alloy-templates/*.tmpl`).
- **Detected Local Host Runtimes (Windows):**
  - `python --version`: `Python 3.14.10` (`pytest 9.2.0`, `pytest-asyncio 1.5.0`, `jsonschema 4.26.0`, `aiohttp 3.14.5`, `fastapi 0.139.0`, `httpx 0.28.1`, `cryptography 49.0.0`, `sqlite3 3.50.4`)
  - `node --version`: `v26.13.1` / `npm --version`: `11.20.0`
  - `git --version`: `git version 2.56.0.windows.4`
  - `docker.exe`: available (`go` and `PyYAML` are **not** pre-installed globally on the host)

---

## Commands

```powershell
# Validate all 47 Draft-07 JSON Schemas in shared/schemas/
python -c "import glob, json, jsonschema; files = sorted(glob.glob('shared/schemas/*.json')); assert len(files) >= 47; [jsonschema.Draft7Validator.check_schema(json.load(open(f, encoding='utf-8'))) for f in files]; print('Validated', len(files), 'schemas')"

# Validate all Grafana Dashboard JSON files (schemaVersion >= 39, UIDs prometheus/loki, LF endings)
python -c "import glob, json; [json.load(open(f, encoding='utf-8')) for f in sorted(glob.glob('shared/dashboards/*.json'))]; print('Dashboards JSON valid')"

# Enforce zero CRLF (\r\n) line endings across shared/, specs, and repo config
python -c "import pathlib, sys; bad = [str(p) for p in pathlib.Path('.').rglob('*') if p.is_file() and '.git' not in p.parts and b'\r\n' in p.read_bytes()]; assert not bad, f'CRLF detected: {bad}'; print('LF check passed')"

# Run contract & schema test suite
python -m pytest tests/contract -v

# Optional container-based promtool check when Docker daemon is active
docker run --rm --entrypoint promtool -v "${PWD}/shared/rules:/rules:ro" quay.io/prometheus/prometheus:v2.54.1 check rules /rules/ns8-cluster.yml /rules/linux-node.yml /rules/windows-node.yml /rules/proxmox-ve.yml /rules/blackbox-web-ssl.yml /rules/snmp-network-ups.yml
```

---

## Project Structure

```text
.gitattributes                         -> Enforces LF line endings on imageroot, scripts, YAML, Alloy, Containerfiles
.gitignore                             -> Excludes node_modules, dist, __pycache__, .pytest_cache, .env, scratch
shared/
  schemas/
    telemetry-contract.schema.json     -> Canonical label regexes, device_role enum, token format, API error envelope
    hub-*-input.json                   -> 17 self-contained Draft-07 NS8 action input schemas for central-monitoring-hub
    hub-*-output.json                  -> 17 self-contained Draft-07 NS8 action output schemas for central-monitoring-hub
    collector-*-input.json             -> 6 self-contained Draft-07 NS8 action input schemas for central-monitoring-collector
    collector-*-output.json            -> 6 self-contained Draft-07 NS8 action output schemas for central-monitoring-collector
  rules/
    ns8-cluster.yml                    -> NS8 node, CPU/RAM/swap, disk/predict_linear, mdadm, Restic backup, container & systemd rules
    linux-node.yml                     -> Linux host down, load, OOM, fs/inodes, disk I/O, systemd, NTP, reboot rules
    windows-node.yml                   -> Windows host down, CPU/RAM, logical disk, auto-services, AD/DNS/SMB, reboot rules
    proxmox-ve.yml                     -> Proxmox node, quorum, storage pools, ZFS health, auto-start VM/LXC, IO delay rules
    blackbox-web-ssl.yml               -> HTTP availability, status >=400/500, latency >3s, TLS expiry <21d/<7d, DNS/TCP rules
    snmp-network-ups.yml               -> SNMP reachability, UPS battery/runtime/replace, switch/firewall ifOperStatus/errors, NAS health
  dashboards/
    ns8-multi-cluster-overview.json    -> MSP Fleet Executive Summary (alerts, nodes, backups, top consumers, Loki errors)
    linux-windows-servers.json         -> Detailed Linux & Windows server metrics + host logs
    proxmox-snmp-infrastructure.json   -> Proxmox VE, SNMP network/firewall/UPS/NAS metrics + Syslog stream
    web-ssl-uptime.json                -> Blackbox availability %, response time, TLS certificate expiry countdown
  alloy-templates/
    config-linux.alloy.tmpl            -> Standalone Linux Alloy config (unix exporter + journal + optional SNMP/Syslog + WAL)
    config-windows.alloy.tmpl          -> Standalone Windows Alloy config (windows exporter + eventlog + WAL)
    config-docker.alloy.tmpl           -> Standalone Docker Alloy config (containers + host + optional LAN SNMP/Proxmox/Syslog + WAL)
    install-linux.sh.tmpl              -> Idempotent Debian/Ubuntu/RHEL/Rocky bash installer
    install-windows.ps1.tmpl           -> Idempotent Windows Server PowerShell installer
    docker-compose.yml.tmpl            -> Docker Compose deployment with persistent WAL volume
tests/
  contract/                            -> Automated schema, rule label preservation, dashboard & template contract tests
```

---

## Canonical Data & API Contract

### 1. Mandatory Telemetry Labels (Metrics & Logs)

Every Prometheus time series and every Loki log stream stored in `central-monitoring-hub` **MUST** carry these four labels:

| Label | Pattern / Enum | Enforcement Point | Purpose |
| :--- | :--- | :--- | :--- |
| `customer` | `^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$` | **Server-enforced** by Hub Auth-Gateway (push) and Hub `file_sd` generator (pull) | Cryptographic/hard tenant boundary for `prom-label-proxy`, Loki `X-Scope-OrgID`, and Alertmanager per-customer routing |
| `site` | `^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$` | Validated against tenant site list or defaulted to token's primary site | Distinguishes physical/logical locations (`hq`, `dc1`, `branch-berlin`) with overlapping LAN subnets |
| `device_role` | Enum: `ns8`, `linux`, `windows`, `proxmox`, `web`, `snmp-network`, `snmp-ups`, `snmp-nas`, `snmp-firewall`, `snmp-printer` | Validated on ingest (defaults to token/job role if omitted; invalid values rejected with `422`) | Drives standard MSP rule pack selectors and Grafana dashboard breakdowns |
| `collector_id` | `^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$` | Validated/stamped on ingest (`hub-central` for central Hub pull/probe scrapes) | Tracks collector health, WAL lag, and origin accountability |

**Alert Rule Aggregation Invariant:** Every alerting rule in `shared/rules/*.yml` that uses PromQL aggregation (`sum`, `avg`, `max`, `min`, `count`, `topk`) **MUST** include `by (customer, site, ...)` (or `without (...)` preserving `customer`, `site`, `device_role`, `instance`) and set labels `severity: warning|critical` and `category: cluster|compute|storage|network|power|web|backup|security`.

### 2. HTTPS Ingest & Query Wire Endpoints

All external traffic enters via NS8 Traefik (`https://<host>`) -> `127.0.0.1:${TCP_PORT}` -> `hub-gateway` (`:8080`):

| Method & Path | Auth | Success Status | Security / Protocol Behavior |
| :--- | :--- | :--- | :--- |
| `POST /api/v1/write` | `Authorization: Bearer cms_v1_...` | `204 No Content` / `200 OK` | Decodes Snappy + Protobuf `prometheus.WriteRequest`, strips any client `customer` label, injects authoritative `customer=<token.customer>` in sorted label order, validates `site`/`device_role`/`collector_id`, re-encodes Snappy + Protobuf, forwards to `http://127.0.0.1:9090/api/v1/write`. Max compressed body: `16 MiB`. |
| `POST /loki/api/v1/push` | `Authorization: Bearer cms_v1_...` | `204 No Content` | Strips any client `X-Scope-OrgID`, injects authoritative `X-Scope-OrgID: <token.customer>`, rewrites stream label set to enforce `customer="<token.customer>"`, forwards to `http://127.0.0.1:3100/loki/api/v1/push`. Max compressed body: `16 MiB`. |
| `GET /api/v1/ingest/verify` | `Authorization: Bearer cms_v1_...` | `200 OK` | Lightweight connectivity & token check used by `test-hub-connection`. Returns `{"status":"ok","customer":"<slug>","token_prefix":"cms_v1_..."}`. |
| `ANY /*` (all other paths) | Grafana Session / LDAP | Upstream status | Proxied to internal Grafana (`http://127.0.0.1:3000`) including WebSocket `/api/live/ws`. Internal Prometheus (`:9090`), Thanos (`:10902`), Loki (`:3100`), Alertmanager (`:9093`), and `prom-label-proxy` (`:9095`) are **NEVER** reachable via `hub-gateway` public paths. |

### 3. Consistent Error Envelope

All Hub Auth-Gateway ingest/API error responses return `Content-Type: application/json` matching `telemetry-contract.schema.json#/definitions/apiError`:

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Missing, malformed, or revoked bearer token."
  }
}
```

Status code mapping: `400` (`BAD_REQUEST` malformed Snappy/Protobuf/JSON), `401` (`UNAUTHORIZED`), `403` (`FORBIDDEN`), `405` (wrong HTTP verb), `413` (`PAYLOAD_TOO_LARGE` >16 MiB), `422` (`VALIDATION_ERROR` invalid `site`/`device_role`), `429` (`RATE_LIMITED`), `502`/`503` (`UPSTREAM_UNAVAILABLE`), `500` (`INTERNAL_ERROR` generic message, stack traces logged server-side only).

### 4. Authoritative Template Placeholders (`shared/alloy-templates/*.tmpl`)

All standalone Alloy templates use deterministic double-brace tokens rendered safely (escaped against injection) by `generate-agent-bundle`:
- `{{HUB_URL}}` — Base HTTPS URL without trailing slash (e.g. `https://monitoring.msp.example.com`)
- `{{AUTH_TOKEN}}` — Dedicated collector or tenant bearer token (`cms_v1_...`)
- `{{CUSTOMER}}` — Validated `customer` slug
- `{{SITE}}` — Validated `site` slug
- `{{COLLECTOR_ID}}` — Validated `collector_id` slug
- `{{SYSLOG_PORT}}` — Unprivileged UDP/TCP port (default `5514`)

---

## Code Style

### Schema Validation & Canonical Label Enforcement Pattern (Python 3)

```python
import re
from typing import Final

CUSTOMER_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]\Z")
SITE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]\Z")
COLLECTOR_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]\Z")
DEVICE_ROLES: Final[frozenset[str]] = frozenset({
    "ns8", "linux", "windows", "proxmox", "web",
    "snmp-network", "snmp-ups", "snmp-nas", "snmp-firewall", "snmp-printer",
})


def enforce_canonical_labels(
    raw_labels: dict[str, str],
    *,
    authoritative_customer: str,
    default_site: str,
    default_role: str,
    default_collector_id: str,
) -> dict[str, str]:
    """Strip spoofed tenant labels and return a canonical, lexicographically sorted label map."""
    if not CUSTOMER_RE.match(authoritative_customer):
        raise ValueError("Invalid authoritative customer slug")

    clean = {k: v for k, v in raw_labels.items() if k != "customer"}
    clean["customer"] = authoritative_customer

    site = clean.get("site") or default_site
    if not SITE_RE.match(site):
        raise ValueError(f"Invalid site label: {site!r}")
    clean["site"] = site

    role = clean.get("device_role") or default_role
    if role not in DEVICE_ROLES:
        raise ValueError(f"Invalid device_role label: {role!r}")
    clean["device_role"] = role

    collector_id = clean.get("collector_id") or default_collector_id
    if not COLLECTOR_RE.match(collector_id):
        raise ValueError(f"Invalid collector_id label: {collector_id!r}")
    clean["collector_id"] = collector_id

    return dict(sorted(clean.items()))
```

---

## Testing Strategy

- **Framework:** `pytest` (`python -m pytest tests/contract -v`) with `jsonschema 4.26.0` (`Draft7Validator`).
- **Schema Meta-Validation:** Every `shared/schemas/*.json` file must parse via `json.load`, pass `Draft7Validator.check_schema`, contain zero external file `$ref`s, and validate both positive fixtures and negative abuse-case fixtures (e.g., `customer: "Customer_A"` uppercase rejected, `customer: "../etc"` path traversal rejected, `storage_mode: "s3"` without `s3.bucket` rejected).
- **Rule Pack Contract Tests:** Parse all 6 `shared/rules/*.yml` files, assert balanced PromQL parentheses/braces, required `severity` and `category` labels, `summary` + `description` annotations, and `customer`/`site` preservation in `by (...)` clauses.
- **Dashboard Contract Tests:** Parse all 4 `shared/dashboards/*.json` files, verify `schemaVersion >= 39`, datasource UIDs `prometheus` and `loki`, and `$customer` / `$site` templating variables.
- **Line-Ending Gate:** Automated test fails if any tracked text file contains `\r\n`.

---

## Boundaries

- **Always:**
  - Use LF (`\n`) line endings in every schema, rule, dashboard, template, and script (`.gitattributes` enforced).
  - Keep every NS8 action schema in `shared/schemas/` 100% self-contained JSON Schema Draft-07 without external `$ref`s.
  - Redact secrets (`has_secret_key`, `token_prefix`, `has_auth_token`) in all `get-*` and `list-*` output schemas; return plaintext bearer tokens **only** on initial `save-tenant` creation or `rotate-token`.
- **Ask first:**
  - Adding a new mandatory label (increases Prometheus TSDB cardinality across >1,500 systems).
  - Changing existing `device_role` enum slugs or renaming JSON Schema required properties.
- **Never:**
  - Define or override `get-status` schemas or actions (violates NS8 Backend Rule #1).
  - Trust client-supplied `customer` labels or `X-Scope-OrgID` headers on ingest.
  - Include PII (employee names, passwords, raw credentials) in metric labels or log stream labels.

---

## Success Criteria

- [ ] All 47 JSON Schema files in `shared/schemas/` parse cleanly with `json.load` and pass `jsonschema.Draft7Validator.check_schema`.
- [ ] Positive and negative payload fixtures exist and pass for Hub and Collector action schemas (`configure-module`, `save-tenant`, `save-target`, `configure-alerting`, `create-silence`, `save-local-target`).
- [ ] All 6 rule packs in `shared/rules/`, all 4 dashboards in `shared/dashboards/`, and all 6 templates in `shared/alloy-templates/` conform to the canonical `customer`, `site`, `device_role`, and `collector_id` contract.
- [ ] Zero files in the repository contain CRLF (`\r\n`) line endings.
