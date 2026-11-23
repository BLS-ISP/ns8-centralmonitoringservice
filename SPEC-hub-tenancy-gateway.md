# Spec: `hub-tenancy-gateway` — Multi-Tenant Auth Gateway, Customer Isolation & Agent Onboarding

- **Module ID:** `hub-tenancy-gateway`
- **Depends on:** `telemetry-contract`, `hub-core`
- **Consumed by:** `hub-probes-alerting`, `hub-ui`

---

## Assumptions

1. Because no local `go` compiler is installed on the Windows engineering host while `Python 3.14.10` (`aiohttp 3.14.5`, `pytest 9.2.0`, `pytest-asyncio 1.5.0`, `cryptography 49.0.0`, `httpx 0.28.1`) is natively available, implementing the Hub Auth-Gateway in Python 3 (`aiohttp` + pure-Python Snappy & Protobuf wire-format codec with optional C-accelerated `python-snappy` inside Linux container) enables 100% native unit & integration testing on Windows **and** minimal memory footprint in `hub/gateway/Containerfile` (`python:3.12-slim`).
2. Tenant bearer tokens (`cms_v1_<43-char-urlsafe-random>`) are generated with `secrets.token_urlsafe(32)` (256-bit entropy) and stored **exclusively as salted SHA-256 / HMAC-SHA256 digests** in `state/tenants.json` (`0600`), keeping only an 11-char display prefix (`cms_v1_xxxx...`) for admin UI identification.
3. Customer portal isolation relies on **defense-in-depth at four independent layers**: (a) dedicated Grafana Organization per customer supporting multiple local `Viewer` and `Editor` accounts (never `Admin` or `isGrafanaAdmin`, with Grafana alerting/provisioning disabled for non-admins and `editable: false` server-proxied datasources), (b) `hub-gateway` (`:8080`) enforcing a strict read-only query allowlist on `/api/datasources/proxy/*` and blocking `/metrics/*`, (c) `prom-label-proxy` (`127.0.0.1:9095`) rewriting every PromQL AST selector via `X-Scope-OrgID`, and (d) Loki (`127.0.0.1:3100`, `auth_enabled: true`) partitioning index and chunks by `X-Scope-OrgID`.

---

## Objective

Build the security-critical multi-tenancy boundary inside `central-monitoring-hub`:
1. **`hub-gateway` HTTP Reverse Proxy, Ingest Enforcer (`127.0.0.1:8080`) & Loopback Relay (`127.0.0.1:9097`):** Authenticates collector bearer tokens, decodes and re-stamps Prometheus Remote Write (`POST /api/v1/write`) and Loki Push (`POST /loki/api/v1/push`) payloads so a token for Customer A can **never** spoof or overwrite Customer B's telemetry, proxies browser/WebSocket traffic (`/*` & `/api/live/ws`) to internal Grafana (`127.0.0.1:3000`) while blocking `/metrics/*` and mutating `/api/datasources/proxy/*` subpaths, and serves pod-internal `/alert-relay/{ntfy|gotify}` plus `GET /metrics/ns8-node` (`state/textfile/ns8-hub-node.prom`) strictly on `127.0.0.1:9097`.
2. **Grafana Multi-Org, 1-Way MSP Simulation & Live NS8 LDAP/AD Multi-Select Sync:** Automatically provisions/updates MSP Main Org (Org 1, full Prometheus/Thanos + pipe-joined multi-tenant Loki `X-Scope-OrgID: t1|t2|...|_msp_internal` + Org Home Dashboard `ns8-multi-cluster-overview` + NS8 `Ldapproxy` multi-select group & user SSO), syncs genuine MSP staff 1-way into active Customer Orgs (`Admin` -> `Admin`, `Editor`/`Viewer` -> Read-Only `Viewer`) for 1-click `?orgId=<id>` support simulation, and manages strictly isolated multi-user Customer Organizations (`list-portal-users`, `save-portal-user`, `delete-portal-user`).
3. **Tenant Lifecycle, Live Directory Discovery & 1-Click Standalone Agent Generator:** Implements all **10** tenancy/SSO/onboarding NS8 actions (`list-tenants`, `save-tenant`, `delete-tenant`, `rotate-token`, `generate-agent-bundle`, `discover-ldap-groups`, `test-ldap-user`, `list-portal-users`, `save-portal-user`, `delete-portal-user`).

---

## Tech Stack

- **Gateway Service:** Python 3.12+ (`aiohttp` async HTTP server/client + WebSocket proxy, pure-Python Snappy framing/block codec & Protobuf varint/length-delimited `WriteRequest` / `PushRequest` wire codec).
- **PromQL AST Isolation:** `quay.io/prometheuscommunity/prom-label-proxy:v0.11.0` (`--label=customer --header-name=X-Scope-OrgID --upstream=${PROMQL_UPSTREAM_URL} --insecure-listen-address=127.0.0.1:9095 --enable-label-apis=true`).
- **LDAP Discovery:** NS8 Python `agent.ldapproxy.Ldapproxy` connecting from Grafana container to `10.0.2.2:<ldap_port>`.
- **Detected Local Host Runtimes (Windows):**
  - `Python 3.14.10` (`aiohttp 3.14.5`, `pytest 9.2.0`, `pytest-asyncio 1.5.0`, `httpx 0.28.1`, `jsonschema 4.26.0`, `cryptography 49.0.0`), `docker.exe`.

---

## Commands

```powershell
# Run gateway unit, Snappy/Protobuf wire-stamping, abuse-case, and tenant action tests locally
python -m pytest tests/hub_tenancy_gateway -v

# Validate tenancy & onboarding schemas
python -c "import json, jsonschema; [jsonschema.Draft7Validator.check_schema(json.load(open(f'shared/schemas/hub-{a}-{d}.json', encoding='utf-8'))) for a in ('list-tenants','save-tenant','delete-tenant','rotate-token','generate-agent-bundle') for d in ('input','output')]; print('Tenancy schemas valid')"

# Compile-check gateway and NS8 action Python modules
python -c "import glob, py_compile; [py_compile.compile(f, doraise=True) for f in glob.glob('hub/gateway/**/*.py', recursive=True)]"
```

---

## Project Structure

```text
hub/
  gateway/
    Containerfile                      -> Minimal rootless-compatible Python 3.12-slim image running hub_gateway
    hub_gateway/
      __init__.py
      app.py                           -> aiohttp server (:8080): /api/v1/write, /loki/api/v1/push, /api/v1/ingest/verify, /* -> Grafana
      auth.py                          -> Constant-time token SHA-256 lookup, grace-period check, per-IP auth rate limiter
      snappy_codec.py                  -> Pure-Python Snappy block decompress/compress (with optional C snappy fast-path)
      prom_remote_write.py             -> Protobuf WriteRequest parser/serializer enforcing authoritative customer/site/role labels
      loki_push.py                     -> JSON & Snappy+Protobuf logproto.PushRequest stream label enforcer + X-Scope-OrgID injection
      proxy.py                         -> Safe Grafana HTTP + WebSocket (/api/live/ws) proxy with /metrics/* block & read-only datasource proxy allowlist
      alert_relay.py                   -> Internal loopback (:9097) Ntfy/Gotify push relay + GET /metrics/ns8-node exporter endpoint
  imageroot/
    pypkg/
      hub_tenancy/
        store.py                       -> Atomic file-locked CRUD on state/tenants.json & portal users (0600) + token hashing/rotation
        grafana_sync.py                -> Idempotent Grafana 11 HTTP API client syncing Org 1, Customer Orgs, 6 dashboards, Org Home Dashboard & 1-way MSP staff
        ldap_client.py                 -> Pure-Python RFC 4511 LDAPv3 client for AD & RFC2307 group + user discovery and login role simulation
        ldap_sync.py                   -> Queries agent.ldapproxy.Ldapproxy, resolves multi-principal DNs & renders multi-org ldap.toml
        bundle_renderer.py             -> Renders shared/alloy-templates/*.tmpl with strict escaping
    actions/
      list-tenants/                    -> validate-input.json, validate-output.json, 20read
      save-tenant/                     -> validate-input.json, validate-output.json, 20save
      delete-tenant/                   -> validate-input.json, validate-output.json, 20delete
      rotate-token/                    -> validate-input.json, validate-output.json, 20rotate
      generate-agent-bundle/           -> validate-input.json, validate-output.json, 20generate
      discover-ldap-groups/            -> validate-input.json, validate-output.json, 20discover
      test-ldap-user/                  -> validate-input.json, validate-output.json, 20test
      list-portal-users/               -> validate-input.json, validate-output.json, 20read
      save-portal-user/                -> validate-input.json, validate-output.json, 20save
      delete-portal-user/              -> validate-input.json, validate-output.json, 20delete
tests/
  hub_tenancy_gateway/                 -> Unit, async HTTP integration, and cross-tenant spoofing security tests
```

---

## Threat Model & Security Architecture (STRIDE)

| Threat | Attack Scenario | Mandatory Control |
| :--- | :--- | :--- |
| **Spoofing** | Compromised collector at Customer A sends `customer="customer-b"` in Prometheus `WriteRequest` or `X-Scope-OrgID: customer-b` in Loki push | `hub-gateway` strips `X-Scope-OrgID`, decodes `WriteRequest` & Loki `PushRequest` stream labels, **deletes** any client `customer` label, and injects `customer=<token.customer>` server-side before forwarding. |
| **Elevation / IDOR** | Customer Portal Viewer in Grafana Org `acme-corp` calls `/api/datasources/proxy/uid/prometheus/api/v1/query?query=up{customer="beta"}` | Grafana datasource is `access: "proxy"`, `editable: false`, injecting `X-Scope-OrgID: acme-corp` to `127.0.0.1:9095` (`prom-label-proxy`), which parses the PromQL AST and rewrites the selector to `up{customer="acme-corp"}`. |
| **Information Disclosure** | Brute-force guessing of bearer tokens or reading plaintext tokens from disk/logs/API | 256-bit `cms_v1_` tokens compared via `hmac.compare_digest` on SHA-256 hashes; never logged; redacted to `token_prefix` in `list-tenants`; failed auth rate-limited per client IP (`X-Forwarded-For` from local Traefik, 20 failures / 5 min -> `429`). |
| **DoS (Zip Bomb)** | Attacker with valid token sends 5 MiB Snappy payload decompressing to 2 GiB | `hub-gateway` caps compressed request body at `16 MiB` (`413`) **and** enforces uncompressed Snappy output cap of `64 MiB` (`413`) before allocating buffers. |
| **Template Injection** | Malicious string in `collector_id` escapes Alloy River config or PowerShell/Bash installer | `save-tenant` and `generate-agent-bundle` strictly validate regexes (`^[a-z0-9]...$`) at the schema boundary **and** quote/escape placeholders during rendering. |

---

## Grafana Multi-Org & LDAP Provisioning Contract

1. **MSP Main Org (Org ID `1`):**
   - Datasource `Prometheus` (`uid: "prometheus"`, `isDefault: true`, `editable: false`): URL `${PROMQL_UPSTREAM_URL}` (`http://127.0.0.1:9090` in `local` mode; `http://127.0.0.1:10902` Thanos Query in `s3` mode).
   - Datasource `Loki` (`uid: "loki"`, `editable: false`): URL `http://127.0.0.1:3100` with `httpHeaderName1: "X-Scope-OrgID"` and `secureJsonData.httpHeaderValue1` set to the pipe-joined list of all registered tenant slugs plus `_msp_internal` (e.g., `acme-corp|beta-gmbh|_msp_internal`). Re-synced automatically on every `save-tenant` / `delete-tenant`!
   - Dashboards & Home Page: All **6** Enterprise NOC JSON models (`117` panels) from `shared/dashboards/` (`ns8-multi-cluster-overview.json`, `ns8-pods-and-modules.json`, `linux-windows-servers.json`, `proxmox-snmp-infrastructure.json`, `web-ssl-uptime.json`, `central-log-explorer.json`) provisioned/reloaded via `POST /api/admin/provisioning/dashboards/reload` (ignoring Grafana 11 `400 Cannot save provisioned dashboard` on file-provisioned Org 1), with Org Home Dashboard set to `ns8-multi-cluster-overview`.
   - **NS8 LDAP/AD SSO (`ldap_enabled == true`) + Multi-Select Group & User Discovery + Login Tester:**
     - Queries `Ldapproxy().get_domain(ldap_domain)`, maps host `10.0.2.2` and proxy port into `/etc/grafana/ldap.toml` (mounted via parent directory `--volume=%E/config/grafana:/etc/grafana:ro,z` so atomic `os.replace` updates take effect immediately without stale inodes).
     - Maps multi-select `ldap_admin_principals` -> Org 1 `Admin` (`grafana_admin = true` on Org 1; `Admin` on active Customer Orgs `c_oid > 1`), `ldap_editor_principals` -> Org 1 `Editor` (`Viewer` on Customer Orgs `c_oid > 1`), and `ldap_viewer_principals` -> Org 1 `Viewer` (`Viewer` on Customer Orgs `c_oid > 1`), accepting multiple AD/LDAP groups **and/or** individual AD/LDAP users (short names or full DNs up to 512 chars).
     - Uses source-grounded Grafana `ldap.go` `group_search_filter` + `member_of = "distinguishedName"` (AD, matching both `member:1.2.840.113556.1.4.1941:=%s` groups and `(&(objectClass=user)(distinguishedName=%s))` direct users) or `member_of = "dn"` (OpenLDAP/RFC2307), with **no** wildcard `group_dn = "*"` fallback.
     - `discover-ldap-groups` connects via `Ldapproxy` (`127.0.0.1:<port>`) to enumerate both directory `groups` (`{name, dn, description}`) and non-computer directory `users` (`{username, display_name, email, dn}`).
     - `test-ldap-user` accepts `ldap_*_principals` (plus legacy singular `ldap_*_group`), evaluates priority `Admin` -> `Editor` -> `Viewer` across both direct user DN matches and group memberships, and returns `{ok, found, username, user_dn, display_name, email, member_of, matched_role, grafana_admin, message}`.
2. **Customer Portal Organization & Multi-User Account Management (`customer_portal_enabled == true`):**
   - Dedicated Grafana Org named `Customer: <display_name> (<customer>)`.
   - Datasource `Prometheus` (`uid: "prometheus"`, `access: "proxy"`, `editable: false`): URL `http://127.0.0.1:9095` (`prom-label-proxy`), `httpHeaderName1: "X-Scope-OrgID"`, `secureJsonData.httpHeaderValue1: "<customer>"`.
   - Datasource `Loki` (`uid: "loki"`, `access: "proxy"`, `editable: false`): URL `http://127.0.0.1:3100`, `httpHeaderName1: "X-Scope-OrgID"`, `secureJsonData.httpHeaderValue1: "<customer>"`.
   - **Multi-User Accounts (`list-portal-users`, `save-portal-user`, `delete-portal-user`):**
     - Supports multiple local Grafana accounts per tenant (`role`: `"Viewer"` or `"Editor"` scoped **strictly** to that tenant's Customer Org, never `Admin`, never `isGrafanaAdmin`, and **always** evicted from Org 1 and all other Customer Orgs!). Because datasources are `editable: false` and `hub-gateway` restricts `/api/datasources/proxy/*` strictly to read-only query paths, even Customer Org `Editor`s (who can build/customize dashboards inside their own Customer Org) can **never** query or write another tenant's metrics or logs!
     - Usernames (`^[a-zA-Z0-9._-]{3,64}$`) enforce global case-insensitive uniqueness across all tenants and block reserved names (`admin`, `root`, `GRAFANA_ADMIN_USER`).
     - Supports `disabled: true|false` per user and `password_unchanged: true` on edits; `list-tenants` exposes `portal_users_count` plus backward-compatible primary `portal_viewer_username` and `grafana_login_url`.
   - Copies of all **6** Enterprise NOC dashboards (`117` panels) imported into each Customer Org with `$customer` locked/hidden (`type="constant"`, `hide=2`) to `<customer>` while leaving `$site`, `$instance`, `$module_id`, `$device_role`, `$job`, `$level`, and `$log_search` interactive, and setting Org Home Dashboard to `ns8-multi-cluster-overview`.
   - **1-Way MSP Staff Support Simulation (`?orgId=<id>`):** Genuine MSP Org-1 accounts (`admin`, `isGrafanaAdmin`, or external LDAP users — never customer portal accounts) are synced one-way into active Customer Orgs (`Admin` -> `Admin`; MSP `Editor`/`Viewer` -> Read-Only `Viewer`) without changing their default Org 1 context.
   - Toggling `customer_portal_enabled` to `false` disables/evicts all portal users' access immediately without deleting historical TSDB/Loki telemetry.

---

## Code Style

### Constant-Time Token Verification & Protobuf `WriteRequest` Tenant Stamping

```python
import hashlib
import hmac
from hub_gateway.prom_remote_write import rewrite_write_request_labels
from hub_gateway.snappy_codec import snappy_compress, snappy_decompress

MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024


def verify_bearer_token(raw_token: str, token_records: list[dict]) -> dict | None:
    candidate_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    matched: dict | None = None
    for rec in token_records:
        if hmac.compare_digest(candidate_digest, rec["sha256"]):
            matched = rec
    return matched


def process_remote_write(compressed_body: bytes, token_meta: dict) -> bytes:
    raw_pb = snappy_decompress(compressed_body, max_length=MAX_DECOMPRESSED_BYTES)
    stamped_pb = rewrite_write_request_labels(
        raw_pb,
        authoritative_customer=token_meta["customer"],
        allowed_sites=frozenset(token_meta["sites"]),
        default_site=token_meta["default_site"],
        default_collector_id=token_meta.get("collector_id") or f"{token_meta['customer']}-push",
    )
    return snappy_compress(stamped_pb)
```

---

## Testing Strategy

- **Framework:** `pytest` + `pytest-asyncio` (`python -m pytest tests/hub_tenancy_gateway -v`).
- **Mandatory Security & Abuse-Case Tests:**
  1. **Cross-Tenant Metric Spoofing Test:** Build a Snappy+Protobuf `WriteRequest` containing `up{customer="victim-corp", site="hq", device_role="linux", collector_id="c1"} 1` authenticated with `attacker-corp`'s token; assert the upstream mock Prometheus receives `customer="attacker-corp"` (sorted lexicographically) and **never** `"victim-corp"`.
  2. **Cross-Tenant Loki Header & Stream Spoofing Test:** Send `POST /loki/api/v1/push` with header `X-Scope-OrgID: victim-corp` and stream `{customer="victim-corp", job="syslog"}` using `attacker-corp`'s token; assert upstream mock Loki receives `X-Scope-OrgID: attacker-corp` and stream `{customer="attacker-corp", ...}`.
  3. **Internal Admin Endpoint Block Test:** Request `GET /api/v1/query`, `POST /-/reload`, or `GET /metrics` through `:8080` and assert Prometheus/Loki/Alertmanager admin routes are never exposed (routed only to Grafana `:3000` or rejected).
  4. **Decompression Bomb Test:** Assert Snappy payloads declaring >64 MiB uncompressed length abort immediately with HTTP `413`.
  5. **Token Rotation Grace Window Test:** Rotate token with `grace_period_minutes=60` -> both old and new tokens authenticate; rotate with `grace_period_minutes=0` -> old token immediately returns `401`.
  6. **Agent Bundle Renderer Test:** Render `linux`, `windows`, and `docker` bundles via `generate-agent-bundle`, verify zero unreplaced `{{...}}` placeholders and valid output against `hub-generate-agent-bundle-output.json`.

---

## Boundaries

- **Always:**
  - Hash every bearer token with SHA-256 before writing to disk; compare digests with `hmac.compare_digest`.
  - Enforce all 8 NS8 backend rules in `list-tenants`, `save-tenant`, `delete-tenant`, `rotate-token`, and `generate-agent-bundle`.
  - Reload `hub-gateway`'s in-memory token table automatically on file mtime change or `SIGHUP` without dropping in-flight requests.
- **Ask first:**
  - Granting `Admin` or `isGrafanaAdmin` to any Customer Portal local account (Customer Portal roles are strictly bounded to `Viewer` and `Editor` with non-editable datasources).
  - Exposing any additional unauthenticated path on `hub-gateway`.
- **Never:**
  - Return full bearer tokens from `list-tenants` or `get-configuration`.
  - Expose `prom-label-proxy` (`:9095`), Prometheus (`:9090`), Thanos (`:10902`), Loki (`:3100`), or internal relay/metrics (`:9097`) directly on host ports or `:8080` public routes.

---

## Success Criteria

- [ ] `POST /api/v1/write` and `POST /loki/api/v1/push` pass end-to-end async integration tests including cross-tenant spoofing rejection/overwriting, rightmost `X-Forwarded-For` rate limiting, `/metrics/*` & `/api/datasources/proxy/*` write/config blocking, and decompression-cap enforcement.
- [ ] All **10** tenancy/LDAP/portal NS8 actions (`list-tenants`, `save-tenant`, `delete-tenant`, `rotate-token`, `generate-agent-bundle`, `discover-ldap-groups`, `test-ldap-user`, `list-portal-users`, `save-portal-user`, `delete-portal-user`) validate cleanly against `shared/schemas/hub-*.json`.
- [ ] Grafana sync logic deterministically provisions Org 1 (full PromQL + pipe-joined multi-tenant Loki + multi-principal `ldap.toml` + 6 dashboards) and Customer Orgs (multi-user `Viewer`/`Editor` + 1-way MSP simulation + `prom-label-proxy` + single-tenant Loki + 6 locked dashboards).
- [ ] `generate-agent-bundle` produces complete, valid Alloy configs and hardened 1-click installers for `linux`, `windows`, and `docker` from `shared/alloy-templates/`.
