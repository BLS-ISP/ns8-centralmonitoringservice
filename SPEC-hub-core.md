# Spec: `hub-core` — Rootless NS8 Module `central-monitoring-hub` Core Stack & Storage

- **Module ID:** `hub-core`
- **Depends on:** `telemetry-contract`
- **Consumed by:** `hub-tenancy-gateway`, `hub-probes-alerting`, `hub-ui`

---

## Assumptions

1. `central-monitoring-hub` runs as an unprivileged NethServer 8 rootless module user (e.g., `central-monitoring-hub1`) on Rocky Linux 9 / Debian 12 NS8 nodes using rootless Podman and `systemd --user`, with zero modifications to NS8's built-in `ns8-metrics` module.
2. Inside the shared Podman pod `central-monitoring-hub-pod`, containers communicate over `127.0.0.1` on dedicated non-overlapping ports; **only** `127.0.0.1:${TCP_PORT}:8080` is published to the NS8 node loopback for Traefik reverse-proxying.
3. For >1,500 monitored systems and multi-month retention, administrators can toggle `storage_mode` between `"local"` (Podman named volumes) and `"s3"` (S3/MinIO object storage using Loki's native TSDB S3 backend plus **Thanos Sidecar + Thanos Store Gateway + Thanos Query**).
4. Daily NS8 Restic cluster backups must stay fast and consistent by default (`backup_include_tsdb: false`), backing up configurations, tenants/tokens, targets, rules, silences, and an online SQLite `.backup` of `grafana.db`, while allowing raw TSDB volume backup opt-in via `backup_include_tsdb: true`.

---

## Objective

Implement the standalone rootless NethServer 8 Software Center module `central-monitoring-hub` (`hub/`): full NS8 lifecycle (`create-module`, `configure-module`, `get-configuration`, `get-overview`, `destroy-module`, `restore-module`, `clone-module`, `update-module.d`), Traefik FQDN/ACME routing with hostname-collision checks, Restic state dump/restore, and the core multi-container Podman pod (**Prometheus**, **Loki**, **Grafana OSS**, **Alertmanager**, plus **Thanos Sidecar/Store/Query** when `storage_mode == "s3"`).

---

## Tech Stack

- **NS8 Runtime:** Python 3 (`/usr/local/agent/pypkg/agent`), Bash, `systemd --user`, Rootless Podman (`--network=slirp4netns:allow_host_loopback=true` so `10.0.2.2` reaches host `ns8-ldapproxy` and Smarthost).
- **Pinned Container Images (`org.nethserver.images` label in `hub/Containerfile`):**
  - `ghcr.io/<org>/central-monitoring-hub-gateway:<tag>` (built from `hub/gateway/Containerfile`, Python 3.12-slim + `aiohttp`)
  - `quay.io/prometheus/prometheus:v2.54.1`
  - `quay.io/prometheus/alertmanager:v0.27.0`
  - `docker.io/grafana/loki:3.1.1`
  - `docker.io/grafana/grafana-oss:11.2.2`
  - `quay.io/prometheuscommunity/prom-label-proxy:v0.11.0`
  - `quay.io/prometheus/blackbox-exporter:v0.25.0`
  - `quay.io/prometheus/snmp-exporter:v0.26.0`
  - `quay.io/thanos/thanos:v0.36.1`
- **Detected Local Host Runtimes (Windows):**
  - `Python 3.14.10` (`pytest 9.2.0`, `jsonschema 4.26.0`, `sqlite3 3.50.4`), `Node.js v26.13.1`, `npm 11.20.0`, `git 2.56.0.windows.4`, `docker.exe` (`go` not installed locally).

---

## Commands

```powershell
# Run Hub backend action, config-renderer, backup/restore & systemd unit tests locally on Windows
python -m pytest tests/hub_core -v

# Validate all Hub NS8 action schemas against shared/schemas/
python -c "import glob, json, jsonschema; [jsonschema.Draft7Validator.check_schema(json.load(open(f, encoding='utf-8'))) for f in glob.glob('shared/schemas/hub-*.json')]; print('Hub schemas valid')"

# Check shell & Python scripts for LF line endings and syntax
python -c "import glob, py_compile; [py_compile.compile(f, doraise=True) for f in glob.glob('hub/imageroot/**/*.py', recursive=True)]"

# Build NS8 module image (on Linux CI / WSL / Docker)
bash hub/build-images.sh
```

---

## Project Structure

```text
hub/
  Containerfile                        -> NS8 module image packaging imageroot/ + ui/dist/ with LF strip & chmod +x
  build-images.sh                      -> Builds central-monitoring-hub and central-monitoring-hub-gateway images
  imageroot/
    etc/
      state-include.conf               -> Restic backup paths (config/, state/*.json, state/grafana.db.bak; conditional tsdb)
    bin/
      module-dump-state                -> Online SQLite backup of grafana.db + Alertmanager nflog/silences snapshot
      module-cleanup-state             -> Removes temporary grafana.db.bak after Restic snapshot completes
      discover-smarthost               -> Queries NS8 Redis cluster/smarthost and writes state/smarthost.env
      render-hub-configs               -> Renders prometheus.yml, loki.yaml, grafana.ini, objstore.yml atomically
    actions/
      create-module/
        20initialize                   -> Generates internal secrets, initial admin password, calls agent.dump_env()
      configure-module/
        validate-input.json            -> Exact copy of shared/schemas/hub-configure-module-input.json
        validate-output.json           -> Exact copy of shared/schemas/hub-configure-module-output.json
        01hostname-validation          -> Checks agent.http_route_in_use(domain); exits 2 with validation JSON on collision
        20configure                    -> Persists env, calls agent.dump_env(), renders configs, sets Traefik route
        80start_services               -> Enables/starts pod + core units + conditional Thanos units (s3 vs local)
      get-configuration/
        validate-input.json            -> Exact copy of shared/schemas/hub-get-configuration-input.json
        validate-output.json           -> Exact copy of shared/schemas/hub-get-configuration-output.json
        20read                         -> Reads config (redacting secrets), LDAP domains, and component health
      get-overview/
        validate-input.json            -> Exact copy of shared/schemas/hub-get-overview-input.json
        validate-output.json           -> Exact copy of shared/schemas/hub-get-overview-output.json
        20read                         -> Fast health, active series/alerts/tenants counts, and volume byte sizes
      restore-module/
        06copyenv                      -> Restores environment vars, calls agent.dump_env()
        50configure                    -> Restores grafana.db from grafana.db.bak, re-registers Traefik route, starts pod
      clone-module/
        50configure                    -> Regenerates MODULE_ID-specific secrets, clears/updates FQDN route, starts pod
      destroy-module/
        20destroy                      -> Removes Traefik route, stops systemd units, removes pod and volumes
    events/
      smarthost-changed/
        10reload_services              -> Refreshes smarthost.env, re-renders alertmanager.yml, reloads Alertmanager
      user-domain-changed/
        10handler                      -> Updates Grafana ldap.toml when NS8 Ldapproxy ports/domains change
    update-module.d/
      20pull_images                    -> Pulls updated container images during module upgrades (never in systemd!)
    systemd/user/
      central-monitoring-hub.service   -> Podman pod manager (-p 127.0.0.1:${TCP_PORT}:8080, slirp4netns host loopback)
      prometheus.service               -> Prometheus (:9090, --web.enable-remote-write-receiver, --web.enable-lifecycle)
      loki.service                     -> Loki (:3100 HTTP / :9096 gRPC, auth_enabled: true, TSDB v13 local or s3)
      alertmanager.service             -> Alertmanager (:9093, --cluster.listen-address="")
      grafana.service                  -> Grafana OSS (:3000, provisioning mounts, Readiness wait on Prometheus/Loki)
      prom-label-proxy.service         -> prom-label-proxy (:9095, --label=customer --header-name=X-Scope-OrgID)
      blackbox-exporter.service        -> Blackbox Exporter (:9115)
      snmp-exporter.service            -> SNMP Exporter (:9116)
      hub-gateway.service              -> Auth & Tenancy Gateway (:8080 ingress -> Grafana :3000 / Prom :9090 / Loki :3100)
      thanos-sidecar.service           -> Thanos Sidecar (:10912 HTTP / :10911 gRPC, active only in storage_mode=s3)
      thanos-store.service             -> Thanos Store Gateway (:10922 HTTP / :10921 gRPC, active only in storage_mode=s3)
      thanos-query.service             -> Thanos Query (:10902 HTTP / :10901 gRPC, active only in storage_mode=s3)
tests/
  hub_core/                            -> Unit & integration tests for Hub actions, config generation, S3/Thanos, backup
```

---

## Architectural Contracts & NS8 Compliance

### 1. Pod Port Allocation & Startup Ordering (NS8 Rules #3, #5, #6)

- **Pod Creation (`central-monitoring-hub.service`):**
  `podman pod create --infra-conmon-pidfile %t/central-monitoring-hub.pid --pod-id-file %t/central-monitoring-hub.pod-id --name central-monitoring-hub --publish 127.0.0.1:${TCP_PORT}:8080 --network=slirp4netns:allow_host_loopback=true --replace`
- **Internal Port Map (`127.0.0.1` inside pod):**
  - `:8080` -> `hub-gateway` (sole published port)
  - `:3000` -> `grafana`
  - `:3100` (HTTP), `:9096` (gRPC) -> `loki`
  - `:9090` -> `prometheus`
  - `:9093` -> `alertmanager`
  - `:9095` -> `prom-label-proxy` (`--upstream=${PROMQL_UPSTREAM_URL}`)
  - `:9115` -> `blackbox-exporter`
  - `:9116` -> `snmp-exporter`
  - `:10902` (HTTP), `:10901` (gRPC) -> `thanos-query` (`storage_mode == "s3"`)
  - `:10912` (HTTP), `:10911` (gRPC) -> `thanos-sidecar` (`storage_mode == "s3"`)
  - `:10922` (HTTP), `:10921` (gRPC) -> `thanos-store` (`storage_mode == "s3"`)
- **Readiness, Systemd `%E` Specifier, Directory Bind-Mounts & Python 3.9 Compatibility:**
  - All Python modules and NS8 action scripts inside `hub/imageroot/` and `hub/gateway/` **MUST** start with `from __future__ import annotations` and remain 100% compatible with Rocky Linux 9's system **Python 3.9** (zero PEP 701 nested/backslash f-strings, zero `@dataclass(slots=True)`, zero `write_text(..., newline=...)`, zero `datetime.UTC`).
  - Every `systemd/user/*.service` unit **MUST** reference NS8 config/state paths via `%E/` (`~/.config`, matching `AGENT_INSTALL_DIR=~/.config` and `AGENT_STATE_DIR=~/.config/state`), **NEVER** `%S/` (`~/.local/state`), mount **parent directories** with SELinux `:z` / `:ro,z` labels (never single-file bind mounts that pin stale inodes across `os.replace`), and pass `--user 0:0` on rootless containers reading `0600` host bind-mounted configs/secrets.
  - `configure-module` and `get-configuration` persist and expose multi-principal arrays `ldap_admin_principals`, `ldap_editor_principals`, and `ldap_viewer_principals` (encoded losslessly as URL-safe Base64 JSON in `LDAP_*_PRINCIPALS_B64` for `systemd EnvironmentFile` / `agent.dump_env()` safety) alongside backward-compatible singular `ldap_admin_group`, `ldap_editor_group`, and `ldap_viewer_group` (up to 512 chars each for full AD Distinguished Names).
  - Every container unit **MUST** use `--pull=missing` and `--restart=on-failure` (NS8 Rule #5: **NEVER** `--pull=always`).
  - `grafana.service`, `hub-gateway.service`, and `thanos-sidecar.service` include `ExecStartPre` readiness loops (`--entrypoint=python3 /wait-pod-endpoints ...`) polling `http://127.0.0.1:9090/-/ready` and `http://127.0.0.1:3100/ready` (bounded timeout 60s) plus backend HTTP connection retries with exponential backoff (NS8 Rule #6).

### 2. Storage Mode Switching (`local` vs. `s3` for >1,500 Systems)

- **`storage_mode == "local"` (Default):**
  - Prometheus stores TSDB in Podman volume `prometheus-data` with `--storage.tsdb.retention.time=${RETENTION_DAYS}d` (and `--storage.tsdb.retention.size=${RETENTION_SIZE_GB}GB` when `> 0`).
  - Loki uses TSDB schema `v13` with `object_store: filesystem` in `loki-data` and `compactor.retention_enabled: true` (`retention_period: ${LOKI_RETENTION_DAYS * 24}h`).
  - `thanos-sidecar.service`, `thanos-store.service`, and `thanos-query.service` are stopped and disabled.
  - `PROMQL_UPSTREAM_URL=http://127.0.0.1:9090` (queried by Grafana Org 1 and `prom-label-proxy`).
- **`storage_mode == "s3"`:**
  - `render-hub-configs` writes `/etc/thanos/objstore.yml` (`chmod 0600`, mounted into Thanos Sidecar & Store) and configures Loki `schema_config` (`store: tsdb`, `object_store: s3`, `schema: v13`) + `storage_config.aws` (`endpoint`, `bucketnames`, `region`, `access_key_id`, `secret_access_key`, `insecure`, `s3forcepathstyle`).
  - Prometheus runs with fixed 2-hour block durations (`--storage.tsdb.min-block-duration=2h --storage.tsdb.max-block-duration=2h`) and `external_labels: { cluster: "${MODULE_ID}", prometheus_replica: "0" }` required by `thanos-sidecar` to upload compacted 2h blocks to S3 without disabling compaction when sidecar only uploads raw 2h blocks.
  - `thanos-sidecar`, `thanos-store`, and `thanos-query` (`:10902`) are enabled and started.
  - `PROMQL_UPSTREAM_URL=http://127.0.0.1:10902` so both Grafana Org 1 and `prom-label-proxy` query real-time head data (via Sidecar) + historical S3 blocks (via Store Gateway) transparently!

### 3. Restic Backup, Restore & Clone (NS8 Rule #7)

- `imageroot/bin/module-dump-state` runs `podman exec grafana sqlite3 /var/lib/grafana/grafana.db ".backup '/var/lib/grafana/backup/grafana.db.bak'"` (moving snapshot into `state/grafana.db.bak`) so SQLite WAL state is 100% consistent without stopping Grafana.
- `imageroot/etc/state-include.conf` always includes `state/environment`, `state/secrets.env`, `state/tenants.json`, `state/portal-secrets.json`, `state/.portal.key`, `state/targets.json`, `state/alerting.json`, `state/silences.json`, `state/grafana.db.bak`, and `config/custom-rules/`. When `backup_include_tsdb == true`, `configure-module` appends `volumes/prometheus-data` and `volumes/loki-data` to `state-include.conf`; when `false`, it omits raw TSDB volumes.

### 4. All 8 Mandatory NS8 Backend Rules Enforced

1. **No `imageroot/actions/get-status` directory exists.** Custom health & metrics live in `get-configuration` and `get-overview`.
2. **`agent.dump_env()` is always called immediately after `agent.set_env()`** in `create-module/20initialize`, `configure-module/20configure`, `restore-module/06copyenv`, and `clone-module/50configure`.
3. **Host port bound strictly to `127.0.0.1:${TCP_PORT}:8080`** and registered with Traefik `set-route`.
4. **`configure-module/01hostname-validation`** checks `agent.http_route_in_use(domain=host)` when `host != os.environ.get("TRAEFIK_HOST", "")`, calling `agent.set_status("validation-failed")`, printing `[{"field":"host","parameter":"host","value":host,"error":"domain_already_used"}]` to `sys.stdout`, and exiting with `sys.exit(2)`.
5. **`--pull=missing` in all `.service` units**; all 9 container images declared in `org.nethserver.images` in `hub/Containerfile`.
6. **Multi-container startup readiness loops** in `ExecStartPre` + retry backoff.
7. **Complete Restic backup, restore & clone actions** (`state-include.conf`, `module-dump-state`, `module-cleanup-state`, `restore-module`, `clone-module`).
8. **LF line endings & `+x` permissions** enforced both in `.gitattributes` and via explicit `sed -i 's/\r$//'` + `chmod +x` inside `hub/Containerfile`.

---

## Code Style

### NS8 `configure-module` Hostname Validation & `agent.dump_env()` Pattern

```python
#!/usr/bin/env python3
import json
import os
import sys
import agent

request = json.load(sys.stdin)
new_host = request["host"].strip().lower()
current_host = os.environ.get("TRAEFIK_HOST", "").strip().lower()

# NS8 Rule #4: Validate Traefik hostname collisions before mutating state
if new_host != current_host and agent.http_route_in_use(domain=new_host):
    agent.set_status("validation-failed")
    json.dump(
        [{"field": "host", "parameter": "host", "value": new_host, "error": "domain_already_used"}],
        sys.stdout,
    )
    sys.exit(2)

agent.set_env("TRAEFIK_HOST", new_host)
agent.set_env("STORAGE_MODE", request["storage_mode"])
agent.set_env(
    "PROMQL_UPSTREAM_URL",
    "http://127.0.0.1:10902" if request["storage_mode"] == "s3" else "http://127.0.0.1:9090",
)
# NS8 Rule #2: Flush environment to disk BEFORE 80start_services restarts systemd units!
agent.dump_env()
```

### Mandatory `hub/Containerfile` Permissions & CRLF Sanitization Block

```dockerfile
RUN find /imageroot -name "__pycache__" -type d -exec rm -rf {} + && \
    find /imageroot -name "*.pyc" -delete && \
    find /imageroot -type f -exec sed -i 's/\r$//' {} + && \
    chmod +x /imageroot/actions/*/[0-9]* /imageroot/update-module.d/* /imageroot/bin/* /imageroot/events/*/[0-9]*
```

---

## Testing Strategy

- **Framework:** `pytest` (`python -m pytest tests/hub_core -v`) using a lightweight mock `agent` fixture simulating NS8 environment files, Redis keys, and `agent.tasks.run`.
- **Unit Tests:**
  - Verify `01hostname-validation` exits `2` with NS8 validation JSON when `http_route_in_use` returns `True`, and passes when saving unchanged `host`.
  - Verify `20configure` calls `agent.dump_env()`, sets `PROMQL_UPSTREAM_URL` to `:9090` (`local`) vs `:10902` (`s3`), never leaks `s3.secret_key` or `grafana_admin_password` in `get-configuration`, and preserves secrets when `*_unchanged=True`.
  - Verify `render-hub-configs` generates valid `prometheus.yml`, `loki.yaml` (`auth_enabled: true`, `querier.multi_tenant_queries_enabled: true`, TSDB `v13`), and Thanos `objstore.yml`.
  - Static audit test asserting `hub/imageroot/actions/get-status` does **not** exist, no `.service` file contains `--pull=always`, and every port binding uses `127.0.0.1`.

---

## Boundaries

- **Always:**
  - Bind host ports exclusively to `127.0.0.1:${TCP_PORT}` and keep Prometheus/Loki/Alertmanager/Thanos bound to `127.0.0.1` inside the pod.
  - Store `secrets.env` and `objstore.yml` with `0600` file permissions.
  - Provision starter dashboards from `shared/dashboards/` into Grafana cleanly on startup.
- **Ask first:**
  - Adding any additional container image to `central-monitoring-hub-pod`.
  - Changing Prometheus TSDB block duration flags (affects Thanos Sidecar compatibility).
- **Never:**
  - Create `imageroot/actions/get-status`.
  - Use `--pull=always` in `imageroot/systemd/user/*.service`.
  - Modify or conflict with NS8's built-in `ns8-metrics` module.

---

## Success Criteria

- [ ] `hub/imageroot/` passes all 8 NS8 architectural audit checks via automated `pytest` tests.
- [ ] `configure-module`, `get-configuration`, and `get-overview` inputs and outputs validate cleanly against `shared/schemas/hub-*.json`.
- [ ] Toggling `storage_mode` between `"local"` and `"s3"` switches Loki storage config, Thanos systemd units, and `PROMQL_UPSTREAM_URL` (`:9090` <-> `:10902`) deterministically without data loss.
- [ ] `state-include.conf`, `module-dump-state`, `restore-module`, and `clone-module` cleanly preserve and restore tenants, targets, rules, silences, and `grafana.db` while respecting `backup_include_tsdb`.
