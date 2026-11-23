# Spec: `site-collector` — Rootless NS8 Module `central-monitoring-collector` (Grafana Alloy)

- **Module ID:** `site-collector`
- **Depends on:** `telemetry-contract`
- **Consumed by:** Customer NS8 Clusters pushing metrics & logs to `central-monitoring-hub`

---

## Assumptions

1. Customer NethServer 8 clusters often sit behind NAT/CGNAT firewalls and use overlapping RFC1918 LAN subnets (e.g., `192.168.1.0/24`); therefore `central-monitoring-collector` requires **zero inbound WAN ports** and pushes all metrics (`POST /api/v1/write`) and logs (`POST /loki/api/v1/push`) outbound over HTTPS (`TCP/443`) authenticated by a tenant/collector bearer token.
2. `central-monitoring-collector` runs 100% rootless under its own NS8 module user without touching or conflicting with NS8's built-in `ns8-metrics` module. Because it does not serve a public web application, it does **not** require a Traefik FQDN route; all administration happens inside the NS8 Cluster-Admin Cockpit UI (`collector/ui/`).
3. **Grafana Alloy (`v1.4.2`)** provides built-in `prometheus.exporter.unix`, `prometheus.exporter.snmp` (v2c & v3), `loki.source.syslog` (UDP/TCP), `loki.source.journal`, and disk-backed Write-Ahead-Log (`prometheus.remote_write` WAL + `loki.write` WAL). For **Proxmox VE** targets in the customer LAN, a lightweight on-demand sidecar `prompve/prometheus-pve-exporter:3.4.5` (`127.0.0.1:9221` inside the collector pod) translates Proxmox API queries into Prometheus metrics scraped by Alloy.

---

## Objective

Implement the standalone, lightweight rootless NethServer 8 Software Center module `central-monitoring-collector` (`collector/`) including its compact bilingual (`en`/`de`) Cockpit UI:
1. **Zero-Touch Local NS8 Telemetry (`collect_local_ns8: true`):** Collects host CPU, RAM, swap, filesystem/inodes, disk I/O, mdadm RAID (`prometheus.exporter.unix` over read-only `/host/proc`, `/host/sys`, `/host/root`), NS8 Restic backup status, systemd unit failures, and NS8 module container inventory (`ns8-collector-textfile.timer` writing `ns8.prom`), plus local journal logs (`loki.source.journal`).
2. **Customer LAN Appliance & Server Scraping (`list-local-targets`, `save-local-target`, `delete-local-target`):** Scrapes LAN **Proxmox VE** nodes/clusters, **Windows Servers** (`windows_exporter` `:9182`), **Linux Servers** (`node_exporter` `:9100`), **SNMP v2c/v3** switches/firewalls/UPS/NAS (`if_mib`, `apcupsd`, `synology`, `generic`), and custom HTTP exporters, plus an optional unprivileged UDP/TCP **Syslog Receiver** (`enable_syslog_receiver`, default port `5514`) for closed LAN appliances.
3. **Resilient Offline WAL Buffering & Connection Verification (`configure-module`, `get-configuration`, `test-hub-connection`):** Buffers metrics and logs to a bounded local Podman volume (`wal_max_disk_mb`) during internet outages and replays automatically upon reconnection, stamping canonical `customer`, `site`, `device_role`, and `collector_id` labels on every sample and log line.

---

## Tech Stack

- **NS8 Backend Runtime:** Python 3 (`/usr/local/agent/pypkg/agent`), Bash, `systemd --user`, Rootless Podman (`--network=slirp4netns:allow_host_loopback=true`).
- **Pinned Container Images (`org.nethserver.images` in `collector/Containerfile`):**
  - `docker.io/grafana/alloy:v1.4.2` (`127.0.0.1:12345` inside pod for health/ready checks)
  - `docker.io/prompve/prometheus-pve-exporter:3.4.5` (`127.0.0.1:9221` inside pod, enabled automatically when `>= 1` enabled `proxmox` target exists)
- **Cockpit UI (`collector/ui/`):** Vue `^2.7.16`, `@vue/cli-service` (`^5.0.8`), `@nethserver/ns8-ui-lib`, `@carbon/vue`, `@carbon/icons-vue`, `vue-i18n` (`en` + `de`).
- **Detected Local Host Runtimes (Windows):**
  - `Python 3.14.10` (`pytest 9.2.0`, `jsonschema 4.26.0`, `httpx 0.28.1`), `Node.js v26.13.1`, `npm 11.20.0`, `git 2.56.0.windows.4`, `docker.exe`.

---

## Commands

```powershell
# Run Collector backend action, Alloy River config-generator, NS8 textfile, and connection-test suite locally
python -m pytest tests/site_collector -v

# Validate all 12 Collector Draft-07 JSON Schemas
python -c "import glob, json, jsonschema; files = sorted(glob.glob('shared/schemas/collector-*.json')); assert len(files) == 12; [jsonschema.Draft7Validator.check_schema(json.load(open(f, encoding='utf-8'))) for f in files]; print('Collector schemas valid')"

# Install & build Collector Cockpit UI
npm --prefix collector/ui install
npm --prefix collector/ui run build
```

---

## Project Structure

```text
collector/
  Containerfile                        -> NS8 module image packaging imageroot/ + ui/dist/ with LF strip & chmod +x
  build-images.sh                      -> Builds central-monitoring-collector image
  imageroot/
    etc/
      state-include.conf               -> Backs up state/environment, state/secrets.env, state/local-targets.json (excludes transient WAL!)
    bin/
      module-dump-state                -> No-op / config snapshot verification hook for Restic consistency
      module-cleanup-state             -> Cleanup hook after Restic snapshot
      collect-ns8-metrics              -> Writes atomic ~/.config/state/textfile/ns8.prom (backups, containers, systemd units)
      render-alloy-config              -> Renders ~/.config/state/config.alloy + pve.yml (0600) from env & local-targets.json
    pypkg/
      collector_lib/
        alloy_renderer.py              -> Deterministic Grafana Alloy River generator + SNMP/PVE/Syslog/WAL blocks
        targets_store.py               -> Atomic CRUD on state/local-targets.json (0600)
        hub_probe.py                   -> HTTPS GET /api/v1/ingest/verify probe with latency & TLS verification
    actions/
      create-module/
        20initialize                   -> Initializes default settings, collector_id, calls agent.dump_env()
      configure-module/
        validate-input.json            -> Exact copy of shared/schemas/collector-configure-module-input.json
        validate-output.json           -> Exact copy of shared/schemas/collector-configure-module-output.json
        20configure                    -> Persists env & token (0600), calls agent.dump_env(), renders config.alloy
        80start_services               -> Starts/reloads pod, alloy.service, optional pve-exporter.service & syslog port
      get-configuration/
        validate-input.json            -> Exact copy of shared/schemas/collector-get-configuration-input.json
        validate-output.json           -> Exact copy of shared/schemas/collector-get-configuration-output.json
        20read                         -> Returns config (token redacted to prefix) + Alloy/PVE health + WAL disk bytes
      list-local-targets/              -> validate-input.json, validate-output.json, 20read
      save-local-target/               -> validate-input.json, validate-output.json, 20save (triggers Alloy HTTP /-/reload)
      delete-local-target/             -> validate-input.json, validate-output.json, 20delete (triggers Alloy HTTP /-/reload)
      test-hub-connection/             -> validate-input.json, validate-output.json, 20test
      restore-module/                  -> 06copyenv (calls agent.dump_env()), 50configure
      clone-module/                    -> 50configure (regenerates unique collector_id so clone doesn't collide!)
      destroy-module/                  -> 20destroy
    update-module.d/
      20pull_images                    -> Pulls updated Alloy & PVE Exporter images during module updates
    systemd/user/
      central-monitoring-collector.service -> Podman pod (publishes UDP/TCP ${SYSLOG_PORT}:5514 ONLY if enable_syslog_receiver=true)
      alloy.service                    -> Grafana Alloy (:12345 loopback inside pod, --stability.level=generally-available, --server.http.listen-addr=127.0.0.1:12345)
      pve-exporter.service             -> Proxmox VE Exporter (:9221 loopback inside pod, conditional on proxmox targets)
      ns8-collector-textfile.service   -> Runs bin/collect-ns8-metrics oneshot
      ns8-collector-textfile.timer     -> Triggers ns8-collector-textfile.service every 60s
  ui/
    package.json
    vue.config.js
    public/
      metadata.json                    -> NS8 Software Center catalog descriptor (en/de description, categories, GHCR source)
      module_default_icon.png          -> NS8 Software Center PNG application icon (packaged into /ui/ inside module scratch image)
      i18n/{en,de}/translation.json
    src/
      main.js
      App.vue
      views/
        Status.vue                     -> Core get-status + collector get-configuration health/WAL card
        LocalTargets.vue               -> Customer LAN targets table & modal (Proxmox, Windows, Linux, SNMP v2c/v3 incl. qnap & printer, Custom)
        Settings.vue                   -> Hub URL, Bearer Token, Customer/Site, Local NS8 switch, Syslog port, WAL size + "Test Connection" button
        About.vue
scripts/
  generate-repomd.py                   -> Publishes both central-monitoring-hub & central-monitoring-collector into a GitHub Pages NS8 Software Center catalog
tests/
  site_collector/                      -> Backend action, Alloy River syntax/label tests, PVE/SNMP config, NS8 cluster-wide collector, and UI compliance tests
```

---

## Architectural & NS8 Compliance Contracts

### 1. All 8 NS8 Backend Rules & All 3 NS8 UI Rules Enforced
1. **Never override `get-status`:** Neither `collector/imageroot/actions/get-status` nor custom status schema overrides exist; Alloy health, WAL byte usage, and target counts are returned via `get-configuration`.
2. **Always call `agent.dump_env()`** immediately after `agent.set_env()` in `create-module`, `configure-module`, `restore-module`, and `clone-module`.
3. **Port Isolation:** Alloy's admin/reload HTTP server listens strictly on `127.0.0.1:12345` inside the pod (never published to the host). Only when `enable_syslog_receiver == true` does the pod publish `-p ${SYSLOG_PORT}:5514/udp -p ${SYSLOG_PORT}:5514/tcp` (`1024 <= SYSLOG_PORT <= 65535`).
4. **No `--pull=always`, Directory Bind-Mounts & Strict `%E/` Systemd Specifier in `.service` units:** Uses `--pull=missing` + `org.nethserver.images`, references `%E/` (`~/.config`, **never** `%S/` `~/.local/state`) for `EnvironmentFile`, `WorkingDirectory`, and directory bind-mounts (`-v %E/state/alloy-conf:/etc/alloy/conf:ro,z` with SELinux `:z` labels so `os.replace` updates never leave Alloy pinned to an unlinked inode), and runs rootless containers with `--user 0:0` when mounting `0600` secret/config files (`4` `.service` units + `ns8-collector-textfile.timer`).
5. **Startup Ordering & Hot Reload:** When `pve-exporter.service` is active, `alloy.service` waits for `127.0.0.1:9221` readiness; updating local LAN targets in `save-local-target` / `delete-local-target` re-renders `config.alloy` and invokes `POST http://127.0.0.1:12345/-/reload` without restarting Alloy or interrupting the WAL queue (recreating the pod only when `enable_syslog_receiver` or `syslog_port` changes).
6. **Restic Backup (`state-include.conf`):** Includes `state/environment`, `state/secrets.env`, and `state/local-targets.json`, deliberately excluding transient multi-GB `alloy-wal` data so backups stay sub-megabyte; `clone-module` mints a fresh `collector_id` suffix so cloned nodes don't overwrite the source node's `collector_id` series.
7. **LF Line Endings & `+x` Permissions:** Enforced in `.gitattributes` and `collector/Containerfile`.
8. **Cockpit UI Compliance:** `collector/ui/` obeys all 3 NS8 UI rules (no `createSuccessNotificationForApp`, explicit Carbon icon registration in `components`/`data()`, eager `en`+`de` loading + mandatory NS8 keys in `translation.json`).

### 2. Canonical Label Stamping, Zero-Root Cluster-Wide NS8 Visibility & `ns8.prom` Contract

- Because a single `central-monitoring-collector` scrapes heterogeneous LAN devices (`ns8`, `proxmox`, `windows`, `linux`, `snmp-network`, `snmp-ups`, `snmp-nas`, `snmp-firewall`, `snmp-printer`), each `prometheus.relabel` / `loki.relabel` pipeline explicitly stamps the target's exact `device_role`, `customer`, `site`, and `collector_id` **before** forwarding to `prometheus.remote_write.hub.receiver` and `loki.write.hub.receiver`!
- Extended SNMP module profiles in `alloy_renderer.py` (`snmp-auths.yml`) include `if_mib`, `apcupsd`, `synology`, `qnap` (`1.3.6.1.4.1.24681.1`: `qnapVolumeStatus`, `qnapDiskTemperature`), `printer` (RFC 3805 `1.3.6.1.2.1.43`: `prtMarkerSuppliesLevel`, `prtMarkerSuppliesMaxCapacity`, `prtMarkerSuppliesDescription`, `prtAlertSeverityLevel`, `prtMarkerLifeCount`), and `generic` (all interface walks emitting `ifSpeed` & `ifHighSpeed` alongside 64-bit/32-bit octet & error counters).
- Standalone Windows & Linux agent onboarding templates (`shared/alloy-templates/install-windows.ps1.tmpl` & `install-linux.sh.tmpl`) enforce Windows Authenticode signature verification, `$env:ProgramData` NTFS ACL lockdown (`SYSTEM` + `Administrators`), Windows Service auto-recovery + non-admin stop/pause tamper protection (`sc.exe sdset`), and Linux `umask 0077` / `0640` atomic config installation.
- Bearer token authentication uses `bearer_token_file = "/etc/alloy/secrets/hub.token"` (`0600`), never embedding raw tokens in process CLI arguments (`ps aux`).
- **Authoritative Zero-Root Cluster-Wide NS8 Discovery (`bin/collect-ns8-metrics`):**
  Running on the NS8 host user slice via `ns8-collector-textfile.timer` (in the **host network namespace**, overcoming per-UID rootless Podman isolation without requiring root privileges):
  1. **Rootless Linux cgroups v2 NS8 Module & Pod Sub-Unit Harvest (`0444` world-readable):** Combines NS8 module accounts from `/etc/passwd` (`UID >= 1000`, `/home/<mid>`), local NS8 Redis `module/*/environment`, and `/sys/fs/cgroup`:
     - **Rootless modules (`module_type="rootless"`):** Reads `/sys/fs/cgroup/user.slice/user-<UID>.slice/` (`cpu.stat`, `memory.current`, `memory.stat` `inactive_file`, `memory.swap.current`, `memory.max`, `memory.events` `oom_kill`, `pids.current`, `io.stat`) plus container sub-units under `user@<UID>.service/{app,user}.slice/*.service`.
     - **Rootful modules (`module_type="rootful"`, e.g. `samba1`, `crowdsec1`):** Reads `/sys/fs/cgroup/system.slice/<mid>.service`.
  2. **Node-Wide Module & Container Harvest:** Queries NS8's local host `node_exporter` (`http://127.0.0.1:9100/metrics`, or the node's WireGuard VPN IP discovered from Redis `node/${NODE_ID}/vpn`) to harvest NS8 Core 3.22+'s cluster-wide `ns8_container_info` / `ns8_module_*` metrics across all modules on that node, synthesizing `ContainerRecord` entries from cgroup sub-units when `ns8-metrics` is not installed.
  3. **Cluster-Wide Restic Backup Harvest:** Queries the local NS8 Redis replica (`127.0.0.1:6379` via `agent.redis_connect(use_replica=True)` or `REDIS_ADDRESS`) for cluster backup schedules and per-module Restic status across all modules on the cluster/node (`ns8_backup_status`, `ns8_backup_failed`, `ns8_backup_last_success_timestamp_seconds`).
  4. **Deterministic Offline / Test Fallback:** Falls back cleanly to JSON state files (`ns8-backups.json`), local `podman ps`, and `systemctl --user` when host `node_exporter` or Redis is unreachable or mocked in unit tests.
- **`bin/collect-ns8-metrics` (`ns8.prom`) & Hub `collect-hub-ns8-metrics` (`ns8-hub-node.prom`) MUST emit these exact metric & label names** to match `shared/rules/ns8-cluster.yml` and all 6 dashboards in `shared/dashboards/`:
  - **cgroups-v2 NS8 Module & Pod Metrics:**
    - `ns8_module_up{module_id="<id>", module_type="rootless|rootful"}` (`1` when active `pids > 0` or `memory_current > 0`, else `0`)
    - `ns8_module_cpu_seconds_total{module_id="<id>", module_type="..."}` (`cpu.stat` `usage_usec / 1e6`)
    - `ns8_module_cpu_throttled_seconds_total{module_id="<id>", module_type="..."}` (`cpu.stat` `throttled_usec / 1e6`)
    - `ns8_module_memory_bytes{module_id="<id>", module_type="..."}` (`memory.current`)
    - `ns8_module_memory_working_set_bytes{module_id="<id>", module_type="..."}` (`max(0, memory.current - inactive_file)`)
    - `ns8_module_memory_swap_bytes{module_id="<id>", module_type="..."}` (`memory.swap.current`)
    - `ns8_module_memory_limit_bytes{module_id="<id>", module_type="..."}` (`memory.max`, `0` when `"max"`)
    - `ns8_module_oom_kills_total{module_id="<id>", module_type="..."}` (`memory.events` `oom_kill`)
    - `ns8_module_io_read_bytes_total{module_id="<id>", module_type="..."}` and `ns8_module_io_write_bytes_total{module_id="<id>", module_type="..."}` (`io.stat` `rbytes`/`wbytes`)
    - `ns8_module_pids{module_id="<id>", module_type="..."}` (`pids.current`)
    - `ns8_pod_unit_cpu_seconds_total{module_id="<id>", unit="<unit>"}` and `ns8_pod_unit_memory_working_set_bytes{module_id="<id>", unit="<unit>"}`
  - **Backup, Container & Systemd Metrics:**
    - `ns8_backup_status{module_id="<id>"}` (`1` = succeeded, `0` = failed) and `ns8_backup_failed{module_id="<id>"}` (`0` = ok, `1` = failed)
    - `ns8_backup_last_success_timestamp_seconds{module_id="<id>"}` (Unix epoch seconds)
    - `ns8_container_info{module_id="<id>", container="<name>", image="<image>"}` (`1`)
    - `ns8_container_running{module_id="<id>", container="<name>"}` (`1` = running, `0` = stopped/exited)
    - `ns8_container_restarts_total{module_id="<id>", container="<name>"}` (Podman container restart count)
    - `ns8_systemd_unit_failed{name="<unit>.service"}` (`1` = failed, `0` = active/healthy)

---

## Code Style

### Generated Grafana Alloy River Block (`alloy_renderer.py` Output Example)

```hcl
prometheus.remote_write "hub" {
  endpoint {
    url               = "https://monitoring.msp.example.com/api/v1/write"
    bearer_token_file = "/etc/alloy/secrets/hub.token"

    tls_config {
      insecure_skip_verify = false
    }

    queue_config {
      capacity             = 10000
      max_shards           = 10
      min_backoff          = "1s"
      max_backoff          = "5m"
      retry_on_http_429    = true
    }
  }

  wal {
    truncate_frequency = "2h"
    min_keepalive_time = "5m"
    max_keepalive_time = "8h"
  }

  external_labels = {
    customer     = "acme-corp",
    site         = "hq",
    collector_id = "acme-corp-hq-ns8",
  }
}
```

---

## Testing Strategy

- **Framework:** `pytest` (`python -m pytest tests/site_collector -v`) + `npm --prefix collector/ui run build`.
- **Test Cases:**
  - Verify `alloy_renderer.py` produces balanced braces/quotes, sets `bearer_token_file` (never inline token), stamps `customer`, `site`, `collector_id`, and exact per-target `device_role` across local NS8, Proxmox VE, Windows (`:9182`), Linux (`:9100`), SNMP v2c/v3 (`if_mib`, `apcupsd`, `synology`, `generic`), Custom Exporter, and Syslog (`loki.source.syslog`).
  - Verify `pve.yml` generation enables `pve-exporter.service` if and only if at least one enabled `proxmox` target is configured, and redacts `pve_token_secret` and SNMP credentials in `list-local-targets`.
  - Verify `test-hub-connection` handles `200 OK` (`verified_customer`), `401 Unauthorized`, TLS errors, and connection timeouts gracefully, matching `collector-test-hub-connection-output.json`.
  - Run full NS8 Backend (8 rules) and NS8 UI (3 rules + `en`/`de` i18n parity) static audit tests against `collector/`.

---

## Boundaries

- **Always:**
  - Store `hub.token` and `pve.yml` in `0600` secret files, never in CLI flags or world-readable files.
  - Validate `hub_url` requires `https://` (`collector-configure-module-input.json`).
  - Keep Syslog listener disabled by default (`enable_syslog_receiver: false`) and bound only to unprivileged ports (`>= 1024`) when enabled.
- **Ask first:**
  - Mounting any host directory writeably into the collector pod (`/host/proc`, `/host/sys`, `/host/root`, and `/var/log/journal` must always be `:ro`).
- **Never:**
  - Override `imageroot/actions/get-status` or call `createSuccessNotificationForApp`.
  - Include `alloy-wal` raw queue directories in `state-include.conf` Restic backups.
  - Interfere with NS8's internal `ns8-metrics` ports or services.

---

## Success Criteria

- [ ] `collector/imageroot/` and `collector/ui/` pass all 8 NS8 Backend Rules and all 3 NS8 UI Rules in automated `pytest` tests (100% Python 3.9 Rocky Linux 9 compatible), and `npm --prefix collector/ui run build` exits `0` with `0` warnings on `Node.js v26.13.1`.
- [ ] All **6** schema-validated Collector NS8 actions (`configure-module`, `get-configuration`, `list-local-targets`, `save-local-target`, `delete-local-target`, `test-hub-connection` — **10** Collector actions total including `create-module`, `restore-module`, `clone-module`, `destroy-module`) validate cleanly against `shared/schemas/collector-*.json` (`12` byte-identical action schemas).
- [ ] `render-alloy-config` and `collect-ns8-metrics` achieve 100% sample-for-sample `ns8_*` parity with Hub self-monitoring (including stopped rootless/rootful modules `ns8_module_up=0` and `max(finite_limits)`) and generate valid Alloy River configs for Proxmox VE, Windows, Linux, SNMP v2c/v3 (`if_mib`, `apcupsd`, `synology`, `qnap`, `printer`, `generic`), Syslog, and WAL-backed HTTPS push.
