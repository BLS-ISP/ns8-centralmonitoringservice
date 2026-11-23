# Spec: `hub-probes-alerting` — Central Pull/Probe Targets, Rule Packs, Multi-Channel Alerting & Silences

- **Module ID:** `hub-probes-alerting`
- **Depends on:** `telemetry-contract`, `hub-core`, `hub-tenancy-gateway`
- **Consumed by:** `hub-ui`

---

## Assumptions

1. Central pull/probe targets (`ns8-federation`, `exporter`, `blackbox`, `snmp`) managed on the Hub are used for public websites/SSL endpoints, VPN-routed infrastructure, and direct NS8 `/federate` endpoints; NATed customer LAN devices behind overlapping RFC1918 subnets are scraped locally by `central-monitoring-collector` or standalone Alloy agents (`site-collector`).
2. Prometheus runs with `--web.enable-lifecycle` and `file_sd_configs` (`refresh_interval: 30s`), allowing `save-target` and `delete-target` to add/update/remove targets atomically **without restarting Prometheus or dropping active Remote Write streams**.
3. Alertmanager v0.27 natively supports SMTP, Slack, MS Teams (`msteams_configs`), Telegram (`telegram_configs`), and generic Webhooks (`webhook_configs`), while push providers Ntfy and Gotify are bridged cleanly through an internal loopback relay route on `hub-gateway` (`http://127.0.0.1:9097/alert-relay/{ntfy|gotify}`) so zero external third-party sidecars are required.
4. In rootless Podman on Linux, raw ICMP sockets require host `net.ipv4.ping_group_range` covering the rootless UID; therefore `blackbox.yml` defaults web/host checks to `http_2xx`, `tcp_connect`, `dns_tcp`, and `dns_udp`, while configuring `icmp` with unprivileged datagram ping (`preferred_ip_protocol: "ip4"`).

---

## Objective

Equip `central-monitoring-hub` with full MSP monitoring & alerting parity to replace PRTG, Checkmk, or Zabbix:
1. **Zero-Downtime Central Target Discovery (`list-targets`, `save-target`, `delete-target`):** Generates Prometheus `file_sd` target files (stamping canonical `customer`, `site`, `device_role`, `collector_id="hub-central"` labels) plus per-target `snmp.yml` auth profiles and federation scrape configs.
2. **Integrated Blackbox & SNMP Probing:** Pre-configured Blackbox Exporter (`:9115` for HTTP/HTTPS status, stacked phase latency, TLS certificate expiry, DNS, TCP with `follow_redirects: false` on POST probes) and SNMP Exporter (`:9116` mounted as a directory `--volume=%E/config/snmp:/etc/snmp_exporter:ro,z`, supporting v2c communities and SNMPv3 `noAuthNoPriv`/`authNoPriv`/`authPriv` across `if_mib`, `apcupsd`, `synology`, `qnap` [Enterprise OID `1.3.6.1.4.1.24681.1`: `qnapVolumeStatus`, `qnapDiskTemperature`, `systemTemperature`], `mikrotik`, `fortigate`, `printer` [RFC 3805 Printer-MIB `1.3.6.1.2.1.43`: `prtMarkerSuppliesLevel`, `prtMarkerSuppliesMaxCapacity`, `prtMarkerSuppliesDescription`, `prtAlertSeverityLevel`, `prtMarkerLifeCount`], and `generic` — all interface-capable profiles emitting `ifSpeed`, `ifHighSpeed`, `ifHCInOctets`/`ifHCOutOctets`, `ifInErrors`/`ifOutErrors`, and `ifName`/`ifDescr` lookups for accurate port utilization `%`).
3. **MSP Standard Alert Rule Packs & Multi-Channel Routing (`get-alerting`, `configure-alerting`, `test-alert`):** Deploys `shared/rules/*.yml` into Prometheus and renders `alertmanager.yml` supporting NS8 Smarthost / custom SMTP, PSA/Ticketing Webhooks, MS Teams & Slack, Ntfy / Telegram / Gotify push notifications, and optional **per-customer email routing** (`customer="<slug>"` -> `tenant.contact_emails`).
4. **Maintenance Windows / Silences (`list-silences`, `create-silence`, `delete-silence`):** Manages scheduled or immediate silences (e.g., Patch Tuesday, Proxmox maintenance) per customer, site, or `device_role` via Alertmanager's v2 HTTP API and persists active/pending silences to `state/silences.json` for Restic backup durability.

---

## Tech Stack

- **Probers & Alert Engine:**
  - `quay.io/prometheus/blackbox-exporter:v0.25.0` (`127.0.0.1:9115`)
  - `quay.io/prometheus/snmp-exporter:v0.26.0` (`127.0.0.1:9116`)
  - `quay.io/prometheus/alertmanager:v0.27.0` (`127.0.0.1:9093`)
  - Internal Push Relay (`hub-gateway` loopback listener `127.0.0.1:9097` for Ntfy/Gotify formatting)
- **NS8 Backend Helpers:** Python 3 (`urllib.request` / `aiohttp` / stdlib `json`, NS8 `discover-smarthost` + `events/smarthost-changed/10reload_services`).
- **Detected Local Host Runtimes (Windows):**
  - `Python 3.14.10` (`pytest 9.2.0`, `pytest-asyncio 1.5.0`, `jsonschema 4.26.0`, `aiohttp 3.14.5`, `httpx 0.28.1`), `docker.exe`.

---

## Commands

```powershell
# Run central target file_sd, Blackbox/SNMP config, Alertmanager routing & silence tests locally
python -m pytest tests/hub_probes_alerting -v

# Validate all target, alerting, and silence schemas
python -c "import json, jsonschema; [jsonschema.Draft7Validator.check_schema(json.load(open(f'shared/schemas/hub-{a}-{d}.json', encoding='utf-8'))) for a in ('list-targets','save-target','delete-target','get-alerting','configure-alerting','test-alert','list-silences','create-silence','delete-silence') for d in ('input','output')]; print('Probes & Alerting schemas valid')"

# Optional container-based amtool config check when Docker daemon is active
docker run --rm --entrypoint amtool -v "${PWD}/scratch:/cfg:ro" quay.io/prometheus/alertmanager:v0.27.0 check-config /cfg/alertmanager.yml
```

---

## Project Structure

```text
hub/
  imageroot/
    pypkg/
      hub_alerting/
        targets_manager.py             -> CRUD on state/targets.json + atomic file_sd/*.json & snmp-auth generation
        blackbox_config.py             -> Renders blackbox.yml (http_2xx, http_post_2xx, tcp_connect, dns_tcp, dns_udp, icmp)
        snmp_config.py                 -> Renders snmp.yml v2c/v3 auth blocks for if_mib, apcupsd, synology, qnap, mikrotik, fortigate, printer, generic
        alertmanager_config.py         -> Renders alertmanager.yml (Smarthost, PSA webhook, Teams, Slack, Telegram, Ntfy/Gotify, per-customer routes)
        silences_manager.py            -> Syncs silences with Alertmanager /api/v2/silences and persists state/silences.json
    actions/
      list-targets/                    -> validate-input.json, validate-output.json, 20read
      save-target/                     -> validate-input.json, validate-output.json, 20save
      delete-target/                   -> validate-input.json, validate-output.json, 20delete
      get-alerting/                    -> validate-input.json, validate-output.json, 20read
      configure-alerting/              -> validate-input.json, validate-output.json, 20configure
      test-alert/                      -> validate-input.json, validate-output.json, 20test
      list-silences/                   -> validate-input.json, validate-output.json, 20read
      create-silence/                  -> validate-input.json, validate-output.json, 20create
      delete-silence/                  -> validate-input.json, validate-output.json, 20delete
tests/
  hub_probes_alerting/                 -> Unit & integration tests for file_sd, SSRF guard, Alertmanager routes & silences
```

---

## Architectural & Security Contracts

### 1. Dynamic `file_sd` & Relabeling Without Restart

- `prometheus.yml` includes static `file_sd_configs` globs under `/etc/prometheus/file_sd/`:
  - `exporters/*.json` -> Direct HTTP/HTTPS scrape with canonical labels `customer`, `site`, `device_role`, `collector_id="hub-central"`.
  - `blackbox/*.json` -> Standard multi-target relabeling (`__address__` -> `__param_target` -> `instance`, `__address__ = 127.0.0.1:9115`, `__param_module = <blackbox_module>`).
  - `snmp/*.json` -> Multi-target relabeling (`__address__` -> `__param_target` -> `instance`, `__address__ = 127.0.0.1:9116`, `__param_module = <snmp_module>`, `__param_auth = <target_auth_profile>`).
  - Federation targets (`ns8-federation`, requiring per-target `basic_auth`/`bearer_token`/`match[]` params) are rendered into `/etc/prometheus/federation_jobs.yml` and applied via `POST http://127.0.0.1:9090/-/reload` (zero downtime, WAL/TSDB intact).
- **SSRF Protection on Scrape & Webhook Endpoints:**
  - `save-target` and `configure-alerting` **MUST** reject loopback/pod-internal addresses (`127.0.0.0/8`, `::1`, `localhost`, `0.0.0.0`, `169.254.169.254`, and `10.0.2.2` on internal pod ports `3000`, `3100`, `8080`, `9090`, `9093`, `9095`, `9096`, `9097`, `10901`-`10922`) with validation error `FORBIDDEN_INTERNAL_ENDPOINT` so user-supplied targets or webhooks can never hit internal Prometheus/Loki/Alertmanager admin endpoints!

### 2. Alertmanager Multi-Channel Routing Tree

1. **Root Route:** Groups by `['customer', 'site', 'alertname']` (`group_wait`, `group_interval`, `repeat_interval`), sending to `msp-default-fanout` (`continue: true`).
2. **MSP Fan-Out Receivers:**
   - `smarthost_email`: Uses NS8 Smarthost (`10.0.2.2:<smarthost_port>` from `state/smarthost.env` when `use_ns8_smarthost == true`) or explicit `smtp_host:smtp_port`.
   - `webhook_psa`: Sends structured Alertmanager v4 JSON payload with `Authorization: Bearer <auth_secret>` to PSA/ticketing endpoint.
   - `chat`: Native `msteams_configs` and/or `slack_configs`.
   - `push`: Filtered by `severity =~ "critical"` (or `"warning|critical"` when `min_severity == "warning"`), routing to native `telegram_configs` or internal `http://127.0.0.1:9097/alert-relay/{ntfy|gotify}`.
3. **Per-Customer Email Sub-Routes (`customer_email_routing.enabled == true`):**
   - For every tenant in `state/tenants.json` with non-empty `contact_emails`, `alertmanager_config.py` generates a child route matching `customer = "<slug>"` (and `severity` matching `customer_email_routing.min_severity`) targeting receiver `customer-email-<slug>`! Updating a tenant's `contact_emails` in `save-tenant` automatically re-renders `alertmanager.yml` and triggers `POST http://127.0.0.1:9093/-/reload`.

### 3. Rule Pack Management (`6` Packs / `81` Alert Rules)

- All **6** rule packs (`81` alert rules total) from `shared/rules/` are baked into `/etc/prometheus/available-rules/` and copied into `/etc/prometheus/rules/` according to `enabled_rule_packs` (all 6 enabled by default), followed by `POST http://127.0.0.1:9090/-/reload`:
  - `ns8-cluster.yml` (`20` rules): Node reachability/staleness, CPU/RAM/swap, partition >85%/>95% & 24h `predict_linear`, `mdadm` RAID, Restic backup failure/staleness, container crashloop/absence, systemd unit failures, plus rootless `cgroups-v2` pod alerts **`NS8ModuleOOMKilled`**, **`NS8ModuleMemoryNearLimit`**, and **`NS8ModuleHighSwapUsage`**.
  - `linux-node.yml` (`15` rules): Host down/staleness, reboot, CPU, core-normalized load, RAM/OOM, filesystem/inodes/read-only mounts, disk I/O saturation, failed systemd units, NTP sync.
  - `snmp-network-ups.yml` (`15` rules): SNMP reachability, critical interface down & packet error/discard rates, UPS on-battery/low-charge/replace-battery, Synology & **QNAP** (`SnmpQnapVolumeDegraded`, `SnmpQnapDiskTemperatureWarning`, `SnmpQnapDiskTemperatureCritical`) NAS health, and **RFC 3805 Printer-MIB** (`SnmpPrinterSupplyLowWarning`, `SnmpPrinterSupplyCritical` with `prtMarkerSuppliesLevel >= 0` sentinel guard, `SnmpPrinterCriticalAlertActive`).
  - `windows-node.yml` (`12` rules): Windows host down/staleness, reboot, CPU, RAM, logical disks `C:`/`D:`, automatic services, AD/NTDS, DNS, SMB.
  - `proxmox-ve.yml` (`11` rules): PVE exporter/node status, quorum, CPU/RAM/IO-wait, storage pools, ZFS health, auto-start VM/LXC stopped.
  - `blackbox-web-ssl.yml` (`8` rules): `probe_success == 0`, HTTP 4xx/5xx, slow response >3s, TLS expiry <21d/<7d, DNS & TCP failures.

---

## Code Style

### Atomic `file_sd` Target Write & SSRF Loopback Guard

```python
import ipaddress
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse


def assert_not_internal_pod_endpoint(raw_endpoint: str) -> None:
    parsed = urlparse(raw_endpoint if "://" in raw_endpoint else f"http://{raw_endpoint}")
    host = (parsed.hostname or "").strip().lower()
    if host in {"localhost", "10.0.2.2", "metadata.google.internal"}:
        raise ValueError(f"Internal host forbidden: {host}")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            raise ValueError(f"Loopback/link-local IP forbidden: {host}")
    except ValueError as exc:
        if "forbidden" in str(exc):
            raise


def atomic_write_json(path: Path, payload: object, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
```

---

## Testing Strategy

- **Framework:** `pytest` (`python -m pytest tests/hub_probes_alerting -v`).
- **Test Cases:**
  - Verify `save-target` writes canonical labels (`customer`, `site`, `device_role`, `collector_id="hub-central"`) into `file_sd` JSON and validates against `hub-save-target-input.json` / `hub-list-targets-output.json` (redacting passwords/SNMP secrets to `has_secret: true`).
  - Verify SSRF guard rejects `127.0.0.1:9090`, `[::1]:3100`, `localhost:9093`, `169.254.169.254`, and `10.0.2.2:9095` in both `save-target` and `configure-alerting` webhook URLs.
  - Verify `alertmanager_config.py` generates valid `alertmanager.yml` with NS8 Smarthost fallback, per-customer email routes, push severity filters, and `*_unchanged` secret preservation.
  - Verify `create-silence`, `list-silences`, and `delete-silence` map `customer`, `site`, `device_role`, and `extra_matchers` accurately to Alertmanager v2 matchers (`customer="*"` omits the `customer` matcher for global maintenance; `ends_at <= starts_at` fails validation).

---

## Boundaries

- **Always:**
  - Validate that a target's `customer` and `site` exist in `state/tenants.json` before saving a pull/probe target.
  - Reload Prometheus (`/-/reload`) and Alertmanager (`/-/reload`) via HTTP lifecycle endpoints instead of restarting containers whenever configs change.
  - Persist `state/targets.json`, `state/alerting.json`, and `state/silences.json` with `0600` permissions using atomic `os.replace`.
- **Ask first:**
  - Adding privileged Linux capabilities (`CAP_NET_RAW`) to any container (must remain 100% unprivileged rootless).
- **Never:**
  - Return SMTP passwords, webhook secrets, chat webhook URLs, Telegram/Ntfy/Gotify tokens, or SNMP communities/v3 passwords in `get-alerting` or `list-targets`.
  - Allow scrape targets or webhook URLs pointing to pod loopback (`127.0.0.0/8`, `::1`, `localhost`).

---

## Success Criteria

- [ ] All 9 NS8 actions (`list-targets`, `save-target`, `delete-target`, `get-alerting`, `configure-alerting`, `test-alert`, `list-silences`, `create-silence`, `delete-silence`) pass schema validation and unit/integration tests.
- [ ] Adding/updating/deleting `exporter`, `blackbox`, and `snmp` targets updates `file_sd` files atomically with zero container restarts.
- [ ] Rendered `alertmanager.yml` routes alerts across Smarthost email, Webhook/PSA, Teams/Slack, Ntfy/Telegram/Gotify, and per-customer `contact_emails` while respecting active Silences.
- [ ] `smarthost-changed` event handler refreshes `alertmanager.yml` automatically when cluster mail relay settings change.
