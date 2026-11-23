# Dashboard-, Metrik- & Alarmregel-Referenzhandbuch (`v1.1.0`)

Vollständiges technisches und operatives Nachschlagewerk für alle **6 Enterprise-NOC-Grafana-11-Dashboards (`117` Panels)**, die **kanonischen Prometheus- und Loki-Metriken** sowie sämtliche **81 vorinstallierten Prometheus-Alarmregeln** in 6 Regelpaketen des **NS8 Central Monitoring Service**.

- **MSP-Benutzerhandbuch:** [`user-guide.md`](user-guide.md)
- **Endkunden-Portal-Handbuch:** [`customer-portal-guide.md`](customer-portal-guide.md)
- **Betriebs- & Runbook-Handbuch:** [`operations-guide.md`](operations-guide.md)
- **Architektur & ADRs:** [`architecture.md`](architecture.md)
- **Modul-Referenzen (EN):** [`../hub/README.md`](../hub/README.md) · [`../collector/README.md`](../collector/README.md) · [`../README.md`](../README.md)

---

## 1. Die 6 Enterprise-NOC-Grafana-11-Dashboards (`117` Panels)

Alle 6 Dashboards liegen unter [`../shared/dashboards/`](../shared/dashboards/) im Format `schemaVersion: 39` (Grafana OSS `11.2.2`) vor und werden automatisch sowohl in der **MSP-Hauptorganisation (`Org 1`)** als auch mandantenisoliert in allen aktivierten **Kunden-Organisationen (`Org > 1`)** bereitgestellt.

### Übergreifende Navigation & Mandanten-Isolation

- **1-Klick-Ansichtenleiste (`Monitoring-Ansichten`):** Jedes Dashboard besitzt oben rechts eine einheitliche Navigationsleiste über das Tag `ns8-central-monitoring` (`includeVars: true`, `keepTime: true`). Beim Wechsel zwischen den 6 Ansichten bleiben der gewählte Mandant (`$customer`), der Standort (`$site`) und das Zeitfenster erhalten.
- **Unüberwindbare Mandantentrennung im Kunden-Portal (`Org > 1`):** Bei der Synchronisation in eine Kunden-Organisation fixiert `grafana_sync.py` die Variable `$customer` automatisch auf `type: "constant"` (`hide: 2`, `editable: false`), während alle Abfragen serverseitig durch `prom-label-proxy` (`:9095`) bzw. Loki Single-Tenant-Header (`X-Scope-OrgID`) erzwungen werden. Alle übrigen Filtervariablen (`$site`, `$instance`, `$module_id`, `$device_role`, `$job`, `$level`, `$log_search`) bleiben für Endkunden voll interaktiv nutzbar.

### Übersichtstabelle aller 6 Dashboards

| # | Titel (DE) | Grafana-UID (` URL: /d/<uid> `) | Datei | Panels | Filtervariablen |
|---|---|---|---|---:|---|
| 1 | **NS8 & MSP Gesamtübersicht** | `ns8-multi-cluster-overview` | `ns8-multi-cluster-overview.json` | 22 | `$customer`, `$site` |
| 2 | **NethServer 8 Pods, Module & Container** | `ns8-pods-and-modules` | `ns8-pods-and-modules.json` | 21 | `$customer`, `$site`, `$instance`, `$module_id` |
| 3 | **Linux- & Windows-Server Deep-Dive** | `linux-windows-servers` | `linux-windows-servers.json` | 24 | `$customer`, `$site`, `$device_role`, `$instance` |
| 4 | **Proxmox VE, Netzwerk, USV & NAS** | `proxmox-snmp-infrastructure` | `proxmox-snmp-infrastructure.json` | 27 | `$customer`, `$site`, `$instance` |
| 5 | **Web, DNS & SSL-Zertifikate (SLA)** | `web-ssl-uptime` | `web-ssl-uptime.json` | 13 | `$customer`, `$site`, `$instance` |
| 6 | **Zentraler Log- & Security-Explorer** | `central-log-explorer` | `central-log-explorer.json` | 10 | `$customer`, `$site`, `$device_role`, `$instance`, `$job`, `$level`, `$log_search` |

---

### 1.1 Dashboard 1: NS8 & MSP Gesamtübersicht (`ns8-multi-cluster-overview`)

- **Zweck:** Zentraler NOC-Leitstand (Start-Dashboard nach dem Login für MSP-Techniker und Endkunden) zur sofortigen Erkennung kritischer Störungen über alle Mandanten, Standorte und Geräteklassen hinweg.
- **Variablen:** `$customer` (*Mandant*), `$site` (*Standort*).
- **Panel-Gruppen (22 Panels):**
  1. **MSP Leitstand — Flottenstatus, Alarme & NethServer 8 KPIs (8 Sparkline-Stats):** *Kritische Alarme*, *Warnungen*, *NS8-Knoten Online* (inkl. Hub-Self-Monitoring), *Systeme Gesamt Online*, *Aktive NS8-Module / Pods* (`ns8_module_up == 1`), *NS8 Pod-OOM-Kills (24h)* (`increase(ns8_module_oom_kills_total[24h])`), *Fehlerhafte Restic-Backups*, *SSL-Zertifikate < 14d*.
  2. **Flotten-Gesundheitsmatrix & Aktive Alarme:** Farbcodierte Systemtabelle mit Gradient-Füllbalken für CPU %, RAM % und höchste Partition % inkl. **3 direkten Data-Links** pro Zeile (*Server Deep-Dive öffnen*, *NS8-Pods & Module öffnen*, *System-Logs im Explorer öffnen*) sowie Echtzeit-Alarmtabelle (`ALERTS{alertstate="firing"}`).
  3. **Top-10 Ressourcenverbraucher — Server & Partitionen:** Top-10 Hosts nach CPU %, Top-10 Hosts nach RAM % und Top-10 Partitionen/Laufwerke nach Füllstand %.
  4. **NethServer 8 Top-Pods (`cgroups v2`) & Restic-Backup-Status:** *Top-10 NS8-Pods nach Working-Set-RAM* (echter Speicherbedarf ohne Linux-Page-Cache), *Top-10 NS8-Pods nach CPU-Last (%)* sowie vollständige *NS8 Restic-Backup-Matrix & Letzte Sicherung*.
  5. **Live-Fehler- & Sicherheits-Logstream (Loki):** Flottenweiter Echtzeit-Stream kritischer System- und Sicherheitsmeldungen.

### 1.2 Dashboard 2: NethServer 8 Pods, Module & Container (`ns8-pods-and-modules`)

- **Zweck:** Tiefenanalyse aller auf NethServer-8-Knoten laufenden Rootless-Podman-Pods (`user.slice/user-<UID>.slice`) und Rootful-Systemdienste (`system.slice/<mid>.service`, z. B. `samba1`, `crowdsec1`) auf Basis kernelseitiger Linux-`cgroups v2`-Telemetrie.
- **Variablen:** `$customer` (*Mandant*), `$site` (*Standort*), `$instance` (*NS8-Knoten*, `device_role="ns8"`), `$module_id` (*NS8-Modul*, z. B. `mail1`, `nextcloud1`, `samba1`, `central-monitoring-hub1`).
- **Panel-Gruppen (21 Panels):**
  1. **Pod- & Modul-KPIs (7 Stats):** *Aktive NS8-Module*, *Rootless Pods*, *Rootful Dienste*, *Summe Pod-RAM (Working-Set)*, *Summe Pod-Swap*, *Pod-OOM-Kills (24h)*, *Fehlerhafte Systemd-Units* (dedupliziert über `node_systemd_unit_state` und `ns8_systemd_unit_failed`).
  2. **NS8-Modul-Ressourcenmatrix:** Echtzeittabelle aller installierten Module mit Typ (`rootless`/`rootful`), Status-Badge (`AKTIV` / `GESTOPPT`), CPU %, Working-Set-RAM, Swap, Prozessanzahl (`ns8_module_pids`), OOM-Kills und **1-Klick-Drill-Down** in den *Zentralen Log-Explorer* (`var-log_search=<module_id>`).
  3. **Zeitreihen pro NS8-Modul:** *CPU-Auslastung & Throttling (%)*, *Working-Set-RAM vs. Gesamt-RAM (inkl. Page-Cache)*, *Swap-Belegung*, *Disk Read / Write Durchsatz (`io.stat`)*.
  4. **Intra-Pod-Container-Aufschlüsselung:** Gestapelte Zeitreihen der einzelnen Systemd-Sub-Units innerhalb der Pods (`ns8_pod_unit_memory_working_set_bytes` & `ns8_pod_unit_cpu_seconds_total`, z. B. `dovecot`, `rspamd`, `clamd`, `mariadb`, `prometheus`, `loki`).
  5. **Container-Inventar & Modul-Logs:** Tabelle *NS8 Container- & Sub-Unit-Inventar* (`ns8_container_running`, `ns8_container_restarts_total`) sowie nach Knoten und `$module_id` gefilterter Loki-Logstream.

### 1.3 Dashboard 3: Linux- & Windows-Server Deep-Dive (`linux-windows-servers`)

- **Zweck:** Einheitliche Betriebssystem-, Storage-, Netzwerk- und Dienst-Diagnose für NethServer-8-Knoten (`ns8`), klassische Linux-Server (`linux`) und Windows-Server (`windows`).
- **Variablen:** `$customer` (*Mandant*), `$site` (*Standort*), `$device_role` (`ns8|linux|windows`), `$instance` (*Server / Host*).
- **Panel-Gruppen (24 Panels):**
  1. **Server-KPIs (7 Stats):** *Linux & NS8 Online*, *Windows Online*, *Unerreichbar*, *Kürzeste Uptime (Letzter Reboot)*, *Fehlerhafte Linux-Units* (inkl. Hub-Self-Monitoring), *Gestoppte Windows-Autodienste*, *Kernel-OOM-Kills (24h)*.
  2. **CPU & System-Load:** *CPU-Aufschlüsselung (`user` / `system` / `iowait` / `steal` + Windows CPU %)* und *System-Load (1m / 5m / 15m) vs. verfügbare CPU-Kerne*.
  3. **Arbeitsspeicher & Dateisysteme:** *RAM-Aufschlüsselung (Belegt / Cache+Buffer / Swap)* sowie vereinheitlichte Tabelle *Dateisysteme & Logische Laufwerke* (Linux-Mountpoints + Windows-Volumes `C:`/`D:` mit Kapazität, freiem Speicher und Gradient-Füllbalken).
  4. **Storage-Performance:** *Disk-Latenz pro Zugriff (`ms` Read / Write)*, *Disk-Durchsatz (Bytes/s)* und *Disk-IOPS*.
  5. **Netzwerk & Gestörte Dienste:** *Netzwerk-Durchsatz RX / TX (Bit/s)*, *Netzwerk-Paketfehler & Drops (/s)* sowie Tabelle *Fehlgeschlagene Linux-Systemd-Units & Gestoppte Windows-Autodienste*.
  6. **Host-Logs:** Kombinierter Journald- und Windows-EventLog-Stream (`Application`, `System`, `Security`).

### 1.4 Dashboard 4: Proxmox VE, Netzwerk, USV & NAS (`proxmox-snmp-infrastructure`)

- **Zweck:** Infrastruktur-Ansicht für Proxmox-VE-Cluster, Switches/Firewalls (IF-MIB / MikroTik / FortiGate), USV-Anlagen (APC / RFC 1628), Synology/QNAP-NAS-Systeme und RFC-3805-Netzwerkdrucker.
- **Variablen:** `$customer` (*Mandant*), `$site` (*Standort*), `$instance` (*System / Appliance*, `device_role=~"proxmox|snmp-.*"`).
- **Panel-Gruppen (27 Panels):**
  1. **Infrastruktur-KPIs (8 Stats):** *Proxmox Quorum*, *Proxmox-Knoten Online*, *Laufende VMs & LXCs*, *Gestoppte Auto-Start-Gäste*, *SNMP-Geräte Online*, *USV auf Batterie*, *USV Min. Stützzeit (Min)*, *Degradierte NAS-Volumes*.
  2. **Proxmox Hypervisor & Storage-Pools:** *Hypervisor CPU-Last & IO-Wait (%)*, *Hypervisor RAM-Auslastung (%)*, *Proxmox Storage-Pool-Tabelle (Kapazität & Füllbalken)*.
  3. **Proxmox VMs & LXCs:** *Top-10 VMs & LXCs nach CPU-Last (%)*, *Top-10 VMs & LXCs nach RAM-Belegung*, *Proxmox VM- & LXC-Gast-Statusmatrix*.
  4. **SNMP Switch- & Firewall-Netzwerk:** *Interface-Traffic RX / TX (Bit/s)*, *Switch-/Firewall-Port-Auslastung (%)* (relativ zu `ifHighSpeed` / `ifSpeed`) und *Interface Paketfehler & Discards (/s)*.
  5. **USV, NAS & Netzwerkdrucker:** *USV Batterieladung (%), Last (%) & Stützzeit (Min)*, *NAS Festplatten- & Systemtemperaturen (°C)* (Synology & QNAP), *Netzwerkdrucker Toner- & Verbrauchsmaterialstände (%)* (RFC 3805).
  6. **Appliance-Syslog:** Live-Syslog-Stream (`job=~".*syslog.*"` / `snmp-*` / `proxmox`).

### 1.5 Dashboard 5: Web, DNS & SSL-Zertifikate (SLA) (`web-ssl-uptime`)

- **Zweck:** Überwachung externer und interner Web-Applikationen, APIs, DNS-Zonen, TCP-Dienste und TLS/SSL-Zertifikatslaufzeiten inkl. SLA-Nachweis gegenüber Endkunden.
- **Variablen:** `$customer` (*Mandant*), `$site` (*Standort*), `$instance` (*Endpunkt / URL*).
- **Panel-Gruppen (13 Panels):**
  1. **SLA-KPIs (6 Stats):** *Überwachte Endpunkte*, *Endpunkte Erreichbar (UP)*, *Endpunkte Gestört (DOWN)*, *24h Verfügbarkeit (SLA %)*, *Kürzeste SSL-Restlaufzeit*, *Ø HTTP-Antwortzeit*.
  2. **State-Timeline & HTTP-Phasen-Latenz:** Lückenlose *Verfügbarkeits-Historie pro Endpunkt (`ONLINE` / `AUSFALL`)* sowie *Gestapelte HTTP-Phasen-Antwortzeit (`resolve` / `connect` / `tls` / `processing` / `transfer` via `probe_http_duration_seconds`)*.
  3. **SSL-Countdown & 7-Tage-SLA:** *SSL-Zertifikats-Countdown & Endpunkt-Statusmatrix* (aufsteigend sortiert nach verbleibenden Tagen, inkl. HTTP-Statuscode & Antwortzeit) und *7-Tage Verfügbarkeits-SLA pro Endpunkt (%)*.

### 1.6 Dashboard 6: Zentraler Log- & Security-Explorer (`central-log-explorer`)

- **Zweck:** Interaktives Forensik-, Troubleshooting- und Security-Suchwerkzeug über sämtliche Loki-Logströme (Linux `journald`, Rootless-Podman-Container, Windows EventLogs `Application`/`System`/`Security` inkl. Event-IDs wie `4625`/`4740` sowie RFC-5424-LAN-Syslog).
- **Variablen:** `$customer` (*Mandant*), `$site` (*Standort*), `$device_role` (*Geräteklasse*), `$instance` (*System / Quelle*), `$job` (*Log-Job*), `$level` (*Alle* / *Kritisch & Fehler* / *Warnung* / *Info*), `$log_search` (*Volltextsuche (RE2-Regex)* als freies Textfeld).
- **Panel-Gruppen (10 Panels):**
  1. **Log- & Security-Kennzahlen (4 Stats):** *Log-Zeilen im Zeitraum*, *Fehler / Kritische Events*, *Warnungen*, *Windows Security-Events* (`channel="Security"`).
  2. **Volumen & Quellen:** Gestapeltes *Log-Volumen-Histogramm nach Level* (`count_over_time(... [$__auto])`) und *Top-10 Logquellen im Zeitraum*.
  3. **Vollbild-Live-Logstream:** Echtzeit-Logpanel mit Zeilenumbruch, JSON/Logfmt-Feldextraktion und kombinierter Filterung nach `$level` und `$log_search`.

---

## 2. Kanonische Metrik- & Label-Referenz

### 2.1 Verpflichtende Multi-Tenant-Labels (Datenvertrag)

Jede Zeitreihe in Prometheus/Thanos und jeder Log-Stream in Loki trägt folgende kanonische Taxonomie-Labels (erzwungen durch `hub-gateway` bzw. zentrale Hub-Scrape-Konfigurationen):

| Label | Beispielwerte | Beschreibung |
|---|---|---|
| `customer` | `acme-corp`, `bls-isp`, `_msp_internal` | Eindeutiger Mandanten-Slug (`_msp_internal` für reine MSP-Hub-Eigenüberwachung in `Org 1`). |
| `site` | `hq`, `dc1`, `branch-berlin`, `hub` | Standort-Bezeichner innerhalb des Mandanten. |
| `device_role` | `ns8`, `linux`, `windows`, `proxmox`, `web`, `dns`, `tcp`, `snmp-network`, `snmp-firewall`, `snmp-ups`, `snmp-nas`, `snmp-printer`, `custom` | Normierte Geräteklasse für Dashboards, Filter und Alarmregeln. |
| `instance` | `ns8-01.acme.local`, `192.168.10.20`, `https://shop.acme.de` | Eindeutiger Hostname, IP oder URL des überwachten Zielsystems. |
| `collector_id` | `acme-corp-hq-ns8`, `hub-local`, `hub-central` | Kennung des liefernden Site-Collectors, Standalone-Alloy-Agenten oder Hub-Scrapers. |

### 2.2 Kanonische Prometheus-Metrikfamilien nach Domäne

| Domäne / Quelle | Kanonische Metriken | Beschreibung |
|---|---|---|
| **NS8 Pods & Module (`cgroups v2`)** | `ns8_module_up{module_id,module_type}` | `1`, wenn das Rootless-/Rootful-NS8-Modul aktive Prozesse oder RAM besitzt, sonst `0`. |
| | `ns8_module_cpu_seconds_total`, `ns8_module_cpu_throttled_seconds_total` | Kumulierte CPU-Nutzung und CPU-Drosselung (`cpu.stat` `usage_usec`/`throttled_usec`) pro NS8-Modul. |
| | `ns8_module_memory_working_set_bytes`, `ns8_module_memory_bytes`, `ns8_module_memory_swap_bytes`, `ns8_module_memory_limit_bytes` | Echter Working-Set-RAM (`memory.current - inactive_file`), Gesamt-RAM, Swap (`memory.swap.current`) und Limit (`memory.max`, `0` = unbegrenzt). |
| | `ns8_module_oom_kills_total`, `ns8_module_pids`, `ns8_module_io_read_bytes_total`, `ns8_module_io_write_bytes_total` | Kumulierte OOM-Kills (`memory.events`), Prozess-/Threadanzahl (`pids.current`) und Block-I/O (`io.stat`). |
| | `ns8_pod_unit_cpu_seconds_total{module_id,unit}`, `ns8_pod_unit_memory_working_set_bytes{module_id,unit}` | Einzelcontainer-/Sub-Unit-Aufschlüsselung innerhalb eines NS8-Pods (z. B. `dovecot`, `rspamd`, `mariadb`, `prometheus`). |
| **NS8 Backups, Container & Systemd** | `ns8_backup_status{module_id}`, `ns8_backup_failed{module_id}`, `ns8_backup_last_success_timestamp_seconds{module_id}` | Status (`1`=OK, `0`=Fehler), Fehlerzähler und Zeitstempel der letzten erfolgreichen NS8-Restic-Datensicherung. |
| | `ns8_container_info{module_id,container,image}`, `ns8_container_running{module_id,container}`, `ns8_container_restarts_total{module_id,container}` | Inventar, Laufstatus (`1`/`0`) und Neustartzähler aller NS8-Podman-Container bzw. synthetisierter Systemd-Units. |
| | `ns8_systemd_unit_failed{name}` | Fehlgeschlagene User-/System-Systemd-Units auf NS8-Knoten (`1`=failed, `0`=healthy). |
| **Linux & NS8 Host (`node_exporter` / Hub-Node)** | `node_cpu_seconds_total`, `node_load1`/`5`/`15`, `node_boot_time_seconds`, `node_memory_MemTotal_bytes`, `node_memory_MemAvailable_bytes`, `node_memory_Buffers_bytes`, `node_memory_Cached_bytes`, `node_memory_SwapTotal_bytes`, `node_memory_SwapFree_bytes`, `node_vmstat_oom_kill` | Host-CPU, System-Load, Uptime, Arbeitsspeicher, Swap und Kernel-OOM-Zähler. |
| | `node_filesystem_size_bytes`, `node_filesystem_avail_bytes`, `node_filesystem_files`, `node_filesystem_files_free`, `node_filesystem_readonly`, `node_disk_read_bytes_total`, `node_disk_written_bytes_total`, `node_disk_reads_completed_total`, `node_disk_writes_completed_total`, `node_disk_read_time_seconds_total`, `node_disk_write_time_seconds_total`, `node_md_disks`, `node_md_disks_required` | Dateisystem-Füllstände, Inodes, Read-Only-Status, Disk-Durchsatz/IOPS/Latenz und Linux-`mdadm`-Software-RAID. |
| | `node_network_receive_bytes_total`, `node_network_transmit_bytes_total`, `node_network_receive_errs_total`, `node_network_transmit_errs_total`, `node_network_receive_drop_total`, `node_network_transmit_drop_total`, `node_systemd_unit_state`, `node_timex_sync_status`, `node_timex_offset_seconds` | Netzwerkschnittstellen, Systemd-Unit-Status und NTP-Zeitsynchronisation. |
| **Windows Server (`windows_exporter` / Alloy)** | `windows_cpu_time_total`, `windows_memory_available_bytes`, `windows_memory_physical_total_bytes` (`windows_cs_physical_memory_bytes`), `windows_logical_disk_size_bytes`, `windows_logical_disk_free_bytes`, `windows_logical_disk_read_bytes_total`, `windows_logical_disk_write_bytes_total`, `windows_service_state`, `windows_service_start_mode`, `windows_system_system_up_time`, `windows_ad_*`, `windows_dns_*`, `windows_smb_*` | CPU, physischer RAM, logische Laufwerke (`C:`, `D:`), Windows-Dienste sowie Active-Directory-, DNS- und SMB-Server-Rollenmetriken. |
| **Proxmox VE (`pve-exporter`)** | `pve_up`, `pve_cluster_quorate`, `pve_cpu_usage_ratio`, `pve_iowait_ratio`, `pve_memory_usage_bytes`, `pve_memory_size_bytes`, `pve_disk_usage_bytes`, `pve_disk_size_bytes`, `pve_onboot_status`, `pve_guest_info`, `pve_zfs_pool_health` | Cluster-Quorum, Hypervisor-Auslastung, Storage-Pools, ZFS-Gesundheit und QEMU-VM-/LXC-Gaststatus. |
| **Web, DNS & TLS (`blackbox-exporter`)** | `probe_success`, `probe_duration_seconds`, `probe_http_duration_seconds{phase}`, `probe_http_status_code`, `probe_ssl_earliest_cert_expiry`, `probe_dns_query_succeeded` | Erreichbarkeit, HTTP-Phasenlatenz, Statuscodes, TLS-Ablaufzeitpunkt (Unix-Sekunden) und DNS-Auflösung. |
| **SNMP v2c/v3 (`snmp-exporter` / Alloy)** | **Netzwerk/Firewall:** `sysUpTime`, `ifAdminStatus`, `ifOperStatus`, `ifHCInOctets`, `ifHCOutOctets`, `ifInOctets`, `ifOutOctets`, `ifSpeed`, `ifHighSpeed`, `ifInErrors`, `ifOutErrors`, `ifInDiscards`, `ifOutDiscards`<br/>**USV:** `upsOutputSource`, `upsBasicOutputStatus`, `upsBatteryStatus`, `upsEstimatedMinutesRemaining`, `upsEstimatedChargeRemaining`, `upsAdvBatteryCapacity`, `upsOutputPercentLoad`, `upsAdvOutputLoad`, `upsAdvBatteryReplaceIndicator`, `upsAlarmBatteryBad`<br/>**NAS (Synology & QNAP):** `raidStatus`, `diskStatus`, `diskTemperature`, `systemTemperature`, `qnapVolumeStatus`, `qnapDiskTemperature`<br/>**Drucker (RFC 3805):** `prtMarkerLifeCount`, `prtMarkerSuppliesLevel`, `prtMarkerSuppliesMaxCapacity`, `prtAlertSeverityLevel` | Herstellerübergreifende und profilbasierte SNMP-Metriken inkl. Interface-Namen (`ifName`, `ifDescr`, `ifAlias`), RAID-/Volume-Namen und Verbrauchsmaterial-Bezeichnungen. |
| **Loki Log-Labels** | `customer`, `site`, `device_role`, `instance`, `collector_id`, `job`, `level`, `unit`, `syslog_identifier`, `channel` | Strukturierte Stream-Labels mit niedriger Kardinalität für schnelle LogQL-Abfragen und Histogramme. |

---

## 3. Vollständiger Katalog aller 81 Prometheus-Alarmregeln (6 Regelpakete)

Alle 6 Regelpakete liegen unter [`../shared/rules/`](../shared/rules/) vor und können im Hub unter **Alerting & Wartung** einzeln aktiviert/deaktiviert sowie durch eigene YAML-Regeldateien unter `config/custom-rules/` ergänzt werden.

| # | Regelpaket-Datei | Zielsysteme / Domäne | Anzahl Regeln |
|---|---|---|---:|
| 3.1 | [`ns8-cluster.yml`](../shared/rules/ns8-cluster.yml) | NethServer 8 Knoten, `cgroups v2` Pods/Module, Container, RAID & Restic-Backups | **20** |
| 3.2 | [`linux-node.yml`](../shared/rules/linux-node.yml) | Linux-Server (CPU, Load, RAM, OOM, Dateisysteme, Inodes, Disk-I/O, Systemd, NTP) | **15** |
| 3.3 | [`windows-node.yml`](../shared/rules/windows-node.yml) | Windows Server, Auto-Dienste, Active Directory (NTDS), DNS & SMB | **12** |
| 3.4 | [`proxmox-ve.yml`](../shared/rules/proxmox-ve.yml) | Proxmox VE Cluster-Quorum, Hypervisoren, Storage-Pools, ZFS & Auto-Start-VMs/LXCs | **11** |
| 3.5 | [`blackbox-web-ssl.yml`](../shared/rules/blackbox-web-ssl.yml) | HTTP/HTTPS-Websites, Antwortzeiten, TLS/SSL-Zertifikate, DNS & TCP-Ports | **8** |
| 3.6 | [`snmp-network-ups.yml`](../shared/rules/snmp-network-ups.yml) | Switches/Firewalls, APC/RFC-1628-USV, Synology/QNAP-NAS & RFC-3805-Netzwerkdrucker | **15** |
| **Gesamt** | **6 Regelpakete (16 Regelgruppen)** | **Vollständige MSP-Flottenabdeckung** | **81** |

---

### 3.1 Regelpaket 1: `ns8-cluster.yml` — NethServer 8 Cluster, Pods & Backups (20 Regeln)

| Alert-Name | Schweregrad | Auslöser & Dauer (`for`) | MSP-Runbook / Empfohlene Maßnahme |
|---|---|---|---|
| `NS8NodeUnreachable` | `critical` | `up{device_role="ns8"} == 0` für `3m` | Netzwerk-/Stromversorgung des NS8-Knotens prüfen; beim Hub-Knoten Status von `hub-ns8-metrics.timer` und `hub-gateway` kontrollieren. |
| `NS8CollectorTelemetryStale` | `critical` | Keine Metriken seit `15m` (`offset 15m unless current`) für `5m` | WAN-Verbindung am Kundenstandort, `alloy.service` auf dem NS8-Knoten und Token-Gültigkeit (`Test Hub Connection`) prüfen; WAL puffert Daten lokal weiter. |
| `NS8HighCpuUsage` | `warning` | Ø CPU-Auslastung `> 90%` (`5m`-Fenster) für `15m` | Im Dashboard *NethServer 8 Pods, Module & Container* prüfen, welches NS8-Modul (`ns8_module_cpu_seconds_total`) die Last verursacht. |
| `NS8CriticalCpuSaturation` | `critical` | Ø CPU-Auslastung `> 97%` (`5m`-Fenster) für `15m` | Akute Überlastung: hängende Container/ClamAV/Rspamd/Backup-Läufe identifizieren oder vCPU-Anzahl des NS8-Knotens erhöhen. |
| `NS8HighMemoryUsage` | `warning` | Host-RAM-Belegung `> 90%` für `10m` | Top-Pods nach Working-Set-RAM (`ns8_module_memory_working_set_bytes`) prüfen und Speicherausbau planen. |
| `NS8CriticalMemoryUsage` | `critical` | Host-RAM-Belegung `> 95%` für `5m` | Akute OOM-Gefahr: speicherintensive Module prüfen, ggf. wartungsarm neu starten und Host-RAM erweitern. |
| `NS8SwapMissing` | `warning` | `node_memory_SwapTotal_bytes == 0` für `30m` | Auf dem NS8-Host mindestens 2–4 GiB Swap einrichten, um Lastspitzen von Rootless-Containern abzufedern. |
| `NS8SwapAlmostFull` | `warning` | Swap-Belegung `> 85%` für `15m` | Dauerhaften Speicherdruck beseitigen; Swap-Nutzung pro NS8-Modul (`ns8_module_memory_swap_bytes`) analysieren. |
| `NS8PartitionSpaceWarning` | `warning` | Reale Partition `> 85%` und `<= 95%` belegt für `10m` | Alte Container-Images (`podman image prune`), Logs oder nicht benötigte Daten auf der betroffenen Partition bereinigen. |
| `NS8PartitionSpaceCritical` | `critical` | Reale Partition `> 95%` belegt für `5m` | Sofort Speicherplatz freigeben oder Volume vergrößern, bevor Datenbanken (`mariadb`, `postgres`, Prometheus/Loki) stoppen. |
| `NS8DiskFillPrediction24h` | `warning` | `< 30%` frei und `predict_linear(...[6h], 24h) < 0` für `30m` | Starkes Datenwachstum (z. B. Mailspool, Nextcloud, WAL oder Log-Flut) identifizieren, bevor die Partition vollläuft. |
| `NS8MdadmRaidDegraded` | `critical` | Ausgefallene oder fehlende Disk in `node_md_disks` für `2m` | `cat /proc/mdstat` & `mdadm --detail` auf dem NS8-Host prüfen, defekten Datenträger zeitnah tauschen und Rebuild überwachen. |
| `NS8ResticBackupFailed` | `critical` | `ns8_backup_status == 0` oder `ns8_backup_failed > 0` für `5m` | Im NS8 Cluster-Admin unter *Backup* Zielspeicher-Erreichbarkeit, Zugangsdaten und Restic-Logs für `module_id` prüfen. |
| `NS8ResticBackupStale` | `warning` | Letztes erfolgreiches Backup `> 36h` alt für `15m` | Geplanten Backup-Zeitplan, hängende Backup-Tasks oder deaktivierte Sicherungsjobs im NS8 Cluster-Admin kontrollieren. |
| `NS8ContainerCrashLoop` | `critical` | `>= 3` Neustarts in `15m` oder `ns8_container_running == 0` für `5m` | Modul-Logs im *Zentralen Log-Explorer* (`unit` / `module_id`) öffnen und `systemctl --user status` im Modul-Kontext prüfen. |
| `NS8ContainerInfoAbsent` | `warning` | `ns8_container_info` verschwunden oder fehlt komplett für `10m` | Prüfen, ob ein Modul entfernt wurde oder `ns8-collector-textfile.timer` / `ns8-metrics` gestört ist. |
| `NS8SystemdUnitFailed` | `critical` | System- oder User-Systemd-Unit im Status `failed` für `5m` | `journalctl -xe` bzw. `runagent -m <modul> systemctl --user status <unit>` prüfen und Ursache beheben. |
| `NS8ModuleOOMKilled` | `critical` | `increase(ns8_module_oom_kills_total[10m]) > 0` (`0m`) | Ein Prozess im NS8-Pod `module_id` wurde vom Kernel wegen Speichermangels beendet: Modul-Speicherlimit (`memory.max`) oder Host-RAM erhöhen und Container-Gesundheit prüfen. |
| `NS8ModuleMemoryNearLimit` | `warning` | Working-Set-RAM `> 90%` von `ns8_module_memory_limit_bytes` für `10m` | Konfiguriertes `cgroups v2`-Speicherlimit des NS8-Moduls erhöhen, bevor ein OOM-Kill ausgelöst wird. |
| `NS8ModuleHighSwapUsage` | `warning` | Modul-Swap `> 1 GiB` bei gleichzeitig `> 85%` Host-RAM für `15m` | Speicherleck oder Unterdimensionierung bei `module_id` untersuchen; Host-RAM aufstocken, um Paging-Latenzen zu vermeiden. |

---

### 3.2 Regelpaket 2: `linux-node.yml` — Linux-Server (15 Regeln)

| Alert-Name | Schweregrad | Auslöser & Dauer (`for`) | MSP-Runbook / Empfohlene Maßnahme |
|---|---|---|---|
| `LinuxHostDown` | `critical` | `up{device_role="linux"} == 0` für `3m` | Host-Erreichbarkeit (Ping/SSH/ILO/IPMI/Proxmox-Konsole) und `node_exporter`-Dienst prüfen. |
| `LinuxAgentTelemetryStale` | `critical` | Keine Metriken seit `15m` für `5m` | Dienststatus `systemctl status alloy` auf dem Linux-Server sowie ausgehende HTTPS-Verbindung zum Hub prüfen. |
| `LinuxHostRebooted` | `warning` | Uptime `< 600s` (`10m`) (`0m`) | Prüfen, ob ein geplanter Wartungs-Reboot vorlag oder ein unerwarteter Absturz/Stromausfall (`journalctl -b -1`) auftrat. |
| `LinuxHighCpuUsage` | `warning` | Ø CPU-Auslastung `> 90%` für `15m` | Im *Linux- & Windows-Server Deep-Dive* prüfen, ob `user`, `system`, `iowait` oder `steal` dominiert; Top-Prozesse kontrollieren. |
| `LinuxHighSystemLoad` | `warning` | Normierte `node_load15 / CPU-Kerne > 2.0` für `15m` | Run-Queue-Stau durch CPU-Überlast oder blockierende Disk-/NFS-I/O (`iowait`) analysieren. |
| `LinuxHighMemoryUsage` | `warning` | RAM-Belegung `> 90%` für `10m` | Speicherverbrauch der Applikationen prüfen und Kapazitätserweiterung einplanen. |
| `LinuxCriticalMemoryPressure` | `critical` | RAM-Belegung `> 96%` (`< 4%` verfügbar) für `5m` | Sofort speicherintensive Prozesse prüfen, bevor der Kernel-OOM-Killer Datenbanken oder Dienste beendet. |
| `LinuxOomKillDetected` | `critical` | `increase(node_vmstat_oom_kill[15m]) > 0` (`0m`) | Im *Zentralen Log-Explorer* nach `Out of memory: Killed process` suchen, betroffenen Dienst prüfen und RAM/Limits anpassen. |
| `LinuxFilesystemSpaceWarning` | `warning` | Dateisystem `> 85%` und `<= 95%` voll für `10m` | Große Verzeichnisse (`du -xhd1`), Log-Rotation oder veraltete Backups bereinigen. |
| `LinuxFilesystemSpaceCritical` | `critical` | Dateisystem `> 95%` voll für `5m` | Umgehend Platz schaffen oder LVM/Partition erweitern, um Schreibfehler zu verhindern. |
| `LinuxFilesystemInodesExhausting` | `warning` | Inode-Belegung `> 90%` für `10m` | Verzeichnisse mit Millionen Kleindateien (z. B. `/var/spool`, Session-/Cache-Ordner) bereinigen. |
| `LinuxFilesystemReadOnly` | `critical` | `node_filesystem_readonly == 1` für `2m` | Kritischer Storage-/Dateisystemfehler: `dmesg`/SMART/Hypervisor-Storage prüfen und Wartungsfenster für `fsck` einplanen. |
| `LinuxDiskIoSaturation` | `warning` | Disk-I/O-Zeit `> 90%` (`5m`-Rate) für `15m` | Im Server-Deep-Dive Lese-/Schreib-Latenz (`ms`) und IOPS prüfen; langsame Datenbankabfragen oder Backup-Last entzerren. |
| `LinuxSystemdServiceFailed` | `warning` | `node_systemd_unit_state{state="failed"} == 1` für `5m` | `systemctl status <name>` und Journald-Logs im Explorer prüfen; Dienst reparieren bzw. neu starten. |
| `LinuxNtpOutOfSync` | `warning` | `node_timex_sync_status == 0` oder Offset `> 0.5s` für `15m` | `chronyc sources` / `timedatectl` und UDP-Port `123` prüfen (wichtig für Kerberos/AD, TLS und korrekte Metrik-Zeitstempel). |

---

### 3.3 Regelpaket 3: `windows-node.yml` — Windows Server & Rollen (12 Regeln)

| Alert-Name | Schweregrad | Auslöser & Dauer (`for`) | MSP-Runbook / Empfohlene Maßnahme |
|---|---|---|---|
| `WindowsHostDown` | `critical` | `up{device_role="windows"} == 0` für `3m` | Server-Erreichbarkeit (Hypervisor/RDP/Ping) sowie `windows_exporter` (`:9182`) prüfen. |
| `WindowsAgentTelemetryStale` | `critical` | Keine Remote-Write-Metriken seit `15m` für `5m` | Windows-Hintergrunddienst `Alloy` (`Get-Service Alloy`) und ausgehende HTTPS-Freigabe zum Hub prüfen. |
| `WindowsHostRebooted` | `warning` | System-Uptime `< 600s` (`0m`) | Windows System-EventLog (Event-IDs `1074`, `6008`, `41`) im *Zentralen Log-Explorer* auf ungeplanten Neustart prüfen. |
| `WindowsHighCpuUsage` | `warning` | Ø CPU-Auslastung `> 90%` für `15m` | Task-Manager / Ressourcenmonitor auf hängende Prozesse, Antivirus-Scans oder SQL/IIS-Spitzen prüfen. |
| `WindowsLowAvailableMemoryWarning` | `warning` | Physische RAM-Auslastung `> 90%` für `10m` | Arbeitsspeicherbelegung (z. B. SQL Server, Exchange, Terminalserver-Sitzungen) prüfen und RAM-Ausbau planen. |
| `WindowsCriticalAvailableMemory` | `critical` | Freier physischer RAM `< 536870912` (`< 512 MiB`) für `5m` | Akuter Speichermangel und Paging-Gefahr: Speicherfresser identifizieren und Server-RAM kurzfristig erweitern. |
| `WindowsLogicalDiskLowWarning` | `warning` | Logisches Laufwerk (`C:`–`Z:`) `< 15%` und `>= 5%` frei für `10m` | `WinSxS`/Temp/IIS-Logs/Schattenkopien bereinigen oder virtuelle Festplatte vergrößern. |
| `WindowsLogicalDiskLowCritical` | `critical` | Logisches Laufwerk (`C:`–`Z:`) `< 5%` frei für `5m` | Sofort Speicherplatz schaffen, bevor AD/NTDS, SQL oder Spooler den Betrieb einstellen. |
| `WindowsAutomaticServiceStopped` | `warning` | Dienst mit `start_mode="auto"` steht auf `stopped` für `5m` *(Harmlose Update-Dienste gefiltert)* | Im *Linux- & Windows-Server Deep-Dive* betroffenen Dienstnamen ablesen, EventLog prüfen und Dienst starten (`Start-Service`). |
| `WindowsActiveDirectoryUnhealthy` | `critical` | Dienst `NTDS != running`, Replikationsstau `> 50` oder Schema-Mismatch für `5m` | Domain Controller umgehend mit `repadmin /replsummary` und `dcdiag` prüfen; DNS- und Netzwerkverbindung zwischen DCs sichern. |
| `WindowsDnsServerDegraded` | `critical` | Dienst `DNS != running` oder Zonentransfer-Fehler `> 0` für `5m` | Windows-DNS-Dienst und DNS-EventLog kontrollieren; sekundäre Zonen/Forwarder überprüfen. |
| `WindowsSmbServerUnhealthy` | `critical` | Dienst `LanmanServer != running` oder `> 50.000` offene Dateien für `5m` | Dateiserver-Dienst `LanmanServer` sowie offene SMB-Sitzungen/Handles (`Get-SmbOpenFile`) auf Handle-Leaks prüfen. |

---

### 3.4 Regelpaket 4: `proxmox-ve.yml` — Proxmox VE Virtualisierung (11 Regeln)

| Alert-Name | Schweregrad | Auslöser & Dauer (`for`) | MSP-Runbook / Empfohlene Maßnahme |
|---|---|---|---|
| `ProxmoxExporterUnreachable` | `critical` | `up{device_role="proxmox"} == 0` für `3m` | Erreichbarkeit der Proxmox-API (`:8006`), Gültigkeit des PVE-API-Tokens (`PVEAuditor`) und `pve-exporter.service` prüfen. |
| `ProxmoxNodeOffline` | `critical` | `pve_up{id=~"node/.*"} == 0` für `2m` | Hypervisor-Host über IPMI/iDRAC/iLO prüfen; HA-Failover der VMs/LXCs im Proxmox-Cluster überwachen. |
| `ProxmoxClusterQuorumLost` | `critical` | `pve_up{id=~"cluster/.*"} == 0` oder `pve_cluster_quorate == 0` für `1m` | Kritisch: Split-Brain-/Quorum-Verlust! Corosync-Netzwerk und `pvecm status` sofort prüfen. |
| `ProxmoxNodeHighCpu` | `warning` | Hypervisor-CPU `> 90%` für `15m` | Im Dashboard *Proxmox VE, Netzwerk, USV & NAS* die *Top-10 VMs & LXCs nach CPU-Last* prüfen und Gäste ggf. per Live-Migration verteilen. |
| `ProxmoxNodeHighMemory` | `warning` | Hypervisor-RAM `> 92%` für `10m` | VM-RAM-Zuweisungen/Ballooning prüfen oder Gäste auf andere Clusterknoten migrieren. |
| `ProxmoxHighCpuIoWait` | `warning` | `pve_iowait_ratio > 20%` (oder Host-`iowait > 20%`) für `10m` | Storage-Engpass (ZFS-Scrub, Backup-Job `vzdump`/PBS, langsame Disks/CEPH) analysieren. |
| `ProxmoxStorageUnavailable` | `critical` | `pve_up{id=~"storage/.*"} == 0` für `3m` | NFS/SMB/iSCSI/PBS/ZFS-Storage-Pool `id` auf dem Proxmox-Knoten prüfen und Mount wiederherstellen. |
| `ProxmoxStoragePoolSpaceWarning` | `warning` | Storage-Pool `> 85%` und `<= 95%` belegt für `10m` | Alte Snapshots, verwaiste VM-Disks oder ISO/Backup-Archive im Storage-Pool bereinigen. |
| `ProxmoxStoragePoolSpaceCritical` | `critical` | Storage-Pool `> 95%` belegt für `5m` | Sofort Platz freigeben! Bei Thin-Provisioning droht sonst ein Einfrieren (`io-error`) laufender VMs. |
| `ProxmoxZfsPoolDegraded` | `critical` | ZFS-Pool nicht im Status `ONLINE` für `2m` | `zpool status -v` auf dem Hypervisor prüfen, defekte SSD/HDD ersetzen und Resilvering überwachen. |
| `ProxmoxAutoStartGuestStopped` | `critical` | VM/LXC mit `onboot == 1` ist `pve_up == 0` für `5m` | Produktiv-VM/-LXC (`Start at boot` aktiv) ist gestoppt: Proxmox-Task-Log prüfen und Gast starten (oder während Wartung Silence setzen). |

---

### 3.5 Regelpaket 5: `blackbox-web-ssl.yml` — Web, DNS, TCP & SSL-Zertifikate (8 Regeln)

| Alert-Name | Schweregrad | Auslöser & Dauer (`for`) | MSP-Runbook / Empfohlene Maßnahme |
|---|---|---|---|
| `BlackboxWebEndpointDown` | `critical` | `probe_success == 0` (HTTP/HTTPS) für `2m` | DNS, Firewall, Reverse-Proxy (Traefik/Nginx) und Backend-Applikation des Ziel-Endpunkts prüfen. |
| `BlackboxHttpServerError5xx` | `critical` | `probe_http_status_code >= 500` für `2m` | Backend-/Applikationsfehler (`500`/`502`/`503`/`504`): Upstream-Container und Applikations-Logs prüfen. |
| `BlackboxHttpClientError4xx` | `warning` | `400 <= probe_http_status_code < 500` für `5m` | Unerwarteter `401`/`403`/`404`-Status: URL-Pfad, Auth-Konfiguration oder gewähltes Blackbox-Modul kontrollieren. |
| `BlackboxSlowHttpResponse` | `warning` | Antwortzeit `probe_duration_seconds > 3s` (bei `probe_success == 1`) für `5m` | Im Dashboard *Web, DNS & SSL-Zertifikate (SLA)* das Panel *Gestapelte HTTP-Phasen-Antwortzeit* prüfen (`DNS`, `TLS` oder `Server Processing`). |
| `BlackboxTlsCertificateExpiringWarning` | `warning` | Zertifikats-Restlaufzeit `< 21` und `>= 7` Tage für `15m` | Automatische ACME-/Let's-Encrypt-Erneuerung prüfen bzw. manuelles Kaufzertifikat rechtzeitig verlängern. |
| `BlackboxTlsCertificateExpiringCritical` | `critical` | Zertifikats-Restlaufzeit `< 7` Tage (oder abgelaufen) für `5m` | Sofort Zertifikat erneuern und Webserver/Reverse-Proxy neu laden, um Browser-/API-Ausfälle zu verhindern. |
| `BlackboxDnsResolutionFailed` | `critical` | `probe_success{module=~"dns.*"} == 0` oder `probe_dns_query_succeeded == 0` für `2m` | Überwachten DNS-Server, Zonen-Autorität und Firewall-Freigaben (`53/udp` & `53/tcp`) prüfen. |
| `BlackboxTcpPortProbeFailed` | `critical` | `probe_success{module=~"tcp.*"} == 0` für `2m` | Ziel-Dienst (z. B. SMTP `:25`/`:587`, IMAPS `:993`, LDAPS `:636`, RDP/VPN) und Firewall-Regeln prüfen. |

---

### 3.6 Regelpaket 6: `snmp-network-ups.yml` — Netzwerk, USV, NAS & Drucker (15 Regeln)

| Alert-Name | Schweregrad | Auslöser & Dauer (`for`) | MSP-Runbook / Empfohlene Maßnahme |
|---|---|---|---|
| `SnmpTargetUnreachable` | `critical` | `up{device_role=~"snmp-.*"} == 0` für `3m` | Strom-/Netzwerkverbindung des Geräts, SNMP-Dienst (`161/udp`), IP-ACL sowie SNMPv2c-Community bzw. SNMPv3-Zugangsdaten prüfen. |
| `SnmpCriticalInterfaceDown` | `critical` | Admin-aktives Uplink/WAN/Trunk/LAG/Server/NAS-Interface meldet `ifOperStatus == 2` für `2m` | Physischen Link, SFP+/Kabel, Switch-Port oder ISP-WAN-Leitung (`ifName` / `ifAlias`) überprüfen. |
| `SnmpInterfaceHighPacketErrorRate` | `warning` | `rate(ifInErrors[5m]) + rate(ifOutErrors[5m]) > 2/s` für `10m` | Defektes Patchkabel, verschmutztes Glasfaser-SFP, Duplex-Mismatch oder EMV-Störung auf Port `ifName` beheben. |
| `SnmpInterfaceHighPacketDiscardRate` | `warning` | `rate(ifInDiscards[5m]) + rate(ifOutDiscards[5m]) > 10/s` für `10m` | Port-Überlastung (Microbursts/Pufferüberlauf) im Panel *Switch-/Firewall-Port-Auslastung (%)* prüfen; QoS/Uplink-Bandbreite anpassen. |
| `SnmpUpsOnBattery` | `critical` | `upsOutputSource == 5`, `upsBasicOutputStatus == 3` oder `upsBatteryStatus == 3` für `1m` | Stromausfall am Kundenstandort! Verbleibende Stützzeit (`upsEstimatedMinutesRemaining`) beobachten und ggf. kontrollierten Shutdown vorbereiten. |
| `SnmpUpsBatteryLow` | `critical` | Batterieladung `< 30%` für `1m` | Kritische Restladung: sofort geordneten Shutdown nicht-essentieller VMs/Hypervisoren prüfen bzw. sicherstellen, dass Shutdown-Agenten greifen. |
| `SnmpUpsReplaceBatteryNeeded` | `warning` | `upsAdvBatteryReplaceIndicator == 2`, `upsBatteryStatus == 4` oder `upsAlarmBatteryBad > 0` für `10m` | Wartungsticket erstellen und verschlissenen USV-Akkusatz zeitnah austauschen. |
| `SnmpNasVolumeOrDiskDegraded` | `critical` | Synology `raidStatus >= 11` oder `diskStatus >= 4` für `2m` | Im Synology DSM Storage-Manager ausgefallenes Laufwerk identifizieren, Ersatzplatte einsetzen und RAID-Reparatur überwachen. |
| `SnmpNasHighDiskTemperature` | `warning` | `diskTemperature > 55°C` oder `systemTemperature > 65°C` für `10m` | Serverraum-Klimatisierung, Staubfilter und NAS-Lüfterdrehzahl prüfen. |
| `SnmpQnapVolumeDegraded` | `critical` | `qnapVolumeStatus` nicht `Ready`/`OK`/`Normal` für `2m` | In QNAP QTS / QuTS hero *Speicher & Snapshots* den betroffenen RAID-Pool (`qnapVolumeDescr`) und SMART-Werte kontrollieren. |
| `SnmpQnapDiskTemperatureWarning` | `warning` | `55°C < qnapDiskTemperature <= 62°C` für `10m` | Belüftung des QNAP-Chassis und Umgebungstemperatur für Laufwerk `qnapDiskID` prüfen. |
| `SnmpQnapDiskTemperatureCritical` | `critical` | `qnapDiskTemperature > 62°C` für `5m` | Akute Überhitzungsgefahr: Kühlung sofort wiederherstellen, um Laufwerksausfälle im RAID-Verbund zu verhindern. |
| `SnmpPrinterSupplyLowWarning` | `warning` | RFC-3805-Verbrauchsmaterial (`prtMarkerSuppliesLevel / MaxCapacity`) `< 10%` und `>= 3%` für `15m` | Ersatz-Tonerkartusche / Trommeleinheit (`prtMarkerSuppliesDescription`) für den Kundenstandort bereitstellen. |
| `SnmpPrinterSupplyCritical` | `critical` | RFC-3805-Verbrauchsmaterial `< 3%` für `5m` | Verbrauchsmaterial fast leer: zeitnahen Austausch am Netzwerkdrucker veranlassen. |
| `SnmpPrinterCriticalAlertActive` | `critical` | `prtAlertSeverityLevel == 3` (kritischer RFC-3805-Hardwarealarm) für `5m` | Meldung `prtAlertDescription` (z. B. Papierstau, offene Abdeckung, Fixiereinheit-Fehler) vor Ort am Gerät beheben. |
