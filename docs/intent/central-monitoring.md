# Confirmed Statement of Intent: NS8 Central Monitoring Service

- **Status:** Bestätigt am 2026-11-20 · Synchronisiert auf Release `v1.1.0` am 2026-11-23
- **Repository-Typ:** Gemeinsames NethServer-8-Monorepo (`hub/` + `collector/` + `shared/`) für zwei eigenständige NS8 Software-Center-Module

---

## Kern-Zielbild

- **Ergebnis (Outcome):** Ein quelloffenes NethServer-8-Monorepo mit zwei eigenständigen, 100 % rootless NS8-Modulen (kompatibel mit Rocky Linux 9 / Python 3.9 & Debian 12):
  1. **`central-monitoring-hub`:** Zentraler Monitoring- & Logging-Server mit Prometheus (inkl. optionalem Thanos für S3-Langzeitspeicher), Grafana 11 (**6** deutsche Enterprise-NOC-Dashboards mit **117** Panels), Alertmanager, Loki 3, Blackbox- & SNMP-Probes (`if_mib`, `apcupsd`, `synology`, `qnap`, `mikrotik`, `fortigate`, `printer` RFC 3805, `generic`), `prom-label-proxy`, Auth-Gateway, integriertem **Rootless `cgroups v2` Hub-Self-Monitoring** sowie 1-Klick-Onboarding-Generator für Standalone-Agenten (Grafana Alloy auf Windows, Linux und Docker).
  2. **`central-monitoring-collector`:** Leichtgewichtiges NS8-Modul (auf Basis von Grafana Alloy `v1.4.2`) für Kunden-NS8-Cluster, das den Kunden-NS8 inkl. **aller lokalen Rootless- & Rootful-NS8-Pods/Module per Linux `cgroups v2`** (`ns8_module_*`, `ns8_pod_unit_*`, Restic-Backups, Container) sowie Systeme im Kunden-LAN (Windows, Linux, Proxmox VE, Switches/Firewalls/USVs/Synology/QNAP/Drucker per SNMP v2c/v3 & Syslog `5514`) einsammelt, bei Verbindungsabbruch lokal per Write-Ahead-Log (WAL) puffert und verschlüsselt per HTTPS + Kunden-Token an den Hub sendet.
- **Nutzer (User):** Primär das **MSP-/Systemhaus-Team** (zentraler Flottenblick über alle Mandanten inkl. Live-NS8-LDAP/AD-Gruppen- & Benutzer-Mehrfachauswahl via `NsMultiSelect`, Login-Tester und **1-Klick-Kundenansicht `?orgId=<id>`**) sowie optional **Endkunden mit technisch strikt isolierten Multi-User-Zugängen** (`Viewer`- & `Editor`-Konten in eigenen Grafana-Organisationen mit gesperrten Read-Only-Datasources + `prom-label-proxy` auf PromQL-Ebene + `X-Scope-OrgID` in Loki + Read-Only-Proxy-Allowlist + serverseitiges Label-Enforcement beim Daten-Ingest).
- **Warum jetzt (Why now):** Vollständige **Ablösung eines bestehenden Systemhaus-Monitoring-Systems** (wie PRTG, Checkmk oder Zabbix) auf NethServer-8-Basis. Dafür ist Funktionsparität bei **Metriken (inkl. granularer NS8-Pod-Ressourcen), Zustandsprüfungen (**6** Regelpakete mit **81** Alarmregeln) und zentralen Logs (Loki inkl. Volltext-Log-Explorer)** über NS8, Windows, Linux, Proxmox VE, Websites/SSL und SNMP Voraussetzung, um das Altsystem abschalten zu können.
- **Erfolgskriterium (Success):**
  - Kundenstandorte mit und ohne eigenen NS8 (auch hinter NAT und mit überlappenden privaten IP-Netzen wie `192.168.1.0/24`) liefern Metriken & Logs zuverlässig an den Hub (inkl. manipulationsgeschützter Windows-Dienst- & Linux-systemd-Installer).
  - **6** vorinstallierte Standard-Alarmpakete (**81** Regeln) pro Geräteklasse sowie Wartungsfenster (Silences für Patchdays/Wartungen) routen Alarme zuverlässig an E-Mail (NS8-Smarthost/SMTP), Webhooks (Ticketsysteme/PSA), Team-Chat (MS Teams/Slack), Push-Dienste (Ntfy/Telegram/Gotify) sowie optional an hinterlegte Kunden-Mailadressen.
  - Kein Kunden-Zugang (weder `Viewer` noch `Editor`) kann technisch Metriken oder Logs fremder Mandanten abfragen, verändern oder überschreiben.
- **Rahmenbedingungen (Constraints):**
  - 100 % Rootless-Podman auf NethServer 8 ohne Port- oder Konfigurationskonflikte zum eingebauten Core-Modul `ns8-metrics` (**57** Draft-07 Schemata, **17** systemd `.service`-Units + **2** `.timer`-Units).
  - Skalierbar für **> 1.500 Systeme und mehrmonatige Aufbewahrung** durch wahlweise lokalen Pod-Speicher oder optionalen **S3-/MinIO-kompatiblen Objektspeicher** (Loki nativ + Thanos für Prometheus-Langzeitblöcke).
  - Tägliches NS8-Restic-Backup sichert standardmäßig Konfiguration, Mandanten/Portal-Zugänge/Tokens, Regeln, Silences & `grafana.db` schlank und konsistent (Rohdaten-Backup optional per Schalter `backup_include_tsdb`).
  - 100 % Open-Source-Komponenten (GPL-3.0-or-later) ohne kostenpflichtige Enterprise-Lizenzen.
- **Explizit außer Scope (Out of scope):**
  - Änderungen oder Eingriffe am internen NS8-Core-Modul `ns8-metrics`.
  - Ein eigenes Ticketsystem oder RMM-/Fernwartungsfunktionen (Anbindung erfolgt über Webhooks/E-Mail).
  - Agenten-Installation auf geschlossenen Netzwerk-/USV-/Firewall-/Drucker-Appliances (Abfrage erfolgt lokal über den Standort-Collector via SNMP & Syslog).
  - Kostenpflichtige Grafana-Enterprise-Funktionen.
