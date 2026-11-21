# Confirmed Statement of Intent: NS8 Central Monitoring Service

- **Status:** Bestätigt am 2026-11-20
- **Repository-Typ:** Gemeinsames NethServer-8-Monorepo (`hub/` + `collector/` + `shared/`) für zwei eigenständige NS8 Software-Center-Module

---

## Kern-Zielbild

- **Ergebnis (Outcome):** Ein quelloffenes NethServer-8-Monorepo mit zwei eigenständigen, rootless NS8-Modulen:
  1. **`central-monitoring-hub`:** Zentraler Monitoring- & Logging-Server mit Prometheus (inkl. optionalem Thanos für S3-Langzeitspeicher), Grafana, Alertmanager, Loki, Blackbox- & SNMP-Probes, `prom-label-proxy`, Auth-Gateway sowie 1-Klick-Onboarding-Generator für Standalone-Agenten (Grafana Alloy auf Windows, Linux und Docker).
  2. **`central-monitoring-collector`:** Leichtgewichtiges NS8-Modul (auf Basis von Grafana Alloy) für Kunden-NS8-Cluster, das den Kunden-NS8 selbst sowie Systeme im Kunden-LAN (Windows, Linux, Proxmox VE, Switches/Firewalls/USVs/NAS per SNMP & Syslog) einsammelt, bei Verbindungsabbruch lokal per Write-Ahead-Log (WAL) puffert und verschlüsselt per HTTPS + Kunden-Token an den Hub sendet.
- **Nutzer (User):** Primär das **MSP-/Systemhaus-Team** (zentraler Flottenblick über alle Mandanten inkl. NS8-LDAP/AD-Login) sowie optional **Endkunden mit technisch strikt isolierten Read-Only-Zugängen** (eigene Grafana-Organisationen + `prom-label-proxy` auf PromQL-Ebene + `X-Scope-OrgID` in Loki + serverseitiges Label-Enforcement beim Daten-Ingest).
- **Warum jetzt (Why now):** Vollständige **Ablösung eines bestehenden Systemhaus-Monitoring-Systems** (wie PRTG, Checkmk oder Zabbix) auf NethServer-8-Basis. Dafür ist Funktionsparität bei **Metriken, Zustandsprüfungen und zentralen Logs (Loki)** über NS8, Windows, Linux, Proxmox VE, Websites/SSL und SNMP Voraussetzung, um das Altsystem abschalten zu können.
- **Erfolgskriterium (Success):**
  - Kundenstandorte mit und ohne eigenen NS8 (auch hinter NAT und mit überlappenden privaten IP-Netzen wie `192.168.1.0/24`) liefern Metriken & Logs zuverlässig an den Hub.
  - Vorinstallierte Standard-Alarmpakete pro Geräteklasse sowie Wartungsfenster (Silences für Patchdays/Wartungen) routen Alarme zuverlässig an E-Mail (NS8-Smarthost), Webhooks (Ticketsysteme/PSA), Team-Chat (MS Teams/Slack), Push-Dienste (Ntfy/Telegram/Gotify) sowie optional an hinterlegte Kunden-Mailadressen.
  - Kein Kunden-Zugang kann technisch Metriken oder Logs fremder Mandanten abfragen oder überschreiben.
- **Rahmenbedingungen (Constraints):**
  - 100 % Rootless-Podman auf NethServer 8 ohne Port- oder Konfigurationskonflikte zum eingebauten Core-Modul `ns8-metrics`.
  - Skalierbar für **> 1.500 Systeme und mehrmonatige Aufbewahrung** durch wahlweise lokalen Pod-Speicher oder optionalen **S3-/MinIO-kompatiblen Objektspeicher** (Loki nativ + Thanos für Prometheus-Langzeitblöcke).
  - Tägliches NS8-Restic-Backup sichert standardmäßig Konfiguration, Mandanten/Tokens, Regeln & Grafana-Dashboards schlank und konsistent (Rohdaten-Backup optional per Schalter).
  - 100 % Open-Source-Komponenten ohne kostenpflichtige Enterprise-Lizenzen.
- **Explizit außer Scope (Out of scope):**
  - Änderungen oder Eingriffe am internen NS8-Core-Modul `ns8-metrics`.
  - Ein eigenes Ticketsystem oder RMM-/Fernwartungsfunktionen (Anbindung erfolgt über Webhooks/E-Mail).
  - Agenten-Installation auf geschlossenen Netzwerk-/USV-/Firewall-Appliances (Abfrage erfolgt lokal über den Standort-Collector via SNMP & Syslog).
  - Kostenpflichtige Grafana-Enterprise-Funktionen.
