# Handbuch & Kurzanleitung für Endkunden im Monitoring-Portal (`docs/customer-portal-guide.md`)

Willkommen in Ihrem **IT-Monitoring- & Systemstatus-Portal**! Über dieses Webportal stellt Ihnen Ihr IT-Dienstleister (Managed Service Provider) jederzeit einen transparenten Echtzeit-Überblick über Verfügbarkeit, Auslastung, Datensicherungen, Zertifikatslaufzeiten und sicherheitsrelevante Systemereignisse Ihrer IT-Infrastruktur bereit.

---

## 1. Anmeldung & Einstieg

1. Öffnen Sie im Browser die von Ihrem IT-Dienstleister mitgeteilte Portal-Adresse:
   ```text
   https://<monitoring-domain-ihres-it-dienstleisters>/login
   ```
2. Melden Sie sich mit Ihrem persönlichen **Benutzernamen** und **Passwort** an.
3. Unmittelbar nach der Anmeldung landen Sie automatisch auf Ihrem zentralen Start-Dashboard **`NS8 & MSP Gesamtübersicht`**, auf dem alle überwachten Systeme und Standorte Ihres Unternehmens zusammengefasst sind.

> [!TIP]
> **Passwort vergessen oder weiterer Mitarbeiter-Zugang benötigt?**
> Aus Sicherheitsgründen werden Portal-Konten zentral durch Ihren IT-Dienstleister verwaltet. Wenden Sie sich einfach kurz an Ihren Support-Ansprechpartner — dieser kann jederzeit weitere persönliche Zugänge für Ihr Team einrichten, nicht mehr benötigte Konten sperren oder Ihr Passwort zurücksetzen.

---

## 2. Berechtigungsrollen im Kundenportal (`Viewer` vs. `Editor`)

Ihr IT-Dienstleister weist jedem Benutzerkonto Ihres Unternehmens eine von zwei Rollen zu:

| Rolle | Berechtigungen im Portal | Typischer Einsatzbereich |
| :--- | :--- | :--- |
| **`Viewer` (Lesezugriff — Standard)** | Uneingeschränktes Betrachten aller Dashboards, Zeitraum-Auswahlen, Standort-/Server-Filter und Log-Recherchen; keine versehentlichen Änderungen an Ansichten möglich. | Geschäftsführung, IT-Koordinatoren, Bereitschaft, Revision |
| **`Editor` (Erweiterte Auswertung)** | Wie `Viewer`, zusätzlich Möglichkeit zum Anlegen und Speichern eigener Auswertungs-Dashboards innerhalb Ihrer eigenen Kunden-Organisation (Datenquellen und Systemkonfigurationen bleiben schreibgeschützt). | Interne IT-Abteilung des Kunden (Co-Managed IT) |

---

## 3. Navigation & Zeitbereich auswählen

- **Zwischen Dashboards wechseln:**
  - Klicken Sie oben in den Dashboards direkt auf die **Schnellwahl-Links** (z. B. zu Server-Details, NS8-Modulen oder dem Log-Explorer), **oder**
  - öffnen Sie links im Hauptmenü **Dashboards**, um alle **6 Standard-Dashboards** auszuwählen.
- **Zeitraum anpassen (oben rechts):**
  - Standardmäßig sehen Sie die letzten **1 bis 6 Stunden** (bzw. 24 Stunden). Über die Zeitauswahl oben rechts (Uhr-Symbol) können Sie jederzeit z. B. *Letzte 24 Stunden*, *Letzte 7 Tage*, *Letzte 30 Tage* oder ein exaktes Datum/Uhrzeitfenster eines Vorfalls auswählen — oder mit der Maus direkt in ein Diagramm hineinzoomen.
- **Automatische Aktualisierung:**
  - Rechts neben der Zeitauswahl können Sie ein festes Aktualisierungsintervall (z. B. `30s` oder `1m`) aktivieren, beispielsweise für einen Wandmonitor in Ihrer internen IT.

---

## 4. Ihre 6 Monitoring-Dashboards im Überblick

Alle Dashboards verfügen am oberen Bildschirmrand über komfortable **Dropdown-Filter**, mit denen Sie gezielt zwischen Ihren Standorten und Systemen umschalten können:

### 4.1 `NS8 & MSP Gesamtübersicht` *(Ihr automatisches Start-Dashboard)*
- **Zweck:** Kompakte Management- und Gesundheitsübersicht Ihrer gesamten überwachten Infrastruktur.
- **Wichtige Inhalte:** Erreichbarkeit aller Systeme, Status der täglichen NethServer-8-Datensicherungen (Restic), aktuelle CPU-/RAM-/Speicherplatz-Spitzenwerte, offene Warnhinweise sowie direkte Sprunglinks in die Detailansichten.
- **Filter oben:** Standort (`$site`).

### 4.2 `NethServer 8 Pods, Module & Container`
- **Zweck:** Detaillierte Einsicht in Ihre NethServer-8-Applikationsserver und die darauf betriebenen Dienste (z. B. Mailserver `mail1`, Nextcloud `nextcloud1`, Datei-/AD-Server `samba1`, Web-Proxy `traefik1`).
- **Wichtige Inhalte:** Ressourcenverbrauch (CPU, Arbeitsspeicher/Working-Set, Swap, Festplatten-I/O, Prozessanzahl) pro NS8-Modul und einzelnem Container, Speichergrenzen/OOM-Überwachung sowie Zeitpunkte und Erfolg der letzten Modul-Backups.
- **Filter oben:** Standort (`$site`), NS8-Knoten (`$instance`), Modul (`$module_id`, z. B. gezielt `mail1` auswählen).

### 4.3 `Linux- & Windows-Server Deep-Dive`
- **Zweck:** Tiefenanalyse Ihrer physischen und virtuellen Windows- und Linux-Server (z. B. Active Directory Domain Controller, Terminal-/RDS-Server, SQL-/ERP-Server, Linux-Applikationsserver).
- **Wichtige Inhalte:** CPU-Last & Warteschlangen, freier Arbeitsspeicher, Laufwerks- & Partitionsbelegung (inkl. Füllstandsverlauf), Netzwerkdurchsatz, Status automatisch startender Windows-Dienste bzw. Linux-`systemd`-Dienste sowie aktuelle Systemmeldungen.
- **Filter oben:** Standort (`$site`), Systemtyp (`$device_role`: `windows` / `linux`), Server (`$instance`).

### 4.4 `Proxmox VE, Netzwerk, USV & NAS`
- **Zweck:** Infrastruktur-Ansicht für Virtualisierung, Netzwerk-Switches, Firewalls, unterbrechungsfreie Stromversorgungen (USV) und Netzwerkspeicher (Synology / QNAP NAS) sowie Netzwerkdrucker.
- **Wichtige Inhalte:**
  - **Proxmox VE:** Cluster-Quorum, Host-Auslastung, ZFS-/Storage-Belegung sowie Status Ihrer virtuellen Maschinen (VMs) und Container.
  - **Switches & Firewalls:** Port-Status (Up/Down), Bandbreite (Ein-/Ausgehend) sowie Paketfehler/Verwürfe.
  - **USV & NAS / Drucker:** Batterie-Ladezustand, Restlaufzeit & Stromversorgungsstatus Ihrer USV, RAID-/Volume-Zustand und Festplattentemperaturen Ihrer NAS-Systeme sowie Verbrauchsmaterial-/Tonerstände überwachter Netzwerkdrucker.
- **Filter oben:** Standort (`$site`), Gerät / Knoten (`$instance`).

### 4.5 `Web, DNS & SSL-Zertifikate (SLA)`
- **Zweck:** Überwachung Ihrer öffentlich erreichbaren Websites, Kundenportale, Online-Shops, Mail-Eingangsports und TLS-/SSL-Zertifikate aus Sicht des Internets.
- **Wichtige Inhalte:** Aktuelle Erreichbarkeit (Verfügbarkeit in %), HTTP-Antwortzeiten, DNS-Auflösungszeiten sowie **Restlaufzeit Ihrer SSL-/TLS-Zertifikate in Tagen**, damit ablaufende Zertifikate rechtzeitig erkannt werden.
- **Filter oben:** Standort (`$site`), geprüfte URL / Domain (`$instance`).

### 4.6 `Zentraler Log- & Security-Explorer`
- **Zweck:** Zentrale Suche in System-, Dienst-, Firewall- und Sicherheitsprotokollen über Ihre Standorte hinweg.
- **So suchen Sie gezielt nach Ereignissen:**
  1. Wählen Sie oben den gewünschten **Standort (`$site`)**, optional die **Geräterolle (`$device_role`)**, das **System (`$instance`)** oder den **Schweregrad (`$level`**, z. B. `error` / `warning`).
  2. Tippen Sie in das Feld **`Suche` (`$log_search`)** einen beliebigen Suchbegriff ein (z. B. einen Benutzernamen, `4625` für fehlgeschlagene Windows-Anmeldungen, einen Dienstnamen oder eine IP-Adresse) und bestätigen Sie mit `Enter`.
  3. Die Diagramme zeigen sofort das zeitliche Auftreten der Treffer, darunter erscheinen die exakten Protokollzeilen im Klartext.

---

## 5. Sprache & Zeitzone persönlich anpassen

Jeder Benutzer kann die Oberfläche individuell einstellen:
1. Klicken Sie oben rechts auf Ihr **Benutzersymbol** -> **Profile** (Profil).
2. Wählen Sie unter **Language** zwischen **Deutsch** und **English** sowie unter **Timezone** Ihre gewünschte Zeitzone (z. B. `Browser Time` oder `Europe/Berlin`).
3. Klicken Sie auf **Save** — die Einstellung gilt sofort nur für Ihr eigenes Konto.

---

## 6. Datenschutz & Technische Mandantentrennung

Ihre Monitoring- und Protokolldaten unterliegen einer mehrstufigen technischen Isolation (**Defense-in-Depth**):
- **Verschlüsselte Übertragung:** Alle Messwerte und Protokolle werden ausschließlich TLS-verschlüsselt (`HTTPS`) vom Standort an das Rechenzentrum übertragen; es sind keine eingehenden Portfreigaben in Ihrer Unternehmens-Firewall erforderlich.
- **Strikte Datentrennung:** Ihr Portal-Zugang ist fest an Ihre eigene Organisation gebunden. Sowohl die Metrik-Datenbank (`prom-label-proxy` Abfrage-Isolation) als auch der Protokollspeicher (`Loki` Mandanten-Partitionierung) erzwingen serverseitig auf Datenbankebene, dass ausschließlich Systeme Ihres eigenen Unternehmens abgefragt werden können — ein Zugriff auf fremde Mandantendaten ist technisch ausgeschlossen.
