"""Renders SNMP Exporter v0.26 configuration (snmp.yml) with v2c/v3 auths and MSP MIB modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hub_alerting import atomic_write_text, resolve_config_dir, yaml_quote

_IF_LOOKUPS_YAML = """        lookups:
          - labels: [ifIndex]
            labelname: ifDescr
            oid: 1.3.6.1.2.1.2.2.1.2
            type: DisplayString
          - labels: [ifIndex]
            labelname: ifName
            oid: 1.3.6.1.2.1.31.1.1.1.1
            type: DisplayString
          - labels: [ifIndex]
            labelname: ifAlias
            oid: 1.3.6.1.2.1.31.1.1.1.18
            type: DisplayString"""

_COMMON_IF_METRICS_YAML = f"""      - name: ifAdminStatus
        oid: 1.3.6.1.2.1.2.2.1.7
        type: gauge
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifOperStatus
        oid: 1.3.6.1.2.1.2.2.1.8
        type: gauge
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifInOctets
        oid: 1.3.6.1.2.1.2.2.1.10
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifInDiscards
        oid: 1.3.6.1.2.1.2.2.1.13
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifInErrors
        oid: 1.3.6.1.2.1.2.2.1.14
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifOutOctets
        oid: 1.3.6.1.2.1.2.2.1.16
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifOutDiscards
        oid: 1.3.6.1.2.1.2.2.1.19
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifOutErrors
        oid: 1.3.6.1.2.1.2.2.1.20
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifHCInOctets
        oid: 1.3.6.1.2.1.31.1.1.1.6
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}
      - name: ifHCOutOctets
        oid: 1.3.6.1.2.1.31.1.1.1.10
        type: counter
        indexes:
          - labelname: ifIndex
            type: gauge
{_IF_LOOKUPS_YAML}"""

SNMP_MODULES_YAML = f"""modules:
  if_mib:
    walk:
      - 1.3.6.1.2.1.1.3.0
      - 1.3.6.1.2.1.2.2
      - 1.3.6.1.2.1.31.1.1
    metrics:
      - name: sysUpTime
        oid: 1.3.6.1.2.1.1.3.0
        type: gauge
{_COMMON_IF_METRICS_YAML}

  apcupsd:
    walk:
      - 1.3.6.1.2.1.33.1
      - 1.3.6.1.4.1.318.1.1.1
    metrics:
      - name: upsBatteryStatus
        oid: 1.3.6.1.2.1.33.1.2.1.0
        type: gauge
      - name: upsEstimatedMinutesRemaining
        oid: 1.3.6.1.2.1.33.1.2.3.0
        type: gauge
      - name: upsEstimatedChargeRemaining
        oid: 1.3.6.1.2.1.33.1.2.4.0
        type: gauge
      - name: upsOutputSource
        oid: 1.3.6.1.2.1.33.1.4.1.0
        type: gauge
      - name: upsOutputPercentLoad
        oid: 1.3.6.1.2.1.33.1.4.4.1.5
        type: gauge
        indexes:
          - labelname: upsOutputLineIndex
            type: gauge
      - name: upsAlarmBatteryBad
        oid: 1.3.6.1.2.1.33.1.6.3.1
        type: gauge
      - name: upsAdvBatteryCapacity
        oid: 1.3.6.1.4.1.318.1.1.1.2.2.1.0
        type: gauge
      - name: upsAdvBatteryReplaceIndicator
        oid: 1.3.6.1.4.1.318.1.1.1.2.2.4.0
        type: gauge
      - name: upsBasicOutputStatus
        oid: 1.3.6.1.4.1.318.1.1.1.4.1.1.0
        type: gauge
      - name: upsAdvOutputLoad
        oid: 1.3.6.1.4.1.318.1.1.1.4.2.3.0
        type: gauge

  synology:
    walk:
      - 1.3.6.1.4.1.6574.1
      - 1.3.6.1.4.1.6574.2
      - 1.3.6.1.4.1.6574.3
    metrics:
      - name: systemTemperature
        oid: 1.3.6.1.4.1.6574.1.2.0
        type: gauge
      - name: diskStatus
        oid: 1.3.6.1.4.1.6574.2.1.1.5
        type: gauge
        indexes:
          - labelname: diskIndex
            type: gauge
        lookups:
          - labels: [diskIndex]
            labelname: diskID
            oid: 1.3.6.1.4.1.6574.2.1.1.2
            type: DisplayString
      - name: diskTemperature
        oid: 1.3.6.1.4.1.6574.2.1.1.6
        type: gauge
        indexes:
          - labelname: diskIndex
            type: gauge
        lookups:
          - labels: [diskIndex]
            labelname: diskID
            oid: 1.3.6.1.4.1.6574.2.1.1.2
            type: DisplayString
      - name: raidStatus
        oid: 1.3.6.1.4.1.6574.3.1.1.3
        type: gauge
        indexes:
          - labelname: raidIndex
            type: gauge

  qnap:
    walk:
      - 1.3.6.1.2.1.1.3.0
      - 1.3.6.1.2.1.2.2
      - 1.3.6.1.2.1.31.1.1
      - 1.3.6.1.4.1.24681.1.2.17
      - 1.3.6.1.4.1.24681.1.3.6.0
      - 1.3.6.1.4.1.24681.1.3.11
    metrics:
      - name: sysUpTime
        oid: 1.3.6.1.2.1.1.3.0
        type: gauge
      - name: systemTemperature
        oid: 1.3.6.1.4.1.24681.1.3.6.0
        type: gauge
      - name: qnapVolumeStatus
        oid: 1.3.6.1.4.1.24681.1.2.17.1.6
        type: DisplayString
        indexes:
          - labelname: qnapVolumeIndex
            type: gauge
        lookups:
          - labels: [qnapVolumeIndex]
            labelname: qnapVolumeDescr
            oid: 1.3.6.1.4.1.24681.1.2.17.1.2
            type: DisplayString
      - name: qnapDiskTemperature
        oid: 1.3.6.1.4.1.24681.1.3.11.1.3
        type: gauge
        indexes:
          - labelname: qnapDiskIndex
            type: gauge
        lookups:
          - labels: [qnapDiskIndex]
            labelname: qnapDiskID
            oid: 1.3.6.1.4.1.24681.1.3.11.1.2
            type: DisplayString
{_COMMON_IF_METRICS_YAML}

  mikrotik:
    walk:
      - 1.3.6.1.2.1.1.3.0
      - 1.3.6.1.2.1.2.2
      - 1.3.6.1.2.1.31.1.1
      - 1.3.6.1.4.1.14988.1.1.3
    metrics:
      - name: sysUpTime
        oid: 1.3.6.1.2.1.1.3.0
        type: gauge
{_COMMON_IF_METRICS_YAML}

  fortigate:
    walk:
      - 1.3.6.1.2.1.1.3.0
      - 1.3.6.1.2.1.2.2
      - 1.3.6.1.2.1.31.1.1
      - 1.3.6.1.4.1.12356.101.4.1
    metrics:
      - name: sysUpTime
        oid: 1.3.6.1.2.1.1.3.0
        type: gauge
      - name: fgSysCpuUsage
        oid: 1.3.6.1.4.1.12356.101.4.1.3.0
        type: gauge
      - name: fgSysMemUsage
        oid: 1.3.6.1.4.1.12356.101.4.1.4.0
        type: gauge
{_COMMON_IF_METRICS_YAML}

  printer:
    walk:
      - 1.3.6.1.2.1.1.3.0
      - 1.3.6.1.2.1.2.2
      - 1.3.6.1.2.1.31.1.1
      - 1.3.6.1.2.1.43.10.2.1
      - 1.3.6.1.2.1.43.11.1.1
      - 1.3.6.1.2.1.43.18.1.1
    metrics:
      - name: sysUpTime
        oid: 1.3.6.1.2.1.1.3.0
        type: gauge
      - name: prtMarkerLifeCount
        oid: 1.3.6.1.2.1.43.10.2.1.4
        type: counter
        indexes:
          - labelname: hrDeviceIndex
            type: gauge
          - labelname: prtMarkerIndex
            type: gauge
      - name: prtMarkerSuppliesDescription
        oid: 1.3.6.1.2.1.43.11.1.1.6
        type: DisplayString
        indexes:
          - labelname: hrDeviceIndex
            type: gauge
          - labelname: prtMarkerSuppliesIndex
            type: gauge
      - name: prtMarkerSuppliesMaxCapacity
        oid: 1.3.6.1.2.1.43.11.1.1.8
        type: gauge
        indexes:
          - labelname: hrDeviceIndex
            type: gauge
          - labelname: prtMarkerSuppliesIndex
            type: gauge
      - name: prtMarkerSuppliesLevel
        oid: 1.3.6.1.2.1.43.11.1.1.9
        type: gauge
        indexes:
          - labelname: hrDeviceIndex
            type: gauge
          - labelname: prtMarkerSuppliesIndex
            type: gauge
        lookups:
          - labels: [hrDeviceIndex, prtMarkerSuppliesIndex]
            labelname: prtMarkerSuppliesDescription
            oid: 1.3.6.1.2.1.43.11.1.1.6
            type: DisplayString
      - name: prtAlertSeverityLevel
        oid: 1.3.6.1.2.1.43.18.1.1.2
        type: gauge
        indexes:
          - labelname: hrDeviceIndex
            type: gauge
          - labelname: prtAlertIndex
            type: gauge
        lookups:
          - labels: [hrDeviceIndex, prtAlertIndex]
            labelname: prtAlertDescription
            oid: 1.3.6.1.2.1.43.18.1.1.8
            type: DisplayString
{_COMMON_IF_METRICS_YAML}

  generic:
    walk:
      - 1.3.6.1.2.1.1
      - 1.3.6.1.2.1.2.2
      - 1.3.6.1.2.1.31.1.1
    metrics:
      - name: sysUpTime
        oid: 1.3.6.1.2.1.1.3.0
        type: gauge
{_COMMON_IF_METRICS_YAML}
"""


def _render_auth_block(auth_name: str, target: dict[str, Any]) -> list[str]:
    version = target.get("snmp_version", "v2c")
    lines = [f"  {auth_name}:"]
    if version == "v3":
        v3 = target.get("snmp_v3") or {}
        sec_level = v3.get("security_level", "authPriv")
        username = v3.get("username", "")
        lines.append("    version: 3")
        lines.append(f"    security_level: {sec_level}")
        lines.append(f"    username: {yaml_quote(username)}")
        if sec_level in {"authNoPriv", "authPriv"}:
            auth_proto = v3.get("auth_protocol", "SHA256")
            auth_pw = v3.get("auth_password", "")
            lines.append(f"    auth_protocol: {auth_proto}")
            lines.append(f"    password: {yaml_quote(auth_pw)}")
        if sec_level == "authPriv":
            priv_proto = v3.get("priv_protocol", "AES")
            priv_pw = v3.get("priv_password", "")
            lines.append(f"    priv_protocol: {priv_proto}")
            lines.append(f"    priv_password: {yaml_quote(priv_pw)}")
    else:
        community = target.get("snmp_community") or "public"
        lines.append(f"    community: {yaml_quote(community)}")
        lines.append("    version: 2")
    return lines


def render_snmp_config(
    snmp_targets: list[dict[str, Any]],
    output_path: Path | None = None,
    *,
    state_dir: str | Path | None = None,
) -> str:
    """Render snmp.yml (mode 0600) with per-target v2c/v3 auth profiles and 6 MSP MIB modules."""
    lines = [
        "# Generated by central-monitoring-hub (hub_alerting.snmp_config)",
        "auths:",
        "  public_v2:",
        '    community: "public"',
        "    version: 2",
    ]
    for target in sorted(snmp_targets, key=lambda item: str(item.get("id", ""))):
        if target.get("target_type") != "snmp":
            continue
        auth_name = f"target_{target['id']}"
        lines.extend(_render_auth_block(auth_name, target))

    lines.append("")
    lines.append(SNMP_MODULES_YAML.rstrip("\n"))
    rendered = "\n".join(lines) + "\n"

    target_path = output_path or (resolve_config_dir(state_dir) / "snmp" / "snmp.yml")
    atomic_write_text(target_path, rendered, mode=0o600)
    return rendered
