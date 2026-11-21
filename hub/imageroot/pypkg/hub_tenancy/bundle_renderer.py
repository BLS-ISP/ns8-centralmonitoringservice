"""Standalone Grafana Alloy onboarding bundle renderer (`linux`, `windows`, `docker`).

Renders `shared/alloy-templates/*.tmpl` with strict input validation, zero shell/River
injection surface, optional dedicated collector-scoped bearer token minting, and
post-render verification that zero `{{...}}` placeholders remain.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Final, Mapping

from hub_tenancy.store import (
    COLLECTOR_RE,
    CUSTOMER_RE,
    SITE_RE,
    load_tenants_raw,
    mint_dedicated_collector_token,
)

HUB_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"\Ahttps://[a-zA-Z0-9.-]+(:[0-9]{1,5})?(/[a-zA-Z0-9._/-]*)?\Z"
)
TOKEN_SAFE_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(cms_v1_[A-Za-z0-9_-]{32,96}|REPLACE_WITH_TENANT_BEARER_TOKEN)\Z"
)
UNREPLACED_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(r"\{\{[^{}]*\}\}")

PLATFORM_SPECS: Final[dict[str, tuple[str, str, str, str]]] = {
    "linux": (
        "config-linux.alloy.tmpl",
        "config.alloy",
        "install-linux.sh.tmpl",
        "install-linux.sh",
    ),
    "windows": (
        "config-windows.alloy.tmpl",
        "config.alloy",
        "install-windows.ps1.tmpl",
        "install-windows.ps1",
    ),
    "docker": (
        "config-docker.alloy.tmpl",
        "config.alloy",
        "docker-compose.yml.tmpl",
        "docker-compose.yml",
    ),
}


def _resolve_templates_dir(state_dir: Path, env: Mapping[str, str] | None = None) -> Path:
    env_map = env or os.environ
    explicit = env_map.get("ALLOY_TEMPLATES_DIR")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            state_dir.parent / "etc" / "shared" / "alloy-templates",
            Path(__file__).resolve().parents[2] / "etc" / "shared" / "alloy-templates",
            Path("/imageroot/etc/shared/alloy-templates"),
            Path(__file__).resolve().parents[4] / "shared" / "alloy-templates",
        ]
    )
    for cand in candidates:
        if cand.is_dir() and (cand / "config-linux.alloy.tmpl").exists():
            return cand
    return candidates[-1]


def _render_template_text(raw_template: str, replacements: dict[str, str], syslog_port: int) -> str:
    rendered = raw_template.replace("\r\n", "\n").replace("\r", "\n")
    for placeholder, val in replacements.items():
        rendered = rendered.replace(f"{{{{{placeholder}}}}}", val)

    if syslog_port != 5514:
        rendered = rendered.replace(
            '"127.0.0.1:5514:5514/udp"', f'"127.0.0.1:{syslog_port}:{syslog_port}/udp"'
        )
        rendered = rendered.replace(
            '"127.0.0.1:5514:5514/tcp"', f'"127.0.0.1:{syslog_port}:{syslog_port}/tcp"'
        )
        rendered = rendered.replace('"5514:5514/udp"', f'"{syslog_port}:{syslog_port}/udp"')
        rendered = rendered.replace('"5514:5514/tcp"', f'"{syslog_port}:{syslog_port}/tcp"')
        rendered = rendered.replace("127.0.0.1:5514", f"127.0.0.1:{syslog_port}")
        rendered = rendered.replace("0.0.0.0:5514", f"0.0.0.0:{syslog_port}")

    leftover = UNREPLACED_PLACEHOLDER_RE.search(rendered)
    if leftover is not None:
        raise RuntimeError(f"Unreplaced template placeholder detected: {leftover.group(0)}")
    return rendered


def _build_instructions(
    platform: str,
    config_filename: str,
    installer_filename: str,
    hub_url: str,
    issue_dedicated_token: bool,
) -> str:
    token_note = (
        "A dedicated collector-scoped bearer token is already embedded in the rendered files."
        if issue_dedicated_token
        else "Replace REPLACE_WITH_TENANT_BEARER_TOKEN with your active tenant bearer token before starting Alloy."
    )
    if platform == "linux":
        return (
            f"1. Save {config_filename} and {installer_filename} into the same directory on the Linux host.\n"
            f"2. Run: sudo bash {installer_filename}\n"
            f"3. {token_note}\n"
            f"4. Metrics and systemd journal logs will stream over HTTPS to {hub_url}."
        )
    if platform == "windows":
        return (
            f"1. Save {config_filename} and {installer_filename} into the same folder on Windows Server.\n"
            f"2. Open an elevated PowerShell prompt and run: .\\{installer_filename}\n"
            f"3. {token_note}\n"
            f"4. Windows host metrics and EventLogs will stream over HTTPS to {hub_url}."
        )
    return (
        f"1. Place {config_filename} and {installer_filename} in a dedicated directory on your Docker host.\n"
        f"2. Run: docker compose up -d\n"
        f"3. {token_note}\n"
        f"4. Container, host, and LAN Syslog telemetry will stream over HTTPS to {hub_url}."
    )


def generate_agent_bundle(
    state_dir: str | Path,
    *,
    customer: str,
    site: str,
    platform: str,
    hub_url: str,
    collector_id: str = "",
    issue_dedicated_token: bool = True,
    syslog_port: int = 5514,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Validate inputs, optionally mint dedicated collector token, and render Alloy bundle."""
    sdir = Path(state_dir)
    customer = customer.strip()
    site = site.strip()
    platform = platform.strip().lower()
    clean_hub_url = hub_url.strip().rstrip("/")

    if not CUSTOMER_RE.match(customer):
        raise ValueError(f"Invalid customer slug: {customer!r}")
    if not SITE_RE.match(site):
        raise ValueError(f"Invalid site slug: {site!r}")
    if platform not in PLATFORM_SPECS:
        raise ValueError(f"Unsupported platform: {platform!r}")
    if not HUB_URL_RE.match(clean_hub_url):
        raise ValueError(f"Invalid hub_url: {clean_hub_url!r}")

    port_int = int(syslog_port)
    if port_int < 1024 or port_int > 65535:
        raise ValueError("syslog_port must be between 1024 and 65535")

    effective_collector_id = collector_id.strip()
    if not effective_collector_id:
        auto = f"{customer}-{site}-{platform}"
        effective_collector_id = auto[:64].rstrip("-._")
    if not COLLECTOR_RE.match(effective_collector_id):
        raise ValueError(f"Invalid collector_id: {effective_collector_id!r}")

    tenants = load_tenants_raw(sdir)
    tenant = next((t for t in tenants if t.get("customer") == customer), None)
    if tenant is None:
        raise KeyError(f"Tenant not found: {customer}")
    if site not in tenant.get("sites", []):
        raise ValueError(f"Site {site!r} is not registered under tenant {customer!r}")

    if issue_dedicated_token:
        auth_token, token_prefix = mint_dedicated_collector_token(
            sdir,
            customer=customer,
            site=site,
            collector_id=effective_collector_id,
        )
    else:
        auth_token = "REPLACE_WITH_TENANT_BEARER_TOKEN"
        token_prefix = str(tenant.get("token_prefix") or "cms_v1_...")

    if not TOKEN_SAFE_RE.match(auth_token):
        raise ValueError("Generated auth_token failed safety pattern validation")

    cfg_tmpl_name, cfg_out_name, inst_tmpl_name, inst_out_name = PLATFORM_SPECS[platform]
    templates_dir = _resolve_templates_dir(sdir, env)

    cfg_raw = (templates_dir / cfg_tmpl_name).read_text(encoding="utf-8")
    inst_raw = (templates_dir / inst_tmpl_name).read_text(encoding="utf-8")

    replacements = {
        "HUB_URL": clean_hub_url,
        "AUTH_TOKEN": auth_token,
        "CUSTOMER": customer,
        "SITE": site,
        "COLLECTOR_ID": effective_collector_id,
        "SYSLOG_PORT": str(port_int),
    }

    cfg_rendered = _render_template_text(cfg_raw, replacements, port_int)
    inst_rendered = _render_template_text(inst_raw, replacements, port_int)

    return {
        "status": "ok",
        "customer": customer,
        "site": site,
        "platform": platform,
        "collector_id": effective_collector_id,
        "hub_url": clean_hub_url,
        "token_prefix": token_prefix,
        "config_filename": cfg_out_name,
        "config_content": cfg_rendered,
        "installer_filename": inst_out_name,
        "installer_content": inst_rendered,
        "instructions": _build_instructions(
            platform, cfg_out_name, inst_out_name, clean_hub_url, issue_dedicated_token
        ),
    }
