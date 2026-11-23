#!/usr/bin/env python3
"""Generate a NethServer 8 Software Center repository for GitHub Pages hosting.

Produces a complete, self-contained NethServer 8 application catalog directory
containing:
  - `repodata.json` & `repomd.json` (plus `repodata/repomd.json` &
    `repodata/repodata.json` for subdirectory compatibility)
  - `<module-id>/metadata.json`, `<module-id>/logo.png`, and
    `<module-id>/module_default_icon.png` copied from `hub/ui/public/` and
    `collector/ui/public/`
  - `.nojekyll` and `index.html` landing page with 1-click NS8 Software Center
    repository instructions and CLI `add-module` commands.

Zero external dependencies (Python 3 standard library only).
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import re
import shutil
import struct
import sys
from typing import Any
import zlib

REPO_ROOT = Path(__file__).resolve().parent.parent

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

MODULE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "id": "central-monitoring-hub",
        "dir": "hub",
        "fallback_metadata": {
            "name": "Central Monitoring Hub",
            "upstream_name": "Prometheus, Loki, Alertmanager & Grafana",
            "description": {
                "en": "Multi-tenant MSP monitoring, logging, alerting, and Grafana portal hub for NethServer 8, Linux, Windows, Proxmox VE, Web/SSL, and SNMP infrastructure.",
                "de": "Mandantenfähiger MSP-Monitoring-, Logging-, Alerting- und Grafana-Portal-Hub für NethServer 8, Linux, Windows, Proxmox VE, Web/SSL und SNMP-Infrastrukturen.",
            },
            "categories": ["monitoring", "administration"],
            "authors": [{"name": "BLS-ISP", "email": "info@bls-isp.de"}],
            "docs": {
                "documentation_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice#readme",
                "bug_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice/issues",
                "code_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice",
                "terms_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice/blob/main/LICENSE",
                "relnotes_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice/releases",
            },
        },
        "fallback_rgb": (15, 98, 254),
    },
    {
        "id": "central-monitoring-collector",
        "dir": "collector",
        "fallback_metadata": {
            "name": "Central Monitoring Collector",
            "upstream_name": "Grafana Alloy & Prometheus Exporters",
            "description": {
                "en": "Lightweight rootless Grafana Alloy telemetry & log collector for customer NethServer 8 clusters and LAN infrastructure (Proxmox VE, Windows, Linux, SNMP v2c/v3, Syslog) with offline WAL buffering.",
                "de": "Leichtgewichtiger Rootless-Grafana-Alloy-Telemetrie- und Log-Collector für Kunden-NethServer-8-Cluster und LAN-Infrastrukturen (Proxmox VE, Windows, Linux, SNMP v2c/v3, Syslog) mit Offline-WAL-Pufferung.",
            },
            "categories": ["monitoring", "administration"],
            "authors": [{"name": "BLS-ISP", "email": "info@bls-isp.de"}],
            "docs": {
                "documentation_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice#readme",
                "bug_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice/issues",
                "code_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice",
                "terms_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice/blob/main/LICENSE",
                "relnotes_url": "https://github.com/BLS-ISP/ns8-centralmonitoringservice/releases",
            },
        },
        "fallback_rgb": (0, 157, 154),
    },
)


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _synthesize_fallback_png(rgb: tuple[int, int, int], size: int = 128) -> bytes:
    """Create a valid 128x128 RGBA PNG if invoked before UI static icon exists."""
    r, g, b = rgb
    rows: list[bytes] = []
    for y in range(size):
        row = bytearray([0])  # filter type 0 (None)
        for x in range(size):
            border = x < 8 or x >= size - 8 or y < 8 or y >= size - 8
            if border:
                row.extend((max(0, r - 25), max(0, g - 25), max(0, b - 25), 255))
            else:
                row.extend((r, g, b, 255))
        rows.append(bytes(row))
    raw_scanlines = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw_scanlines, level=9)
    return PNG_SIGNATURE + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")


def validate_png_bytes(raw: bytes) -> tuple[int, int]:
    """Validate PNG header, IHDR dimensions, chunk CRCs, and IEND trailer."""
    if len(raw) < 33 or not raw.startswith(PNG_SIGNATURE):
        raise ValueError("Invalid PNG file signature")
    offset = 8
    width = 0
    height = 0
    saw_ihdr = False
    saw_iend = False
    while offset + 8 <= len(raw):
        length = struct.unpack(">I", raw[offset : offset + 4])[0]
        ctype = raw[offset + 4 : offset + 8]
        data_end = offset + 8 + length
        crc_end = data_end + 4
        if crc_end > len(raw):
            raise ValueError(f"Truncated PNG chunk {ctype!r}")
        cdata = raw[offset + 8 : data_end]
        expected_crc = struct.unpack(">I", raw[data_end:crc_end])[0]
        actual_crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"CRC mismatch in PNG chunk {ctype!r}")
        if ctype == b"IHDR":
            if len(cdata) != 13:
                raise ValueError("Invalid PNG IHDR chunk length")
            width, height = struct.unpack(">II", cdata[:8])
            if width <= 0 or height <= 0:
                raise ValueError("PNG dimensions must be positive")
            saw_ihdr = True
        elif ctype == b"IEND":
            saw_iend = True
            break
        offset = crc_end
    if not saw_ihdr or not saw_iend:
        raise ValueError("PNG missing required IHDR or IEND chunk")
    return width, height


def parse_containerfile_labels(containerfile: Path, gateway_image: str) -> dict[str, str]:
    """Extract OCI LABEL key-value pairs from a module Containerfile."""
    if not containerfile.is_file():
        return {"org.nethserver.rootfull": "0"}
    raw = containerfile.read_text(encoding="utf-8")
    # Join backslash-continued lines
    joined = re.sub(r"\\\n\s*", " ", raw)
    labels: dict[str, str] = {}
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("LABEL "):
            continue
        rest = stripped[6:].strip()
        for match in re.finditer(r'([A-Za-z0-9._-]+)\s*=\s*(?:"([^"]*)"|([^\s]+))', rest):
            key = match.group(1)
            val = match.group(2) if match.group(2) is not None else (match.group(3) or "")
            val = val.replace("${GATEWAY_IMAGE}", gateway_image).replace("$GATEWAY_IMAGE", gateway_image)
            labels[key] = val
    return labels


def normalize_semver_tag(raw_tag: str) -> tuple[str, bool, str]:
    """Return (ns8_semver_tag, is_testing, oci_image_tag)."""
    cleaned = raw_tag.strip()
    if not cleaned or cleaned in {"latest", "main", "master"}:
        return "1.0.3", False, cleaned or "latest"
    semver = cleaned[1:] if cleaned.startswith("v") and len(cleaned) > 1 and cleaned[1].isdigit() else cleaned
    if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z", semver):
        return "1.0.3", True, cleaned
    is_testing = "-" in semver
    return semver, is_testing, semver


def _write_json_lf(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    path.write_bytes(content.encode("utf-8"))


def _render_landing_html(org: str, repo_name: str, semver_tag: str, catalog: list[dict[str, Any]]) -> str:
    safe_org = html.escape(org)
    safe_repo = html.escape(repo_name)
    safe_ver = html.escape(semver_tag)
    pages_url = f"https://{safe_org}.github.io/{safe_repo}/"
    cards_html: list[str] = []
    for entry in catalog:
        mod_id = html.escape(str(entry["id"]))
        mod_name = html.escape(str(entry["name"]))
        desc_de = html.escape(str(entry.get("description", {}).get("de", "")))
        desc_en = html.escape(str(entry.get("description", {}).get("en", "")))
        src = html.escape(str(entry["source"]))
        cards_html.append(
            f"""      <section class="card">
        <div class="card-head">
          <img src="{mod_id}/logo.png" alt="{mod_name} icon" width="64" height="64" />
          <div>
            <h2>{mod_name}</h2>
            <code>{src}:{safe_ver}</code>
          </div>
        </div>
        <p><strong>DE:</strong> {desc_de}</p>
        <p><strong>EN:</strong> {desc_en}</p>
        <pre><code>add-module {src}:{safe_ver} 1</code></pre>
      </section>"""
        )

    joined_cards = "\n".join(cards_html)
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NS8 Central Monitoring Service — Software Center Repository</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 920px; margin: 2rem auto; padding: 0 1.25rem; color: #161616; background: #f4f4f4; line-height: 1.5; }}
    header {{ background: #161616; color: #ffffff; padding: 1.5rem; border-radius: 6px; margin-bottom: 1.5rem; }}
    header h1 {{ margin: 0 0 0.5rem 0; font-size: 1.5rem; }}
    .repo-box {{ background: #ffffff; padding: 1.25rem; border-left: 4px solid #0f62fe; border-radius: 4px; margin-bottom: 1.5rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 1rem; }}
    .card {{ background: #ffffff; padding: 1.25rem; border-radius: 4px; border: 1px solid #e0e0e0; }}
    .card-head {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.75rem; }}
    .card-head h2 {{ margin: 0 0 0.25rem 0; font-size: 1.15rem; }}
    pre {{ background: #262626; color: #f4f4f4; padding: 0.75rem; border-radius: 4px; overflow-x: auto; }}
    a {{ color: #0f62fe; }}
  </style>
</head>
<body>
  <header>
    <h1>NS8 Central Monitoring Service — NethServer 8 Software Center Repository</h1>
    <div>Version: <strong>{safe_ver}</strong> &middot; Registry Namespace: <code>ghcr.io/{safe_org}</code></div>
  </header>
  <div class="repo-box">
    <strong>1-Klick NethServer 8 Software Center Einbindung:</strong>
    <ol>
      <li>Öffnen Sie im NS8 Cluster-Admin <strong>Einstellungen &rarr; Software-Repositorys &rarr; Repository hinzufügen</strong>.</li>
      <li>Name: <code>central-monitoring</code> &middot; URL: <code>{pages_url}</code></li>
      <li>Installieren Sie <strong>Central Monitoring Hub</strong> oder <strong>Central Monitoring Collector</strong> direkt im Software Center.</li>
    </ol>
    <div>Index-Endpunkte: <a href="repodata.json">repodata.json</a> &middot; <a href="repomd.json">repomd.json</a> &middot; <a href="repodata/repomd.json">repodata/repomd.json</a></div>
  </div>
  <div class="grid">
{joined_cards}
  </div>
</body>
</html>
"""


def generate_repository(
    *,
    root: Path = REPO_ROOT,
    org: str = "bls-isp",
    tag: str = "1.0.3",
    repo_name: str = "ns8-centralmonitoringservice",
    output_dir: Path,
    strict_assets: bool = False,
) -> list[dict[str, Any]]:
    """Build the NS8 Software Center catalog directory and return the module list."""
    clean_org = org.strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9._-]*\Z", clean_org):
        raise ValueError(f"Invalid registry/GitHub org slug: {org!r}")

    semver_tag, is_testing, oci_tag = normalize_semver_tag(tag)
    gateway_image = f"ghcr.io/{clean_org}/central-monitoring-hub-gateway:{oci_tag}"

    output_dir.mkdir(parents=True, exist_ok=True)
    repodata_subdir = output_dir / "repodata"
    repodata_subdir.mkdir(parents=True, exist_ok=True)

    catalog: list[dict[str, Any]] = []

    for spec in MODULE_SPECS:
        mod_id = spec["id"]
        mod_dir = root / spec["dir"]
        public_dir = mod_dir / "ui" / "public"
        meta_file = public_dir / "metadata.json"
        icon_file = public_dir / "module_default_icon.png"

        if meta_file.is_file():
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        elif not strict_assets:
            meta = dict(spec["fallback_metadata"])
        else:
            raise FileNotFoundError(f"Missing required {meta_file}")

        if icon_file.is_file():
            icon_bytes = icon_file.read_bytes()
            validate_png_bytes(icon_bytes)
        elif not strict_assets:
            icon_bytes = _synthesize_fallback_png(spec["fallback_rgb"])
            validate_png_bytes(icon_bytes)
        else:
            raise FileNotFoundError(f"Missing required {icon_file}")

        labels = parse_containerfile_labels(mod_dir / "Containerfile", gateway_image)
        source_image = f"ghcr.io/{clean_org}/{mod_id}"

        code_url = f"https://github.com/{clean_org}/{repo_name}"
        docs_obj = dict(meta.get("docs") or {})
        docs_obj.setdefault("documentation_url", f"{code_url}#readme")
        docs_obj.setdefault("bug_url", f"{code_url}/issues")
        docs_obj["code_url"] = code_url

        mod_out_metadata: dict[str, Any] = {
            "name": meta["name"],
        }
        if meta.get("upstream_name"):
            mod_out_metadata["upstream_name"] = meta["upstream_name"]
        mod_out_metadata.update(
            {
                "description": meta["description"],
                "categories": list(meta.get("categories") or ["monitoring"]),
                "authors": list(meta.get("authors") or []),
                "docs": docs_obj,
                "source": source_image,
            }
        )

        for base in (output_dir / mod_id, repodata_subdir / mod_id):
            base.mkdir(parents=True, exist_ok=True)
            (base / "logo.png").write_bytes(icon_bytes)
            (base / "module_default_icon.png").write_bytes(icon_bytes)
            _write_json_lf(base / "metadata.json", mod_out_metadata)

        catalog_entry = {
            "id": mod_id,
            **mod_out_metadata,
            "logo": f"{mod_id}/logo.png",
            "screenshots": [],
            "versions": [
                {
                    "tag": semver_tag,
                    "testing": is_testing,
                    "labels": labels,
                }
            ],
        }
        catalog.append(catalog_entry)

    # Emit NS8 Software Center catalog files at both root and repodata/ paths
    _write_json_lf(output_dir / "repodata.json", catalog)
    _write_json_lf(output_dir / "repomd.json", catalog)
    _write_json_lf(repodata_subdir / "repodata.json", catalog)
    _write_json_lf(repodata_subdir / "repomd.json", catalog)

    (output_dir / ".nojekyll").write_bytes(b"")
    landing = _render_landing_html(clean_org, repo_name, semver_tag, catalog)
    (output_dir / "index.html").write_bytes(landing.encode("utf-8"))

    return catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate NethServer 8 Software Center repository metadata & icons for GitHub Pages."
    )
    parser.add_argument(
        "--org",
        default="bls-isp",
        help="GitHub / GHCR organization or owner namespace (lowercased automatically).",
    )
    parser.add_argument(
        "--tag",
        default="1.0.3",
        help="Release version tag to advertise in Software Center (e.g. 1.0.3 or v1.0.3).",
    )
    parser.add_argument(
        "--repo-name",
        default="ns8-centralmonitoringservice",
        help="GitHub repository name used for landing-page & code URLs.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "repodata",
        help="Target directory for generated static repository files.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Monorepo root directory.",
    )
    parser.add_argument(
        "--strict-assets",
        action="store_true",
        help="Fail if ui/public/metadata.json or module_default_icon.png is missing.",
    )
    args = parser.parse_args(argv)

    out_dir = args.output_dir.resolve()
    if out_dir == args.root.resolve():
        print("Error: --output-dir must be a dedicated subdirectory, not repo root", file=sys.stderr)
        return 1
    if out_dir.exists() and (out_dir / "repomd.json").exists():
        shutil.rmtree(out_dir)

    catalog = generate_repository(
        root=args.root.resolve(),
        org=args.org,
        tag=args.tag,
        repo_name=args.repo_name,
        output_dir=out_dir,
        strict_assets=args.strict_assets,
    )
    print(
        f"Generated NS8 Software Center repository ({len(catalog)} modules, org={args.org.lower()}, tag={args.tag}) -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
