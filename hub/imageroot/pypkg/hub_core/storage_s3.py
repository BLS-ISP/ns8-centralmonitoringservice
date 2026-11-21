"""S3 / MinIO object storage validation and Thanos / Loki S3 configuration builders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hub_core import atomic_write_text, yaml_quote


def normalize_s3_settings(
    *,
    storage_mode: str,
    raw_s3: dict[str, Any],
    existing_secret: str,
) -> tuple[dict[str, Any], str]:
    """Normalize S3 settings and enforce required credentials when storage_mode == 's3'."""
    endpoint = str(raw_s3.get("endpoint", "")).strip()
    bucket = str(raw_s3.get("bucket", "")).strip()
    region = str(raw_s3.get("region") or "us-east-1").strip() or "us-east-1"
    access_key = str(raw_s3.get("access_key", "")).strip()
    provided_secret = str(raw_s3.get("secret_key", ""))
    unchanged = bool(raw_s3.get("secret_key_unchanged", False))
    insecure = bool(raw_s3.get("insecure", False))
    path_style = bool(raw_s3.get("path_style", True))

    effective_secret = provided_secret if provided_secret else (existing_secret if unchanged else "")

    if storage_mode == "s3":
        if not endpoint:
            raise ValueError("S3 endpoint is required when storage_mode is 's3'")
        if not bucket:
            raise ValueError("S3 bucket is required when storage_mode is 's3'")
        if not access_key:
            raise ValueError("S3 access_key is required when storage_mode is 's3'")
        if not effective_secret:
            raise ValueError("S3 secret_key is required when storage_mode is 's3'")

    normalized = {
        "endpoint": endpoint,
        "bucket": bucket,
        "region": region,
        "access_key": access_key,
        "secret_key_unchanged": unchanged,
        "insecure": insecure,
        "path_style": path_style,
    }
    return normalized, effective_secret


def render_thanos_objstore_yaml(
    *,
    endpoint: str,
    bucket: str,
    region: str,
    access_key: str,
    secret_key: str,
    insecure: bool,
    path_style: bool,
) -> str:
    """Render Thanos S3 objstore.yml deterministically without PyYAML."""
    lookup_type = "path" if path_style else "auto"
    insecure_str = "true" if insecure else "false"
    lines = [
        "type: S3",
        "config:",
        f"  bucket: {yaml_quote(bucket)}",
        f"  endpoint: {yaml_quote(endpoint)}",
        f"  region: {yaml_quote(region or 'us-east-1')}",
        f"  access_key: {yaml_quote(access_key)}",
        f"  secret_key: {yaml_quote(secret_key)}",
        f"  insecure: {insecure_str}",
        "  signature_version2: false",
        f"  bucket_lookup_type: {yaml_quote(lookup_type)}",
        "  put_user_metadata: {}",
        "  http_config:",
        "    idle_conn_timeout: 90s",
        "    response_header_timeout: 2m",
        "    insecure_skip_verify: false",
    ]
    return "\n".join(lines) + "\n"


def write_thanos_objstore_file(
    config_dir: Path,
    *,
    endpoint: str,
    bucket: str,
    region: str,
    access_key: str,
    secret_key: str,
    insecure: bool,
    path_style: bool,
) -> Path:
    """Write config/thanos/objstore.yml with strict 0600 permissions."""
    target = config_dir / "thanos" / "objstore.yml"
    content = render_thanos_objstore_yaml(
        endpoint=endpoint,
        bucket=bucket,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        insecure=insecure,
        path_style=path_style,
    )
    atomic_write_text(target, content, mode=0o600)
    return target


def render_loki_storage_blocks(
    *,
    storage_mode: str,
    endpoint: str = "",
    bucket: str = "",
    region: str = "us-east-1",
    access_key: str = "",
    secret_key: str = "",
    insecure: bool = False,
    path_style: bool = True,
) -> tuple[str, str, str]:
    """Return (object_store, storage_config_block, delete_request_store) for Loki v3 TSDB v13."""
    if storage_mode == "s3":
        insecure_str = "true" if insecure else "false"
        path_style_str = "true" if path_style else "false"
        storage_block = "\n".join(
            [
                "storage_config:",
                "  tsdb_shipper:",
                "    active_index_directory: /var/lib/loki/tsdb-index",
                "    cache_location: /var/lib/loki/tsdb-cache",
                "  aws:",
                f"    endpoint: {yaml_quote(endpoint)}",
                f"    bucketnames: {yaml_quote(bucket)}",
                f"    region: {yaml_quote(region or 'us-east-1')}",
                f"    access_key_id: {yaml_quote(access_key)}",
                f"    secret_access_key: {yaml_quote(secret_key)}",
                f"    insecure: {insecure_str}",
                f"    s3forcepathstyle: {path_style_str}",
            ]
        )
        return "s3", storage_block, "s3"

    storage_block = "\n".join(
        [
            "storage_config:",
            "  tsdb_shipper:",
            "    active_index_directory: /var/lib/loki/tsdb-index",
            "    cache_location: /var/lib/loki/tsdb-cache",
            "  filesystem:",
            "    directory: /var/lib/loki/chunks",
        ]
    )
    return "filesystem", storage_block, "filesystem"
