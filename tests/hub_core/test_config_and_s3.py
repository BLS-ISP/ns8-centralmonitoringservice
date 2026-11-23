"""Unit tests for hub_core config rendering, env_store, and S3/Thanos storage mode."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.hub_core.conftest import FakeNS8Env


def test_initialize_secrets_creates_private_secrets_file(ns8_env: FakeNS8Env) -> None:
    from hub_core.env_store import ensure_initial_secrets, read_secrets

    secrets = ensure_initial_secrets(ns8_env.state_dir)
    secrets_path = ns8_env.state_dir / "secrets.env"

    assert secrets_path.exists()
    assert b"\r\n" not in secrets_path.read_bytes()
    assert len(secrets["GRAFANA_ADMIN_PASSWORD"]) >= 16
    assert len(secrets["GRAFANA_SECRET_KEY"]) >= 32
    assert len(secrets["HUB_INTERNAL_SECRET"]) >= 32

    reloaded = read_secrets(ns8_env.state_dir)
    assert reloaded == secrets


def test_local_mode_config_rendering_disables_s3_and_points_to_prometheus(ns8_env: FakeNS8Env) -> None:
    from hub_core.config_renderer import render_all_configs
    from hub_core.env_store import apply_configuration, ensure_initial_secrets

    ensure_initial_secrets(ns8_env.state_dir)
    apply_configuration(
        ns8_env.state_dir,
        {
            "host": "hub.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "retention_days": 45,
            "retention_size_gb": 120,
            "loki_retention_days": 30,
            "backup_include_tsdb": False,
            "storage_mode": "local",
        },
    )
    render_all_configs(ns8_env.state_dir)

    assert ns8_env.persisted_env["STORAGE_MODE"] == "local"
    assert ns8_env.persisted_env["PROMQL_UPSTREAM_URL"] == "http://127.0.0.1:9090"
    assert "--storage.tsdb.retention.size=120GB" in ns8_env.persisted_env["PROMETHEUS_EXTRA_ARGS"]
    assert "--storage.tsdb.min-block-duration=2h" not in ns8_env.persisted_env["PROMETHEUS_EXTRA_ARGS"]

    prom_yml = (ns8_env.config_dir / "prometheus" / "prometheus.yml").read_text(encoding="utf-8")
    assert "cluster: \"central-monitoring-hub1\"" in prom_yml
    assert "prometheus_replica: \"0\"" in prom_yml
    assert "/etc/prometheus/federation_jobs.yml" in prom_yml
    assert "/etc/prometheus/file_sd/exporters/*.json" in prom_yml
    assert "/etc/prometheus/file_sd/blackbox/*.json" in prom_yml
    assert "/etc/prometheus/file_sd/snmp/*.json" in prom_yml

    loki_yaml = (ns8_env.config_dir / "loki" / "loki.yaml").read_text(encoding="utf-8")
    assert "auth_enabled: true" in loki_yaml
    assert "multi_tenant_queries_enabled: true" in loki_yaml
    assert "schema: v13" in loki_yaml
    assert "object_store: filesystem" in loki_yaml
    assert "retention_period: 720h" in loki_yaml
    assert "secret_access_key" not in loki_yaml

    grafana_ini = (ns8_env.config_dir / "grafana" / "grafana.ini").read_text(encoding="utf-8")
    assert "http_addr = 127.0.0.1" in grafana_ini
    assert "http_port = 3000" in grafana_ini
    assert "domain = hub.msp.example.com" in grafana_ini
    assert "allow_sign_up = false" in grafana_ini
    assert "[alerting]\nenabled = false" in grafana_ini
    assert "[unified_alerting]\nenabled = false" in grafana_ini

    # Starter dashboards copied into config/grafana/dashboards
    dashboards = list((ns8_env.config_dir / "grafana" / "dashboards").glob("*.json"))
    assert len(dashboards) >= 4


def test_s3_mode_renders_thanos_objstore_and_loki_s3_and_preserves_secret(ns8_env: FakeNS8Env) -> None:
    from hub_core.config_renderer import render_all_configs
    from hub_core.env_store import apply_configuration, ensure_initial_secrets, read_secrets

    ensure_initial_secrets(ns8_env.state_dir)
    apply_configuration(
        ns8_env.state_dir,
        {
            "host": "hub.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "retention_days": 14,
            "retention_size_gb": 50,
            "loki_retention_days": 90,
            "backup_include_tsdb": False,
            "storage_mode": "s3",
            "s3": {
                "endpoint": "minio.internal.lan:9000",
                "bucket": "ns8-central-telemetry",
                "region": "eu-central-1",
                "access_key": "minio-access-key",
                "secret_key": "s3cr3t\"with#special:chars",
                "secret_key_unchanged": False,
                "insecure": True,
                "path_style": True,
            },
        },
    )
    render_all_configs(ns8_env.state_dir)

    assert ns8_env.persisted_env["STORAGE_MODE"] == "s3"
    assert ns8_env.persisted_env["PROMQL_UPSTREAM_URL"] == "http://127.0.0.1:10902"
    assert "--storage.tsdb.min-block-duration=2h" in ns8_env.persisted_env["PROMETHEUS_EXTRA_ARGS"]
    assert "--storage.tsdb.max-block-duration=2h" in ns8_env.persisted_env["PROMETHEUS_EXTRA_ARGS"]

    objstore_path = ns8_env.config_dir / "thanos" / "objstore.yml"
    assert objstore_path.exists()
    objstore_text = objstore_path.read_text(encoding="utf-8")
    assert "type: S3" in objstore_text
    assert 'bucket: "ns8-central-telemetry"' in objstore_text
    assert 'endpoint: "minio.internal.lan:9000"' in objstore_text
    assert "insecure: true" in objstore_text
    assert 'bucket_lookup_type: "path"' in objstore_text

    loki_yaml = (ns8_env.config_dir / "loki" / "loki.yaml").read_text(encoding="utf-8")
    assert "object_store: s3" in loki_yaml
    assert 'bucketnames: "ns8-central-telemetry"' in loki_yaml
    assert "s3forcepathstyle: true" in loki_yaml
    assert "retention_period: 2160h" in loki_yaml

    # Update retention with secret_key_unchanged=True and empty secret_key -> preserves secret!
    apply_configuration(
        ns8_env.state_dir,
        {
            "host": "hub.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "retention_days": 21,
            "retention_size_gb": 0,
            "loki_retention_days": 90,
            "backup_include_tsdb": False,
            "storage_mode": "s3",
            "s3": {
                "endpoint": "minio.internal.lan:9000",
                "bucket": "ns8-central-telemetry",
                "region": "eu-central-1",
                "access_key": "minio-access-key",
                "secret_key": "",
                "secret_key_unchanged": True,
                "insecure": True,
                "path_style": True,
            },
        },
    )
    assert read_secrets(ns8_env.state_dir)["S3_SECRET_KEY"] == 's3cr3t"with#special:chars'
    assert "--storage.tsdb.retention.size=" not in ns8_env.persisted_env["PROMETHEUS_EXTRA_ARGS"]


def test_s3_mode_rejects_missing_secret_when_none_previously_stored(ns8_env: FakeNS8Env) -> None:
    from hub_core.env_store import apply_configuration, ensure_initial_secrets

    ensure_initial_secrets(ns8_env.state_dir)
    with pytest.raises(ValueError, match="secret_key"):
        apply_configuration(
            ns8_env.state_dir,
            {
                "host": "hub.msp.example.com",
                "lets_encrypt": True,
                "http2https": True,
                "storage_mode": "s3",
                "s3": {
                    "endpoint": "s3.eu-central-1.amazonaws.com",
                    "bucket": "msp-metrics",
                    "access_key": "AKIA12345",
                    "secret_key": "",
                    "secret_key_unchanged": True,
                },
            },
        )


def test_secrets_env_writes_raw_podman_compatible_lines_and_rejects_control_chars(
    ns8_env: FakeNS8Env,
) -> None:
    from hub_core.config_renderer import render_grafana_ini
    from hub_core.env_store import apply_configuration, ensure_initial_secrets, read_secrets, write_secrets

    ensure_initial_secrets(ns8_env.state_dir)
    complex_pw = 'Admin#Pass "With" $Spaces \\ & \'Quotes\'!'
    apply_configuration(
        ns8_env.state_dir,
        {
            "host": "hub.msp.example.com",
            "lets_encrypt": True,
            "http2https": True,
            "storage_mode": "local",
            "grafana_admin_password": complex_pw,
        },
    )

    raw_secrets_text = (ns8_env.state_dir / "secrets.env").read_text(encoding="utf-8")
    # Podman --env-file takes everything after '=' literally (must NOT wrap value in quotes!)
    assert f"GF_SECURITY_ADMIN_PASSWORD={complex_pw}\n" in raw_secrets_text
    assert f"GRAFANA_ADMIN_PASSWORD={complex_pw}\n" in raw_secrets_text
    assert read_secrets(ns8_env.state_dir)["GRAFANA_ADMIN_PASSWORD"] == complex_pw

    for bad_char in ("\n", "\r", "\x00", "\u2028", "\u2029"):
        with pytest.raises(ValueError, match="control|line"):
            write_secrets(ns8_env.state_dir, {"GRAFANA_ADMIN_PASSWORD": f"bad{bad_char}injected=1"})

    ini_text = render_grafana_ini(
        host="hub.msp.example.com;allow_sign_up=true\n[auth.anonymous]\nenabled=true",
        ldap_enabled=False,
        secret_key="sec#key;with_comment_chars\ninjected=1",
    )
    assert '\ndomain = """' in ini_text
    assert '\nsecret_key = """' in ini_text
    assert "\ninjected=1" not in ini_text


def test_v104_encode_decode_ldap_principals_roundtrip_dedup_and_legacy_fallback() -> None:
    import re

    from hub_core.env_store import decode_ldap_principals, encode_ldap_principals

    raw_items = [
        "  CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net  ",
        "cn=domain admins,cn=users,dc=ad,dc=bls-isp,dc=net",
        "",
        "CN=Müllers Team,OU=\"IT Ops\",DC=ad,DC=bls-isp,DC=net\r\n",
        "CN=Genera,CN=Users,DC=ad,DC=bls-isp,DC=net",
    ]
    encoded = encode_ldap_principals(raw_items)
    assert re.match(r"^[A-Za-z0-9_-]+=*\Z", encoded), f"Not URL-safe Base64 ASCII: {encoded!r}"

    decoded = decode_ldap_principals(
        {"LDAP_ADMIN_PRINCIPALS_B64": encoded, "LDAP_ADMIN_GROUP": "IgnoredLegacy"},
        "LDAP_ADMIN_PRINCIPALS_B64",
        "LDAP_ADMIN_GROUP",
        default_fallback=["Domain Admins"],
    )
    assert decoded == [
        "CN=Domain Admins,CN=Users,DC=ad,DC=bls-isp,DC=net",
        'CN=Müllers Team,OU="IT Ops",DC=ad,DC=bls-isp,DC=net',
        "CN=Genera,CN=Users,DC=ad,DC=bls-isp,DC=net",
    ]

    # Empty list [] encoded in *_B64 must round-trip as [] without falling back to default!
    empty_b64 = encode_ldap_principals([])
    assert (
        decode_ldap_principals(
            {"LDAP_ADMIN_PRINCIPALS_B64": empty_b64},
            "LDAP_ADMIN_PRINCIPALS_B64",
            "LDAP_ADMIN_GROUP",
            default_fallback=["Domain Admins"],
        )
        == []
    )

    # Legacy env key fallback when *_B64 is absent
    assert decode_ldap_principals(
        {"LDAP_EDITOR_GROUP": "CN=Engineers,DC=ad,DC=bls-isp,DC=net"},
        "LDAP_EDITOR_PRINCIPALS_B64",
        "LDAP_EDITOR_GROUP",
        default_fallback=[],
    ) == ["CN=Engineers,DC=ad,DC=bls-isp,DC=net"]

    # Explicit empty legacy env key returns [] rather than default_fallback
    assert (
        decode_ldap_principals(
            {"LDAP_ADMIN_GROUP": ""},
            "LDAP_ADMIN_PRINCIPALS_B64",
            "LDAP_ADMIN_GROUP",
            default_fallback=["Domain Admins"],
        )
        == []
    )

    # Default fallback only when neither *_B64 nor legacy_key exists in env
    assert decode_ldap_principals(
        {},
        "LDAP_ADMIN_PRINCIPALS_B64",
        "LDAP_ADMIN_GROUP",
        default_fallback=["Domain Admins"],
    ) == ["Domain Admins"]
