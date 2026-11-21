from __future__ import annotations

import pytest

from hub_alerting.ssrf_guard import (
    SSRFValidationError,
    assert_not_internal_pod_endpoint,
    validate_webhook_url,
)


@pytest.mark.parametrize(
    "forbidden_target",
    [
        "127.0.0.1:9090",
        "http://127.0.0.1:9090/metrics",
        "127.0.0.53:53",
        "[::1]:3100",
        "::1",
        "http://[::1]:9093/-/reload",
        "localhost:9093",
        "https://LOCALHOST./federate",
        "sub.localhost:8080",
        "0.0.0.0:8080",
        "[::]:9090",
        "169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "fe80::1",
        "http://metadata.google.internal/computeMetadata/v1/",
        "10.0.2.2:9095",
        "10.0.2.2:3000",
        "10.0.2.2",
        "[::ffff:127.0.0.1]:9090",
        "[::ffff:169.254.169.254]:80",
        "[::ffff:10.0.2.2]:9090",
    ],
)
def test_ssrf_guard_rejects_loopback_link_local_metadata_and_pod_hosts(
    forbidden_target: str,
) -> None:
    with pytest.raises(SSRFValidationError) as exc_info:
        assert_not_internal_pod_endpoint(forbidden_target, field="endpoints")
    assert exc_info.value.code == "FORBIDDEN_INTERNAL_ENDPOINT"
    assert "FORBIDDEN_INTERNAL_ENDPOINT" in str(exc_info.value)


@pytest.mark.parametrize(
    "bad_webhook",
    [
        "http://127.0.0.1:9093/api/v2/alerts",
        "http://[::1]:3100/loki/api/v1/push",
        "https://localhost:9093/hook",
        "http://169.254.169.254/latest",
        "http://10.0.2.2:9095/api/v1/query",
        "file:///etc/passwd",
        "gopher://198.51.100.10:70/",
        "ftp://198.51.100.10/pub",
    ],
)
def test_webhook_url_validation_rejects_ssrf_and_non_http_schemes(
    bad_webhook: str,
) -> None:
    with pytest.raises(SSRFValidationError) as exc_info:
        validate_webhook_url(bad_webhook, field="webhook_psa.url")
    assert exc_info.value.code == "FORBIDDEN_INTERNAL_ENDPOINT"


@pytest.mark.parametrize(
    "valid_target",
    [
        "https://portal.acme.example.com",
        "198.51.100.25:9100",
        "192.168.50.10",
        "[2001:db8::10]:9100",
        "ns8.customer-a.example.org:443",
    ],
)
def test_ssrf_guard_accepts_external_and_vpn_routed_targets(valid_target: str) -> None:
    assert_not_internal_pod_endpoint(valid_target, field="endpoints")


def test_webhook_url_accepts_external_https_endpoints() -> None:
    validate_webhook_url("https://hooks.slack.com/services/T000/B000/XXXX", field="slack")
    validate_webhook_url("https://psa.msp.example.com/api/webhooks/am", field="psa")
