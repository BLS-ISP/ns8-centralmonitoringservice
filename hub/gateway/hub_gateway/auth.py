"""Constant-time bearer token authentication, rotation grace-window check, and IP rate limiting."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
from pathlib import Path
import time
from typing import Any
from aiohttp import web


@dataclass(frozen=True)
class TokenRecord:
    sha256: str
    token_prefix: str
    customer: str
    display_name: str
    sites: tuple[str, ...]
    allowed_sites: frozenset[str]
    default_site: str
    bound_collector_id: str | None = None
    expires_at_epoch: float | None = None


def _parse_iso8601_epoch(value: str | None) -> float | None:
    if not value or not isinstance(value, str):
        return None
    txt = value.strip()
    if not txt:
        return None
    if txt.endswith(("Z", "z")):
        txt = txt[:-1] + "+00:00"
    dt = datetime.fromisoformat(txt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


class TokenStoreWatcher:
    """Thread/async-safe immutable snapshot loader for `state/tenants.json`."""

    def __init__(self, tenants_file: Path) -> None:
        self._path = Path(tenants_file)
        self._last_sig: tuple[int, int] | None = None
        self._records: tuple[TokenRecord, ...] = ()

    @property
    def path(self) -> Path:
        return self._path

    def reload(self) -> tuple[TokenRecord, ...]:
        """Force reload from disk without dropping in-flight requests."""
        self._last_sig = None
        return self.get_records()

    def get_records(self) -> tuple[TokenRecord, ...]:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            self._last_sig = None
            self._records = ()
            return self._records

        sig = (st.st_mtime_ns, st.st_size)
        if sig == self._last_sig:
            return self._records

        try:
            raw_text = self._path.read_text(encoding="utf-8")
            doc: Any = json.loads(raw_text) if raw_text.strip() else {}
        except (OSError, json.JSONDecodeError):
            # Preserve last known good snapshot if a partial read ever occurs
            return self._records

        tenants_list: list[dict[str, Any]]
        if isinstance(doc, dict) and isinstance(doc.get("tenants"), list):
            tenants_list = doc["tenants"]
        elif isinstance(doc, list):
            tenants_list = doc
        else:
            tenants_list = []

        parsed: list[TokenRecord] = []
        for t in tenants_list:
            if not isinstance(t, dict):
                continue
            customer = str(t.get("customer") or "").strip()
            if not customer:
                continue
            display_name = str(t.get("display_name") or customer)
            sites_raw = t.get("sites")
            sites = (
                tuple(str(s) for s in sites_raw if isinstance(s, str) and s)
                if isinstance(sites_raw, list)
                else ()
            )
            default_site = str(t.get("default_site") or (sites[0] if sites else "hq"))
            allowed_all = frozenset(sites) if sites else frozenset({default_site})

            primary_hash = str(t.get("token_sha256") or "").strip().lower()
            primary_prefix = str(t.get("token_prefix") or "cms_v1_...")
            if len(primary_hash) == 64:
                parsed.append(
                    TokenRecord(
                        sha256=primary_hash,
                        token_prefix=primary_prefix,
                        customer=customer,
                        display_name=display_name,
                        sites=sites or (default_site,),
                        allowed_sites=allowed_all,
                        default_site=default_site,
                        bound_collector_id=None,
                        expires_at_epoch=None,
                    )
                )

            prev_hash = str(t.get("previous_token_sha256") or "").strip().lower()
            prev_exp_str = t.get("previous_token_expires_at") or t.get("grace_until")
            if len(prev_hash) == 64 and prev_exp_str:
                try:
                    prev_exp = _parse_iso8601_epoch(str(prev_exp_str))
                except ValueError:
                    prev_exp = None
                if prev_exp is not None:
                    parsed.append(
                        TokenRecord(
                            sha256=prev_hash,
                            token_prefix=str(t.get("previous_token_prefix") or primary_prefix),
                            customer=customer,
                            display_name=display_name,
                            sites=sites or (default_site,),
                            allowed_sites=allowed_all,
                            default_site=default_site,
                            bound_collector_id=None,
                            expires_at_epoch=prev_exp,
                        )
                    )

            ded_list = t.get("dedicated_tokens")
            if isinstance(ded_list, list):
                for d in ded_list:
                    if not isinstance(d, dict):
                        continue
                    d_hash = str(d.get("token_sha256") or "").strip().lower()
                    d_site = str(d.get("site") or default_site)
                    d_col = str(d.get("collector_id") or "").strip() or None
                    d_prefix = str(d.get("token_prefix") or "cms_v1_...")
                    if len(d_hash) == 64:
                        parsed.append(
                            TokenRecord(
                                sha256=d_hash,
                                token_prefix=d_prefix,
                                customer=customer,
                                display_name=display_name,
                                sites=sites or (d_site,),
                                allowed_sites=frozenset({d_site}),
                                default_site=d_site,
                                bound_collector_id=d_col,
                                expires_at_epoch=None,
                            )
                        )

        self._records = tuple(parsed)
        self._last_sig = sig
        return self._records

    def verify_bearer_header(
        self, auth_header: str | None, *, now_epoch: float | None = None
    ) -> TokenRecord | None:
        if not auth_header or not isinstance(auth_header, str):
            return None
        parts = auth_header.strip().split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        raw_token = parts[1].strip()
        if not raw_token or len(raw_token) > 512:
            return None

        records = self.get_records()
        candidate_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        now = time.time() if now_epoch is None else now_epoch

        matched: TokenRecord | None = None
        for rec in records:
            digest_ok = hmac.compare_digest(candidate_digest, rec.sha256)
            time_ok = rec.expires_at_epoch is None or now < rec.expires_at_epoch
            if digest_ok and time_ok:
                matched = rec
        return matched


class AuthRateLimiter:
    """Bounded per-IP sliding-window rate limiter for failed bearer token authentications."""

    def __init__(
        self,
        *,
        max_failures: int = 20,
        window_seconds: float = 300.0,
        max_tracked_ips: int = 10000,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_tracked_ips = max_tracked_ips
        self._failures: OrderedDict[str, list[float]] = OrderedDict()

    @staticmethod
    def extract_client_ip(request: web.Request) -> str:
        remote = (request.remote or "").strip()
        # Trust rightmost hop appended by local NS8 Traefik reverse proxy on loopback / slirp4netns
        if remote in ("", "127.0.0.1", "::1") or remote.startswith("10.0.2."):
            xff = request.headers.get("X-Forwarded-For", "").strip()
            if xff:
                last_hop = xff.rsplit(",", 1)[-1].strip()
                if last_hop:
                    return last_hop
        return remote or "unknown"

    def _prune(self, ip: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        timestamps = self._failures.get(ip)
        if not timestamps:
            return []
        fresh = [t for t in timestamps if t > cutoff]
        if fresh:
            self._failures[ip] = fresh
            self._failures.move_to_end(ip)
        else:
            self._failures.pop(ip, None)
        return fresh

    def check(self, ip: str, *, now: float | None = None) -> tuple[bool, int]:
        """Return (is_limited, retry_after_seconds)."""
        ts = time.monotonic() if now is None else now
        fresh = self._prune(ip, ts)
        if len(fresh) >= self.max_failures:
            oldest = fresh[0]
            retry_after = max(1, int(math.ceil((oldest + self.window_seconds) - ts)))
            return True, retry_after
        return False, 0

    def record_failure(self, ip: str, *, now: float | None = None) -> None:
        ts = time.monotonic() if now is None else now
        fresh = self._prune(ip, ts)
        if ip not in self._failures and len(self._failures) >= self.max_tracked_ips:
            self._failures.popitem(last=False)
        fresh.append(ts)
        self._failures[ip] = fresh
        self._failures.move_to_end(ip)
