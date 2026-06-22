"""Scan orchestration: guard -> probe (network) -> evaluate (checks) -> score."""
from __future__ import annotations

import asyncio
import datetime as dt
import socket
import ssl
import time

import httpx

from ..config import get_settings
from ..guard import normalize_hostname, resolve_and_guard
from ..scoring import compute
from . import (
    checks_content,
    checks_cookies,
    checks_csp,
    checks_dns,
    checks_headers,
    checks_tls,
    checks_wellknown,
)
from .base import Hop, ProbeContext

ENGINE_VERSION = "1.0.0"

# (key, label, evaluation function). All functions are pure - they read ctx only.
CATEGORIES = [
    ("tls", "TLS & Transport", checks_tls.run),
    ("headers", "Security Headers", checks_headers.run),
    ("csp", "Content Security Policy", checks_csp.run),
    ("cookies", "Cookies", checks_cookies.run),
    ("dns_email", "DNS & Email Authentication", checks_dns.run),
    ("redirects", "Redirects", checks_content.run_redirects),
    ("mixed_content", "Mixed Content", checks_content.run_mixed_content),
    ("http_protocol", "HTTP Protocol", checks_content.run_protocol),
    ("wellknown", "Disclosure & .well-known", checks_wellknown.run),
]


def _tls_info(hostname: str, timeout: float) -> dict:
    """Blocking TLS handshake inspection. Returns version/expiry/issuer or error."""
    out = {"version": "", "days": None, "issuer": "", "error": ""}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                out["version"] = tls.version() or ""
                cert = tls.getpeercert()
        if cert:
            issuer = {k: v for part in cert.get("issuer", []) for k, v in part}
            out["issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))
            not_after = cert.get("notAfter")
            if not_after:
                expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=dt.timezone.utc
                )
                out["days"] = (expires - dt.datetime.now(dt.timezone.utc)).days
    except Exception as exc:  # noqa: BLE001 - surfaced as a finding, not a crash
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


async def _probe(hostname: str, ips: list[str]) -> ProbeContext:
    settings = get_settings()
    timeout = settings.scan_timeout_seconds
    ctx = ProbeContext(hostname=hostname, resolved_ips=ips)

    limits = httpx.Limits(max_connections=10)
    headers = {"User-Agent": f"AegisScan/{ENGINE_VERSION} (+https://github.com/) posture-check"}

    async with httpx.AsyncClient(
        follow_redirects=True, timeout=timeout, limits=limits, headers=headers, verify=True
    ) as client:
        # Run independent network probes concurrently.
        https_task = client.get(f"https://{hostname}/")
        http_task = _http_redirect_check(hostname, timeout, headers)
        sectxt_task = _security_txt(client, hostname)
        tls_task = asyncio.to_thread(_tls_info, hostname, timeout)
        dns_task = asyncio.to_thread(checks_dns.gather, hostname, min(timeout, 5.0))

        https_res, http_res, sectxt_status, tls, dns = await asyncio.gather(
            https_task, http_task, sectxt_task, tls_task, dns_task, return_exceptions=True
        )

    # --- HTTPS landing response ---
    if isinstance(https_res, httpx.Response):
        ctx.https_ok = True
        ctx.final_url = str(https_res.url)
        ctx.status_code = https_res.status_code
        ctx.http_version = https_res.http_version
        ctx.headers = {k.lower(): v for k, v in https_res.headers.items()}
        ctx.set_cookies = https_res.headers.get_list("set-cookie")
        ctx.body_snippet = https_res.text[:200_000]
        for h in https_res.history:
            ctx.hops.append(
                Hop(url=str(h.url), status_code=h.status_code, location=h.headers.get("location"))
            )
    else:
        ctx.https_ok = False
        ctx.https_error = _err(https_res)

    # --- plain HTTP redirect behaviour ---
    if isinstance(http_res, dict):
        ctx.http_redirects_to_https = http_res.get("redirects_to_https")
        ctx.http_error = http_res.get("error", "")
    else:
        ctx.http_error = _err(http_res)

    # --- TLS ---
    if isinstance(tls, dict):
        ctx.tls_version = tls["version"]
        ctx.tls_cert_days_remaining = tls["days"]
        ctx.tls_cert_issuer = tls["issuer"]
        ctx.tls_error = tls["error"]

    # --- DNS + security.txt status live together in ctx.dns ---
    ctx.dns = dns if isinstance(dns, dict) else {"errors": [_err(dns)]}
    ctx.dns["security_txt_status"] = sectxt_status if isinstance(sectxt_status, int) else None

    return ctx


async def _http_redirect_check(hostname: str, timeout: float, headers: dict) -> dict:
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=headers) as c:
            r = await c.get(f"http://{hostname}/")
            loc = r.headers.get("location", "")
            return {"redirects_to_https": (300 <= r.status_code < 400 and loc.startswith("https://"))}
    except Exception as exc:  # noqa: BLE001
        return {"redirects_to_https": None, "error": f"{type(exc).__name__}"}


async def _security_txt(client: httpx.AsyncClient, hostname: str) -> int | None:
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = await client.get(f"https://{hostname}{path}")
            if r.status_code == 200:
                return 200
        except Exception:  # noqa: BLE001
            return None
    return 404


def _err(exc: object) -> str:
    if isinstance(exc, BaseException):
        return f"{type(exc).__name__}: {exc}"
    return "unknown error"


async def run_scan(raw_hostname: str) -> dict:
    """Public entrypoint. Returns a result dict matching schemas.ScanResult."""
    started = time.perf_counter()
    hostname = normalize_hostname(raw_hostname)
    ips = resolve_and_guard(hostname)  # raises TargetNotAllowed on private/invalid

    ctx = await _probe(hostname, ips)

    categories: list[dict] = []
    summary = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for key, label, fn in CATEGORIES:
        findings = [f.to_dict() for f in fn(ctx)]
        for f in findings:
            summary[f["status"]] = summary.get(f["status"], 0) + 1
        categories.append({"key": key, "label": label, "findings": findings})

    scored = compute(categories)
    return {
        "hostname": hostname,
        "grade": scored["grade"],
        "score": scored["score"],
        "max_score": scored["max_score"],
        "categories": scored["categories"],
        "summary": summary,
        "engine_version": ENGINE_VERSION,
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }
