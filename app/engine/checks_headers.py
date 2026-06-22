"""HTTP security-header checks."""
from __future__ import annotations

from .base import (
    FAIL,
    INFO,
    PASS,
    SEV_LOW,
    SEV_MEDIUM,
    WARN,
    Finding,
    ProbeContext,
)

OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"


def run(ctx: ProbeContext) -> list[Finding]:
    if not ctx.https_ok:
        return [
            Finding(
                title="Security headers",
                status=INFO,
                severity=SEV_LOW,
                detail="Skipped - no successful HTTPS response to inspect.",
            )
        ]

    findings: list[Finding] = []

    # HSTS
    hsts = ctx.header("strict-transport-security")
    if not hsts:
        findings.append(
            Finding(
                "Strict-Transport-Security (HSTS) present", FAIL, SEV_MEDIUM,
                "No HSTS header. Browsers may still try plain HTTP.",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                [OWASP_MISCONFIG], weight=2.0,
            )
        )
    else:
        max_age = _directive_int(hsts, "max-age")
        if max_age is not None and max_age < 15552000:  # < 180 days
            findings.append(
                Finding(
                    "Strict-Transport-Security (HSTS) present", WARN, SEV_LOW,
                    f"HSTS present but max-age is low ({max_age}s).",
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    [OWASP_MISCONFIG], weight=2.0,
                )
            )
        else:
            findings.append(
                Finding(
                    "Strict-Transport-Security (HSTS) present", PASS, SEV_LOW,
                    f"HSTS set ({hsts}).", owasp=[OWASP_MISCONFIG], weight=2.0,
                )
            )

    # X-Content-Type-Options
    findings.append(
        _simple_presence(
            ctx, "x-content-type-options",
            "X-Content-Type-Options: nosniff",
            expected_value="nosniff",
            fix="X-Content-Type-Options: nosniff",
        )
    )

    # Clickjacking protection: X-Frame-Options OR CSP frame-ancestors
    xfo = ctx.header("x-frame-options")
    csp = ctx.header("content-security-policy") or ""
    if xfo or "frame-ancestors" in csp.lower():
        findings.append(
            Finding(
                "Clickjacking protection", PASS, SEV_LOW,
                "Protected via " + ("X-Frame-Options" if xfo else "CSP frame-ancestors") + ".",
                owasp=[OWASP_MISCONFIG],
            )
        )
    else:
        findings.append(
            Finding(
                "Clickjacking protection", FAIL, SEV_MEDIUM,
                "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                "Content-Security-Policy: frame-ancestors 'self'   (or X-Frame-Options: DENY)",
                [OWASP_MISCONFIG],
            )
        )

    # Referrer-Policy
    rp = ctx.header("referrer-policy")
    strong = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
    if rp and any(v.strip().lower() in strong for v in rp.split(",")):
        findings.append(Finding("Referrer-Policy set", PASS, SEV_LOW, f"Referrer-Policy: {rp}", owasp=[OWASP_MISCONFIG]))
    elif rp:
        findings.append(
            Finding("Referrer-Policy set", WARN, SEV_LOW, f"Weak Referrer-Policy: {rp}",
                    "Referrer-Policy: strict-origin-when-cross-origin", [OWASP_MISCONFIG])
        )
    else:
        findings.append(
            Finding("Referrer-Policy set", FAIL, SEV_LOW, "No Referrer-Policy header.",
                    "Referrer-Policy: strict-origin-when-cross-origin", [OWASP_MISCONFIG])
        )

    # Permissions-Policy
    findings.append(
        _simple_presence(
            ctx, "permissions-policy",
            "Permissions-Policy present",
            fix="Permissions-Policy: geolocation=(), camera=(), microphone=()",
            missing_status=WARN,
        )
    )

    # Cross-Origin-Opener-Policy (isolation - a modern hardening header)
    findings.append(
        _simple_presence(
            ctx, "cross-origin-opener-policy",
            "Cross-Origin-Opener-Policy present",
            fix="Cross-Origin-Opener-Policy: same-origin",
            missing_status=WARN, weight=0.5,
        )
    )

    # Server / X-Powered-By version disclosure
    server = ctx.header("server") or ""
    powered = ctx.header("x-powered-by")
    if powered or any(ch.isdigit() for ch in server):
        findings.append(
            Finding(
                "Software version not disclosed", WARN, SEV_LOW,
                f"Response advertises software details (Server: {server!r}"
                + (f", X-Powered-By: {powered!r}" if powered else "") + ").",
                "Strip version numbers: set 'server_tokens off' (nginx) and remove X-Powered-By.",
                [OWASP_MISCONFIG], weight=0.5,
            )
        )
    else:
        findings.append(
            Finding("Software version not disclosed", PASS, SEV_LOW,
                    "No obvious version disclosure in Server/X-Powered-By.", owasp=[OWASP_MISCONFIG], weight=0.5)
        )

    return findings


def _directive_int(header_value: str, name: str) -> int | None:
    for part in header_value.split(";"):
        part = part.strip()
        if part.lower().startswith(name.lower() + "="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _simple_presence(
    ctx: ProbeContext,
    header: str,
    title: str,
    *,
    expected_value: str | None = None,
    fix: str,
    missing_status: str = FAIL,
    weight: float = 1.0,
) -> Finding:
    value = ctx.header(header)
    if value is None:
        return Finding(title, missing_status, SEV_MEDIUM, f"Missing {header} header.", fix, [OWASP_MISCONFIG], weight)
    if expected_value and expected_value.lower() not in value.lower():
        return Finding(title, WARN, SEV_LOW, f"{header}: {value} (expected '{expected_value}').", fix, [OWASP_MISCONFIG], weight)
    return Finding(title, PASS, SEV_LOW, f"{header}: {value}", owasp=[OWASP_MISCONFIG], weight=weight)
