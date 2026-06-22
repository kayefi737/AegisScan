"""TLS / transport checks."""
from __future__ import annotations

from .base import (
    FAIL,
    INFO,
    PASS,
    SEV_HIGH,
    SEV_LOW,
    SEV_MEDIUM,
    WARN,
    Finding,
    ProbeContext,
)

OWASP_CRYPTO = "A02:2021 Cryptographic Failures"


def run(ctx: ProbeContext) -> list[Finding]:
    findings: list[Finding] = []

    # 1. HTTPS reachable at all
    if not ctx.https_ok:
        findings.append(
            Finding(
                title="Site reachable over HTTPS",
                status=FAIL,
                severity=SEV_HIGH,
                detail=f"Could not complete an HTTPS request: {ctx.https_error or 'unknown error'}.",
                fix="Serve the site over HTTPS with a valid certificate (e.g. via Let's Encrypt / your CDN).",
                owasp=[OWASP_CRYPTO],
                weight=3.0,
            )
        )
        # Without a successful TLS handshake the remaining TLS checks are moot.
        return findings

    findings.append(
        Finding(
            title="Site reachable over HTTPS",
            status=PASS,
            severity=SEV_HIGH,
            detail="The apex responded successfully over TLS.",
            owasp=[OWASP_CRYPTO],
            weight=3.0,
        )
    )

    # 2. Negotiated TLS protocol version
    ver = ctx.tls_version or ""
    if ver in {"TLSv1.3", "TLSv1.2"}:
        findings.append(
            Finding(
                title="Modern TLS protocol negotiated",
                status=PASS,
                severity=SEV_MEDIUM,
                detail=f"Connection negotiated {ver}.",
                owasp=[OWASP_CRYPTO],
                weight=2.0,
            )
        )
    elif ver:
        findings.append(
            Finding(
                title="Modern TLS protocol negotiated",
                status=FAIL,
                severity=SEV_HIGH,
                detail=f"Connection negotiated {ver}, which is deprecated.",
                fix="Disable TLS 1.0/1.1 and require TLS 1.2+ at your server or CDN edge.",
                owasp=[OWASP_CRYPTO],
                weight=2.0,
            )
        )

    # 3. Certificate expiry
    days = ctx.tls_cert_days_remaining
    if days is not None:
        if days < 0:
            findings.append(
                Finding(
                    title="Certificate is current",
                    status=FAIL,
                    severity=SEV_HIGH,
                    detail=f"The certificate expired {abs(days)} day(s) ago.",
                    fix="Renew the certificate immediately and automate renewal.",
                    owasp=[OWASP_CRYPTO],
                    weight=2.0,
                )
            )
        elif days < 14:
            findings.append(
                Finding(
                    title="Certificate is current",
                    status=WARN,
                    severity=SEV_MEDIUM,
                    detail=f"The certificate expires in {days} day(s).",
                    fix="Renew soon and confirm auto-renewal is working.",
                    owasp=[OWASP_CRYPTO],
                    weight=2.0,
                )
            )
        else:
            findings.append(
                Finding(
                    title="Certificate is current",
                    status=PASS,
                    severity=SEV_LOW,
                    detail=f"Valid for another {days} day(s). Issuer: {ctx.tls_cert_issuer or 'unknown'}.",
                    owasp=[OWASP_CRYPTO],
                    weight=2.0,
                )
            )

    # 4. HTTP -> HTTPS redirect
    if ctx.http_redirects_to_https is True:
        findings.append(
            Finding(
                title="Plain HTTP redirects to HTTPS",
                status=PASS,
                severity=SEV_MEDIUM,
                detail="An http:// request is redirected to https://.",
                owasp=[OWASP_CRYPTO],
                weight=2.0,
            )
        )
    elif ctx.http_redirects_to_https is False:
        findings.append(
            Finding(
                title="Plain HTTP redirects to HTTPS",
                status=FAIL,
                severity=SEV_HIGH,
                detail="The site answers over plain HTTP without redirecting to HTTPS.",
                fix="Add a 301 redirect from http:// to https:// for all paths.",
                owasp=[OWASP_CRYPTO],
                weight=2.0,
            )
        )
    else:
        findings.append(
            Finding(
                title="Plain HTTP redirects to HTTPS",
                status=INFO,
                severity=SEV_LOW,
                detail=f"Could not test plain HTTP ({ctx.http_error or 'no response'}).",
            )
        )

    return findings
