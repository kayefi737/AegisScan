"""Three small categories: redirects, mixed content, HTTP protocol version."""
from __future__ import annotations

import re

from .base import FAIL, INFO, PASS, SEV_LOW, SEV_MEDIUM, WARN, Finding, ProbeContext

OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"
OWASP_CRYPTO = "A02:2021 Cryptographic Failures"

_HTTP_ASSET = re.compile(r"""(?:src|href)\s*=\s*['"]http://[^'"]+['"]""", re.IGNORECASE)


def run_redirects(ctx: ProbeContext) -> list[Finding]:
    if not ctx.https_ok:
        return [Finding("Redirects", INFO, SEV_LOW, "Skipped - no HTTPS response.")]

    hops = ctx.hops
    findings = [
        Finding("Redirect chain length is reasonable",
                PASS if len(hops) <= 3 else WARN,
                SEV_LOW,
                f"{len(hops)} redirect hop(s) before the final response.",
                None if len(hops) <= 3 else "Collapse long redirect chains; each hop adds latency and risk.",
                [OWASP_MISCONFIG])
    ]

    # Downgrade inside the chain (https -> http) is dangerous.
    downgrade = any(h.location and h.location.startswith("http://") for h in hops)
    if downgrade:
        findings.append(
            Finding("No HTTPS->HTTP downgrade in redirects", FAIL, SEV_MEDIUM,
                    "A redirect in the chain points to a plain-HTTP URL.",
                    "Ensure every redirect target uses https://.", [OWASP_CRYPTO])
        )
    else:
        findings.append(Finding("No HTTPS->HTTP downgrade in redirects", PASS, SEV_LOW,
                                "No insecure downgrade detected in the redirect chain.", owasp=[OWASP_CRYPTO]))
    return findings


def run_mixed_content(ctx: ProbeContext) -> list[Finding]:
    if not ctx.https_ok:
        return [Finding("Mixed content", INFO, SEV_LOW, "Skipped - no HTTPS response.")]

    matches = _HTTP_ASSET.findall(ctx.body_snippet or "")
    if matches:
        return [
            Finding("No mixed (HTTP) content on an HTTPS page", FAIL, SEV_MEDIUM,
                    f"Found {len(matches)} asset reference(s) loaded over plain http:// on an https:// page.",
                    "Load every asset over https:// (or use protocol-relative // URLs).",
                    [OWASP_CRYPTO])
        ]
    return [
        Finding("No mixed (HTTP) content on an HTTPS page", PASS, SEV_LOW,
                "No obvious http:// asset references in the landing HTML.", owasp=[OWASP_CRYPTO])
    ]


def run_protocol(ctx: ProbeContext) -> list[Finding]:
    if not ctx.https_ok:
        return [Finding("HTTP protocol version", INFO, SEV_LOW, "Skipped - no HTTPS response.")]

    ver = ctx.http_version or "unknown"
    modern = ver in {"HTTP/2", "HTTP/2.0", "HTTP/3"}
    return [
        Finding("Modern HTTP protocol",
                PASS if modern else WARN,
                SEV_LOW,
                f"Negotiated {ver}.",
                None if modern else "Enable HTTP/2 (or HTTP/3) at your server / CDN for performance and multiplexing.",
                [OWASP_MISCONFIG], weight=0.5)
    ]
