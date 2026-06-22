"""Deep Content-Security-Policy analysis (a PostureScan 'future work' item)."""
from __future__ import annotations

from .base import FAIL, INFO, PASS, SEV_LOW, SEV_MEDIUM, WARN, Finding, ProbeContext

OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"
OWASP_INJECTION = "A03:2021 Injection"


def _parse(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if not parts:
            continue
        out[parts[0].lower()] = [p.lower() for p in parts[1:]]
    return out


def run(ctx: ProbeContext) -> list[Finding]:
    if not ctx.https_ok:
        return [Finding("Content-Security-Policy", INFO, SEV_LOW, "Skipped - no HTTPS response.")]

    csp = ctx.header("content-security-policy")
    if not csp:
        return [
            Finding(
                "Content-Security-Policy present", FAIL, SEV_MEDIUM,
                "No CSP header. CSP is the strongest defence-in-depth against XSS.",
                "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
                [OWASP_MISCONFIG, OWASP_INJECTION], weight=2.0,
            )
        ]

    findings = [
        Finding("Content-Security-Policy present", PASS, SEV_LOW, "A CSP header is set.",
                owasp=[OWASP_MISCONFIG], weight=2.0)
    ]
    policy = _parse(csp)
    script = policy.get("script-src", policy.get("default-src", []))

    # unsafe-inline / unsafe-eval in script context
    if "'unsafe-inline'" in script:
        findings.append(
            Finding("CSP avoids 'unsafe-inline' scripts", FAIL, SEV_MEDIUM,
                    "script-src allows 'unsafe-inline', which largely defeats CSP's XSS protection.",
                    "Remove 'unsafe-inline'; adopt nonces or hashes for inline scripts.",
                    [OWASP_INJECTION], weight=1.5)
        )
    else:
        findings.append(Finding("CSP avoids 'unsafe-inline' scripts", PASS, SEV_LOW,
                                "No 'unsafe-inline' in the script context.", owasp=[OWASP_INJECTION], weight=1.5))

    if "'unsafe-eval'" in script:
        findings.append(
            Finding("CSP avoids 'unsafe-eval'", WARN, SEV_LOW,
                    "script-src allows 'unsafe-eval'.",
                    "Remove 'unsafe-eval' and refactor any eval()/new Function() usage.",
                    [OWASP_INJECTION])
        )
    else:
        findings.append(Finding("CSP avoids 'unsafe-eval'", PASS, SEV_LOW, "No 'unsafe-eval'.", owasp=[OWASP_INJECTION]))

    # default-src present
    if "default-src" in policy:
        findings.append(Finding("CSP sets a default-src fallback", PASS, SEV_LOW, "default-src is defined.", owasp=[OWASP_MISCONFIG]))
    else:
        findings.append(
            Finding("CSP sets a default-src fallback", WARN, SEV_LOW,
                    "No default-src; directives you forgot to set will be unrestricted.",
                    "Add: default-src 'self'", [OWASP_MISCONFIG])
        )

    # object-src 'none'
    obj = policy.get("object-src", policy.get("default-src", []))
    if obj == ["'none'"]:
        findings.append(Finding("CSP disables plugins (object-src 'none')", PASS, SEV_LOW, "object-src 'none' set.", owasp=[OWASP_MISCONFIG]))
    else:
        findings.append(
            Finding("CSP disables plugins (object-src 'none')", WARN, SEV_LOW,
                    "object-src is not locked to 'none'.", "Add: object-src 'none'", [OWASP_MISCONFIG])
        )

    # wildcard source
    if any("*" in src for srcs in policy.values() for src in srcs if src not in {"'none'"}):
        findings.append(
            Finding("CSP avoids wildcard sources", WARN, SEV_MEDIUM,
                    "A directive uses a '*' wildcard source, weakening the policy.",
                    "Replace '*' with explicit origins.", [OWASP_MISCONFIG])
        )
    else:
        findings.append(Finding("CSP avoids wildcard sources", PASS, SEV_LOW, "No wildcard sources detected.", owasp=[OWASP_MISCONFIG]))

    return findings
