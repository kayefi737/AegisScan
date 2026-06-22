"""Cookie attribute checks (Secure / HttpOnly / SameSite)."""
from __future__ import annotations

from .base import FAIL, INFO, PASS, SEV_LOW, SEV_MEDIUM, WARN, Finding, ProbeContext

OWASP_AUTH = "A07:2021 Identification and Authentication Failures"
OWASP_CRYPTO = "A02:2021 Cryptographic Failures"


def _cookie_name(raw: str) -> str:
    return raw.split("=", 1)[0].strip() or "(unnamed)"


def run(ctx: ProbeContext) -> list[Finding]:
    if not ctx.https_ok:
        return [Finding("Cookies", INFO, SEV_LOW, "Skipped - no HTTPS response.")]

    if not ctx.set_cookies:
        return [Finding("Cookie security", INFO, SEV_LOW, "No cookies were set on the landing response.")]

    findings: list[Finding] = []
    for raw in ctx.set_cookies:
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        name = _cookie_name(raw)
        problems = []
        if "secure" not in attrs:
            problems.append("missing Secure")
        if "httponly" not in attrs:
            problems.append("missing HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            problems.append("missing SameSite")

        if not problems:
            findings.append(
                Finding(f"Cookie '{name}' is hardened", PASS, SEV_LOW,
                        "Secure, HttpOnly and SameSite are all set.",
                        owasp=[OWASP_AUTH, OWASP_CRYPTO])
            )
        else:
            status = FAIL if "missing Secure" in problems else WARN
            findings.append(
                Finding(
                    f"Cookie '{name}' is hardened", status,
                    SEV_MEDIUM if status == FAIL else SEV_LOW,
                    f"Cookie '{name}' is {', '.join(problems)}.",
                    f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax",
                    [OWASP_AUTH, OWASP_CRYPTO],
                )
            )
    return findings
