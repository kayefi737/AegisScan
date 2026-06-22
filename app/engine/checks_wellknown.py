"""/.well-known checks (currently: security.txt per RFC 9116).

The runner fetches /.well-known/security.txt and stores the status code in
ctx.dns['security_txt_status'] to avoid a second probe pass here.
"""
from __future__ import annotations

from .base import INFO, PASS, SEV_LOW, WARN, Finding, ProbeContext

OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"


def run(ctx: ProbeContext) -> list[Finding]:
    status = (ctx.dns or {}).get("security_txt_status")
    if status == 200:
        return [
            Finding("security.txt published (RFC 9116)", PASS, SEV_LOW,
                    "A /.well-known/security.txt file is served, giving researchers a contact path.",
                    owasp=[OWASP_MISCONFIG], weight=0.5)
        ]
    if status is None:
        return [Finding("security.txt published (RFC 9116)", INFO, SEV_LOW, "Could not test /.well-known/security.txt.")]
    return [
        Finding("security.txt published (RFC 9116)", WARN, SEV_LOW,
                "No /.well-known/security.txt; researchers have no documented way to report issues.",
                "Publish /.well-known/security.txt with Contact: and Expires: fields.",
                [OWASP_MISCONFIG], weight=0.5)
    ]
