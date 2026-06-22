"""DNS and email-authentication checks: SPF, DMARC, CAA, DNSSEC, MX.

`gather()` performs the (blocking) DNS lookups and is run in a worker thread by the
runner. `run()` evaluates the gathered records into findings.
"""
from __future__ import annotations

from typing import Any

from .base import FAIL, INFO, PASS, SEV_LOW, SEV_MEDIUM, WARN, Finding, ProbeContext

OWASP_MISCONFIG = "A05:2021 Security Misconfiguration"


def gather(hostname: str, timeout: float = 5.0) -> dict[str, Any]:
    """Collect DNS records relevant to posture. Never raises - errors are captured."""
    import dns.resolver  # imported lazily so the module imports without network

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    out: dict[str, Any] = {"spf": None, "dmarc": None, "caa": [], "mx": [], "dnssec": False, "errors": []}

    def _txt(name: str) -> list[str]:
        try:
            answers = resolver.resolve(name, "TXT")
            return ["".join(s.decode() if isinstance(s, bytes) else s for s in r.strings) for r in answers]
        except Exception as exc:  # noqa: BLE001 - any DNS error is non-fatal
            out["errors"].append(f"TXT {name}: {type(exc).__name__}")
            return []

    for txt in _txt(hostname):
        if txt.lower().startswith("v=spf1"):
            out["spf"] = txt
            break

    for txt in _txt(f"_dmarc.{hostname}"):
        if txt.lower().startswith("v=dmarc1"):
            out["dmarc"] = txt
            break

    try:
        out["caa"] = [r.to_text() for r in resolver.resolve(hostname, "CAA")]
    except Exception:  # noqa: BLE001
        pass

    try:
        out["mx"] = [r.exchange.to_text() for r in resolver.resolve(hostname, "MX")]
    except Exception:  # noqa: BLE001
        pass

    try:
        resolver.resolve(hostname, "DNSKEY")
        out["dnssec"] = True
    except Exception:  # noqa: BLE001
        out["dnssec"] = False

    return out


def run(ctx: ProbeContext) -> list[Finding]:
    dns = ctx.dns or {}
    findings: list[Finding] = []

    # DMARC - the highest-value email-spoofing control.
    dmarc = dns.get("dmarc")
    if not dmarc:
        findings.append(
            Finding("DMARC policy published", FAIL, SEV_MEDIUM,
                    "No DMARC record at _dmarc." + ctx.hostname + ". Attackers can spoof this domain in email.",
                    "_dmarc.%s  TXT  \"v=DMARC1; p=quarantine; rua=mailto:dmarc@%s\"" % (ctx.hostname, ctx.hostname),
                    [OWASP_MISCONFIG], weight=1.5)
        )
    elif "p=none" in dmarc.replace(" ", "").lower():
        findings.append(
            Finding("DMARC policy published", WARN, SEV_LOW,
                    "DMARC is in monitor-only mode (p=none).",
                    "Tighten to p=quarantine or p=reject once you have reviewed reports.",
                    [OWASP_MISCONFIG], weight=1.5)
        )
    else:
        findings.append(Finding("DMARC policy published", PASS, SEV_LOW, f"DMARC set: {dmarc}", owasp=[OWASP_MISCONFIG], weight=1.5))

    # SPF
    spf = dns.get("spf")
    if not spf:
        findings.append(
            Finding("SPF record published", WARN, SEV_LOW,
                    "No SPF record. Receivers cannot verify which servers may send mail for this domain.",
                    "%s  TXT  \"v=spf1 include:_spf.yourprovider.com -all\"" % ctx.hostname,
                    [OWASP_MISCONFIG])
        )
    else:
        findings.append(Finding("SPF record published", PASS, SEV_LOW, f"SPF set: {spf}", owasp=[OWASP_MISCONFIG]))

    # CAA - constrains which CAs may issue certs.
    if dns.get("caa"):
        findings.append(Finding("CAA record restricts certificate issuance", PASS, SEV_LOW,
                                f"{len(dns['caa'])} CAA record(s) present.", owasp=[OWASP_MISCONFIG], weight=0.5))
    else:
        findings.append(
            Finding("CAA record restricts certificate issuance", WARN, SEV_LOW,
                    "No CAA record; any CA may issue certificates for this domain.",
                    "%s  CAA  0 issue \"letsencrypt.org\"" % ctx.hostname, [OWASP_MISCONFIG], weight=0.5)
        )

    # DNSSEC
    if dns.get("dnssec"):
        findings.append(Finding("DNSSEC enabled", PASS, SEV_LOW, "DNSKEY records present.", owasp=[OWASP_MISCONFIG], weight=0.5))
    else:
        findings.append(
            Finding("DNSSEC enabled", INFO, SEV_LOW,
                    "No DNSKEY found. DNSSEC is valuable but not yet universal; treat as advisory.",
                    "Enable DNSSEC at your DNS provider.", [OWASP_MISCONFIG], weight=0.5)
        )

    return findings
