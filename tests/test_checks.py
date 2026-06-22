"""Unit tests for individual checks - no network, synthetic ProbeContext."""
from app.engine import checks_cookies, checks_csp, checks_dns, checks_headers, checks_tls
from app.engine.base import ProbeContext


def _ctx(**kw) -> ProbeContext:
    base = dict(hostname="example.com", resolved_ips=["93.184.216.34"], https_ok=True)
    base.update(kw)
    return ProbeContext(**base)


def _by_title(findings, title):
    return next(f for f in findings if f.title == title)


def test_tls_fail_when_https_down():
    findings = checks_tls.run(_ctx(https_ok=False, https_error="timeout"))
    assert _by_title(findings, "Site reachable over HTTPS").status == "fail"


def test_tls_pass_modern_and_valid_cert():
    findings = checks_tls.run(_ctx(
        tls_version="TLSv1.3", tls_cert_days_remaining=90, http_redirects_to_https=True,
    ))
    assert _by_title(findings, "Modern TLS protocol negotiated").status == "pass"
    assert _by_title(findings, "Certificate is current").status == "pass"
    assert _by_title(findings, "Plain HTTP redirects to HTTPS").status == "pass"


def test_headers_missing_hsts_fails():
    findings = checks_headers.run(_ctx(headers={}))
    assert _by_title(findings, "Strict-Transport-Security (HSTS) present").status == "fail"


def test_headers_all_present_pass():
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "cross-origin-opener-policy": "same-origin",
        "server": "nginx",
    }
    findings = checks_headers.run(_ctx(headers=headers))
    assert _by_title(findings, "Strict-Transport-Security (HSTS) present").status == "pass"
    assert _by_title(findings, "Clickjacking protection").status == "pass"


def test_csp_unsafe_inline_flagged():
    findings = checks_csp.run(_ctx(headers={"content-security-policy": "script-src 'self' 'unsafe-inline'"}))
    assert _by_title(findings, "CSP avoids 'unsafe-inline' scripts").status == "fail"


def test_cookie_without_secure_fails():
    findings = checks_cookies.run(_ctx(set_cookies=["sid=abc; HttpOnly; SameSite=Lax"]))
    assert _by_title(findings, "Cookie 'sid' is hardened").status == "fail"


def test_dns_missing_dmarc_fails():
    findings = checks_dns.run(_ctx(dns={"dmarc": None, "spf": "v=spf1 -all", "caa": ["x"], "dnssec": True}))
    assert _by_title(findings, "DMARC policy published").status == "fail"
    assert _by_title(findings, "SPF record published").status == "pass"
