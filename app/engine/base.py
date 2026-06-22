"""Shared types for the scan engine: findings, probe context, helpers."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

# Finding statuses
PASS = "pass"
WARN = "warn"
FAIL = "fail"
INFO = "info"

# Severities
SEV_INFO = "info"
SEV_LOW = "low"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"


def _slug(title: str) -> str:
    return hashlib.sha1(title.encode()).hexdigest()[:10]


@dataclass
class Finding:
    title: str
    status: str
    severity: str = SEV_MEDIUM
    detail: str = ""
    fix: str | None = None
    owasp: list[str] = field(default_factory=list)
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": _slug(self.title),
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "detail": self.detail,
            "fix": self.fix,
            "owasp": self.owasp,
            "weight": self.weight,
        }


@dataclass
class Hop:
    url: str
    status_code: int
    location: str | None = None


@dataclass
class ProbeContext:
    """Everything the checks need, gathered once up front and shared."""

    hostname: str
    resolved_ips: list[str]

    # HTTPS fetch of the apex over TLS
    https_ok: bool = False
    https_error: str = ""
    final_url: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased keys
    set_cookies: list[str] = field(default_factory=list)
    body_snippet: str = ""
    http_version: str = ""
    hops: list[Hop] = field(default_factory=list)

    # Plain HTTP fetch (to verify redirect-to-HTTPS behaviour)
    http_redirects_to_https: bool | None = None
    http_error: str = ""

    # TLS handshake details
    tls_version: str = ""
    tls_cert_days_remaining: int | None = None
    tls_cert_issuer: str = ""
    tls_error: str = ""

    # DNS / email
    dns: dict[str, Any] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())
