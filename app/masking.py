"""Privacy-aware hostname masking for the public dashboard.

Anything not on the public-benchmark allowlist is masked so that people scanning
their own (possibly internal-sounding) hostnames are not exposed to visitors.
"""
from __future__ import annotations

from .config import get_settings


def mask_hostname(hostname: str) -> str:
    settings = get_settings()
    host = hostname.lower().strip()
    if host in settings.benchmark_set:
        return host

    # Keep the public suffix (last two labels) for context, mask the rest.
    labels = host.split(".")
    if len(labels) <= 2:
        head = labels[0]
        masked_head = head[0] + "***" if head else "***"
        suffix = "." + labels[1] if len(labels) == 2 else ""
        return masked_head + suffix

    suffix = ".".join(labels[-2:])
    first = labels[0]
    masked_first = first[0] + "***" if first else "***"
    return f"{masked_first}.***.{suffix}"
