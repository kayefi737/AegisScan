"""SSRF guard + hostname normalisation.

The scanner makes outbound requests to user-supplied hostnames, so it MUST refuse
to probe private / loopback / link-local / reserved address space. This is the
same class of protection PostureScan described, implemented defensively here.
"""
from __future__ import annotations

import ipaddress
import socket

from .config import get_settings


class TargetNotAllowed(ValueError):
    """Raised when a hostname is invalid or resolves to a disallowed address."""


def normalize_hostname(raw: str) -> str:
    """Strip scheme, path, port, userinfo and lower-case a user-supplied target."""
    host = (raw or "").strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]      # drop path
    host = host.split("@")[-1]        # drop userinfo
    host = host.split(":", 1)[0]      # drop port
    host = host.strip(".")
    if not host or " " in host or "." not in host:
        raise TargetNotAllowed("Enter a valid public hostname, e.g. example.com")
    # Reject obviously local names.
    if host in {"localhost"} or host.endswith(".localhost") or host.endswith(".local"):
        raise TargetNotAllowed("Local hostnames cannot be scanned")
    return host


def _is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_guard(hostname: str) -> list[str]:
    """Resolve a hostname and ensure every resolved IP is public.

    Returns the list of resolved IPs. Raises TargetNotAllowed otherwise.
    """
    settings = get_settings()
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"Could not resolve '{hostname}'") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise TargetNotAllowed(f"Could not resolve '{hostname}'")

    if settings.allow_private_targets:
        return ips

    for ip in ips:
        if not _is_public_ip(ip):
            raise TargetNotAllowed(
                f"'{hostname}' resolves to a non-public address ({ip}) and was blocked"
            )
    return ips
