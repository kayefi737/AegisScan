import socket

import pytest

from app.guard import TargetNotAllowed, normalize_hostname, resolve_and_guard


def test_normalize_strips_scheme_path_port():
    assert normalize_hostname("https://Example.com:443/path?x=1") == "example.com"
    assert normalize_hostname("  HTTP://sub.example.com/  ") == "sub.example.com"


def test_normalize_rejects_bad_input():
    for bad in ["", "localhost", "not a host", "noTLD", "my.local"]:
        with pytest.raises(TargetNotAllowed):
            normalize_hostname(bad)


def test_guard_blocks_private_ip(monkeypatch):
    # Pretend the hostname resolves to a private address.
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, None, None, "", ("192.168.1.10", 0))],
    )
    with pytest.raises(TargetNotAllowed):
        resolve_and_guard("internal.example.com")


def test_guard_allows_public_ip(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))],
    )
    assert resolve_and_guard("example.com") == ["93.184.216.34"]


def test_guard_blocks_loopback(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, None, None, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(TargetNotAllowed):
        resolve_and_guard("evil.example.com")
