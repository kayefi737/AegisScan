"""Test fixtures. Configures an isolated SQLite DB BEFORE the app is imported."""
import os
import pathlib
import tempfile

# Must be set before app.* modules read settings at import time.
_tmp = tempfile.mkdtemp()
os.environ["AEGIS_SECRET_KEY"] = "test-key"
os.environ["AEGIS_DATABASE_URL"] = "sqlite:///" + (pathlib.Path(_tmp) / "test.db").as_posix()
os.environ["AEGIS_RATE_LIMIT_PER_MINUTE"] = "1000"
os.environ["AEGIS_ENV"] = "test"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_client(client):
    """A client carrying a valid bearer token for a freshly-registered user."""
    email = "tester@example.com"
    client.post("/api/auth/register", json={"email": email, "password": "supersecret"})
    res = client.post("/api/auth/login", data={"username": email, "password": "supersecret"})
    token = res.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client
