"""
Functional tests for the target app's *normal* behaviour.
These exist so future security patches can be verified not to break anything.
Run with:  pytest tests/
"""

import os
import sys
import pytest

# Ensure the app module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app, init_db, DATABASE, SAFE_DIR  # noqa: E402


@pytest.fixture(autouse=True)
def setup_app(tmp_path):
    """Create a fresh DB and public dir for every test."""
    import app as app_module

    db_path = str(tmp_path / "test_users.db")
    pub_dir = str(tmp_path / "public")
    os.makedirs(pub_dir, exist_ok=True)

    # Write a sample file for the /file endpoint
    with open(os.path.join(pub_dir, "hello.txt"), "w") as f:
        f.write("Hello from tests!\n")

    # Patch module-level constants
    app_module.DATABASE = db_path
    app_module.SAFE_DIR = pub_dir

    init_db()
    app.config["TESTING"] = True
    yield


@pytest.fixture
def client():
    return app.test_client()


# ---- Test 1: Home page loads -------------------------------------------
def test_index_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Target App" in resp.data


# ---- Test 2: Valid login succeeds --------------------------------------
def test_valid_login(client):
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "password123"},
    )
    assert resp.status_code == 200
    assert b"Welcome" in resp.data
    assert b"alice" in resp.data


# ---- Test 3: Invalid login is rejected ---------------------------------
def test_invalid_login(client):
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "wrongpass"},
    )
    assert resp.status_code == 401
    assert b"Invalid credentials" in resp.data


# ---- Test 4: Search returns matching users -----------------------------
def test_search_returns_results(client):
    resp = client.get("/search?q=bob")
    assert resp.status_code == 200
    assert b"bob" in resp.data


# ---- Test 5: File endpoint serves a legitimate file --------------------
def test_file_serves_public_file(client):
    resp = client.get("/file?name=hello.txt")
    assert resp.status_code == 200
    assert b"Hello from tests!" in resp.data
