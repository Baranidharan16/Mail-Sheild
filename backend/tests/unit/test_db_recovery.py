"""
Targeted tests for MailShield Database Recovery, Connectivity, and Migration.
"""
import os
import sqlite3
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from main import app
from app.database.session import get_db
from scripts.migrate_sqlite_to_pg import run_migration


client = TestClient(app, raise_server_exceptions=False)


def test_db_unavailable_exception_handler():
    """Verify that database connection failures return HTTP 503 with the exact safe detail message."""
    def raise_db_error():
        raise OperationalError("SELECT 1", {}, Exception("Connection refused to postgresql-host:5432"))
        yield

    app.dependency_overrides[get_db] = raise_db_error
    try:
        resp = client.post("/api/auth/login", json={"email": "analyst@mailshield.ai", "password": "Password123!"})
        assert resp.status_code == 503
        data = resp.json()
        assert data.get("detail") == "The database is temporarily unavailable. Please try again shortly."
        # Verify no credentials or internal host info are leaked to the client
        assert "postgresql-host" not in resp.text
        assert "password" not in resp.text.lower() or "Password123" not in resp.text
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_health_check_database_connectivity():
    """Verify health endpoint accurately reflects database status without throwing unhandled exceptions."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "database" in data
    assert data["database"] in ("ok", "unavailable")
    # Verify no credentials leaked
    assert "password" not in str(data).lower()


def test_migration_dry_run_and_execution(tmp_path):
    """Verify migrate_sqlite_to_pg works in dry-run and live modes with data validation."""
    source_sqlite = tmp_path / "source.db"
    target_sqlite = tmp_path / "target.db"

    # Create dummy source with one table
    conn = sqlite3.connect(source_sqlite)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255), email VARCHAR(255), password_hash VARCHAR(255), created_at TIMESTAMP, updated_at TIMESTAMP, last_login TIMESTAMP, is_active BOOLEAN)")
    cur.execute("INSERT INTO users VALUES ('u1', 'Test', 'test@example.com', 'hash123', '2026-01-01 00:00:00', '2026-01-01 00:00:00', NULL, 1)")
    conn.commit()
    conn.close()

    target_url = f"sqlite:///{target_sqlite}"

    # Dry-run
    ok_dry = run_migration(str(source_sqlite), target_url, dry_run=True)
    assert ok_dry is True
    # Verify dry-run created 0 user tables
    t_conn = sqlite3.connect(target_sqlite)
    t_cur = t_conn.cursor()
    tables = [r[0] for r in t_cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    t_conn.close()
    assert "users" not in tables

    # Live run
    ok_live = run_migration(str(source_sqlite), target_url, dry_run=False)
    assert ok_live is True

    # Verify target row count
    t_conn = sqlite3.connect(target_sqlite)
    t_cur = t_conn.cursor()
    count = t_cur.execute("SELECT count(*) FROM users").fetchone()[0]
    t_conn.close()
    assert count == 1
