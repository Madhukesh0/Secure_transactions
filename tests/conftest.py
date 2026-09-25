"""Shared fixtures for the SecurePay test suite."""

import pytest

from securepay import db
from securepay.crypto import generate_rsa_keypair


@pytest.fixture(scope="session")
def keypair():
    """One small RSA keypair for primitive round-trip tests."""
    priv = generate_rsa_keypair(1024)
    return priv, priv.publickey()


@pytest.fixture(scope="session")
def keypairs():
    """Distinct customer / gateway RSA keypairs for flow tests."""
    return generate_rsa_keypair(1024), generate_rsa_keypair(1024)


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Point the db layer at a throwaway database for one test."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "securepay-test.db"))
    db._local.conn = None
    db.init_db()
    yield db
    db._local.conn = None
