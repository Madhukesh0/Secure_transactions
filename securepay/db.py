"""
SQLite persistence for the SecurePay MVP.

Stores an audit trail that survives browser refreshes and app restarts:

  transactions - one row per gateway decision (APPROVED / REJECTED)
                 includes the envelope itself (JSON), auth code, amount
  attacks      - one row per attack attempt, outcome, and detection reason
  customers    - account sign-ups: CUST-XXXXXX id + salted PBKDF2
                 password hash (the plaintext password is never stored)
  meta         - simple key/value (schema version, counters)

Run standalone to inspect:  python -m securepay.db
"""

import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

from securepay.crypto import hash_password, verify_password

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_PROJECT_ROOT, "securepay.db")

_lock = threading.Lock()
_local = threading.local()


def _conn():
    """One connection per thread."""
    if getattr(_local, "conn", None) is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    """Create tables if missing (idempotent, safe to call on every run)."""
    with _lock, _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                txn_id      TEXT    NOT NULL,
                ts          TEXT    NOT NULL,
                decision    TEXT    NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
                auth_code   TEXT,
                amount      REAL,
                currency    TEXT,
                reason      TEXT,          -- rejection reason if any
                envelope    TEXT NOT NULL  -- full JSON of what arrived
            );
            CREATE INDEX IF NOT EXISTS idx_txn_id ON transactions(txn_id);

            CREATE TABLE IF NOT EXISTS attacks (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                attack    TEXT    NOT NULL,
                blocked   INTEGER NOT NULL CHECK (blocked IN (0,1)),
                reason    TEXT,
                txn_id    TEXT
            );

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS customers (
                id            TEXT PRIMARY KEY,
                name          TEXT NOT NULL,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,   -- pbkdf2_sha256$iter$salt$hash
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_customer_email ON customers(email);
            """
        )
        c.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '1')"
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record_transaction(txn_id, decision, envelope, auth=None, reason=None):
    """Log one gateway decision. Returns the new row id."""
    amount = None
    currency = None
    if auth and isinstance(auth.get("amount"), dict):
        amount = auth["amount"].get("value")
        currency = auth["amount"].get("currency")
    with _lock, _conn() as c:
        cur = c.execute(
            """INSERT INTO transactions
               (txn_id, ts, decision, auth_code, amount, currency, reason, envelope)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                txn_id,
                _now(),
                decision,
                (auth or {}).get("auth_code"),
                amount,
                currency,
                reason,
                json.dumps(envelope),
            ),
        )
        return cur.lastrowid


def record_attack(attack, blocked, reason=None, txn_id=None):
    """Log one attack attempt."""
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO attacks (ts, attack, blocked, reason, txn_id) VALUES (?,?,?,?,?)",
            (_now(), attack, 1 if blocked else 0, reason, txn_id),
        )
        return cur.lastrowid


def list_transactions(limit=50):
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM transactions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def list_attacks(limit=50):
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def stats() -> dict:
    with _lock, _conn() as c:
        total_tx = c.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        approved = c.execute(
            "SELECT COUNT(*) FROM transactions WHERE decision='APPROVED'"
        ).fetchone()[0]
        total_atk = c.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        blocked = c.execute("SELECT COUNT(*) FROM attacks WHERE blocked=1").fetchone()[0]
        replayed = c.execute(
            "SELECT COUNT(DISTINCT txn_id) FROM transactions WHERE reason LIKE '%replay%'"
        ).fetchone()[0]
        return {
            "transactions": total_tx,
            "approved": approved,
            "rejected": total_tx - approved,
            "attacks": total_atk,
            "blocked": blocked,
            "distinct_txns": replayed,
        }


def clear_all():
    """Wipe everything (used by the sidebar 'Reset demo' button)."""
    with _lock, _conn() as c:
        c.execute("DELETE FROM transactions")
        c.execute("DELETE FROM attacks")


# --- customer accounts --------------------------------------------------------

def _new_customer_id():
    """Random unique CUST-XXXXXX id (look-alike letters/digits excluded)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    with _lock, _conn() as c:
        while True:
            cid = "CUST-" + "".join(secrets.choice(alphabet) for _ in range(6))
            if c.execute("SELECT 1 FROM customers WHERE id=?", (cid,)).fetchone() is None:
                return cid


def get_customer(customer_id):
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM customers WHERE id=?",
                        (customer_id,)).fetchone()
        return dict(row) if row else None


def get_customer_by_email(email):
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM customers WHERE email=?",
                        (str(email or "").strip().lower(),)).fetchone()
        return dict(row) if row else None


def register_customer(name, email, password):
    """Create an account, hash the password, return {'id','name','email'}."""
    name = str(name or "").strip()
    email = str(email or "").strip().lower()
    if not name or not email or not password:
        raise ValueError("Name, email and password are all required.")
    if "@" not in email or "." not in email:
        raise ValueError("That email address doesn't look valid.")
    if len(str(password)) < 6:
        raise ValueError("Password must be at least 6 characters.")
    if get_customer_by_email(email):
        raise ValueError(f"An account with {email} already exists — sign in instead.")
    cid = _new_customer_id()
    try:
        with _lock, _conn() as c:
            c.execute(
                """INSERT INTO customers (id, name, email, password_hash, created_at)
                   VALUES (?,?,?,?,?)""",
                (cid, name, email, hash_password(str(password)), _now()),
            )
    except sqlite3.IntegrityError:
        raise ValueError(f"An account with {email} already exists — sign in instead.")
    return {"id": cid, "name": name, "email": email}


def login_customer(email, password):
    """Check credentials; returns {'id','name','email'} or None (same message
    for unknown email and wrong password — never reveal which one failed)."""
    row = get_customer_by_email(email)
    if row and verify_password(str(password), row["password_hash"]):
        return {"id": row["id"], "name": row["name"], "email": row["email"]}
    return None


def list_customers(limit=50):
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT id, name, email, created_at, password_hash "
            "FROM customers ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def _demo():
    init_db()
    env = {"txn_id": "TXN-DEMO", "iv": "x", "ciphertext": "y"}
    record_transaction("TXN-DEMO", "APPROVED", env,
                       auth={"auth_code": "AUTH-TEST", "amount": {"value": 1648, "currency": "INR"}})
    record_transaction("TXN-DEMO", "REJECTED", env, reason="replay")
    record_attack("Bit-flip", True, "JSON decode FAILED", "TXN-DEMO")
    print("stats:", stats())
    print("transactions:", json.dumps(list_transactions(), indent=2))
    print("attacks:", json.dumps(list_attacks(), indent=2))


if __name__ == "__main__":
    _demo()
