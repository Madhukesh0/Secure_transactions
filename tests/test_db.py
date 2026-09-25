"""Audit-trail tests for securepay.db (run against a throwaway database)."""

import json


def test_record_and_list_transaction(tmp_db):
    row_id = tmp_db.record_transaction(
        "TXN-1", "APPROVED", {"txn_id": "TXN-1"},
        auth={"auth_code": "AUTH-1",
              "amount": {"value": 1648.0, "currency": "INR"}})
    assert row_id == 1
    rows = tmp_db.list_transactions()
    assert len(rows) == 1
    row = rows[0]
    assert row["txn_id"] == "TXN-1"
    assert row["decision"] == "APPROVED"
    assert row["auth_code"] == "AUTH-1"
    assert row["amount"] == 1648.0
    assert row["currency"] == "INR"
    assert json.loads(row["envelope"])["txn_id"] == "TXN-1"


def test_rejection_reason_persisted(tmp_db):
    tmp_db.record_transaction("TXN-2", "REJECTED", {"txn_id": "TXN-2"},
                              reason="replay")
    row = tmp_db.list_transactions()[0]
    assert row["decision"] == "REJECTED"
    assert row["auth_code"] is None
    assert row["reason"] == "replay"


def test_attacks_recorded(tmp_db):
    tmp_db.record_attack("Bit-flip", True, "JSON decode FAILED", "TXN-1")
    tmp_db.record_attack("Replay", False, None, "TXN-1")
    rows = tmp_db.list_attacks()  # newest first
    assert [r["blocked"] for r in rows] == [0, 1]
    assert rows[1]["reason"] == "JSON decode FAILED"
    assert rows[1]["txn_id"] == "TXN-1"


def test_stats_and_clear(tmp_db):
    tmp_db.record_transaction("TXN-1", "APPROVED", {"txn_id": "TXN-1"},
                              auth={"auth_code": "A"})
    tmp_db.record_transaction("TXN-1", "REJECTED", {"txn_id": "TXN-1"},
                              reason="replay")
    tmp_db.record_attack("Bit-flip", True, "JSON decode FAILED", "TXN-1")
    s = tmp_db.stats()
    assert s["transactions"] == 2
    assert s["approved"] == 1
    assert s["rejected"] == 1
    assert s["attacks"] == 1
    assert s["blocked"] == 1
    tmp_db.clear_all()
    assert tmp_db.stats()["transactions"] == 0
    assert tmp_db.stats()["attacks"] == 0
