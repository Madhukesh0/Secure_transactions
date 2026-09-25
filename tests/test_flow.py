"""Transaction-flow and attack-simulation tests for securepay.flow."""

from securepay import flow
from securepay.crypto import gateway_processes_envelope
from securepay.flow import (
    attack_bitflip,
    attack_forge_hmac,
    attack_forge_signature,
    attack_wrong_key,
)


def test_normalize_items_drops_blank_rows():
    raw = [
        {"sku": "", "title": "", "qty": "", "price": ""},
        {"sku": "S1", "title": "Item", "qty": "2", "price": "9.5"},
    ]
    items = flow.normalize_items(raw)
    assert len(items) == 1
    assert items[0] == {"sku": "S1", "title": "Item", "qty": 2, "price": 9.5}


def test_cart_total():
    assert flow.cart_total([{"qty": 2, "price": 9.5}, {"qty": 1, "price": 100}]) == 119.0


def test_mask_payload_hides_secrets():
    payload = {"payment": {"card_number": "4532015112830366", "cvv": "328"}}
    masked = flow.mask_payload(payload)
    assert masked["payment"]["card_number"].endswith("0366")
    assert "*" in masked["payment"]["card_number"]
    assert masked["payment"]["cvv"] == "***"
    assert payload["payment"]["cvv"] == "328"  # original untouched


CUSTOMER = {"id": "CUST-1", "name": "Test User", "email": "test@example.com"}
CARD = {"number": "4532015112830366", "holder": "TEST USER",
        "expiry": "12/27", "cvv": "328"}


def _envelope(keypairs):
    cust, gw = keypairs
    payload, envelope = flow.build_envelope(
        CUSTOMER, CARD, flow.DEFAULT_ITEMS, cust, gw.publickey())
    return payload, envelope


def test_build_envelope_and_gateway_approval(keypairs):
    cust, gw = keypairs
    payload, envelope = _envelope(keypairs)
    seen = set()
    auth, log = flow.run_gateway(envelope, gw, cust.publickey(), seen)
    assert auth is not None
    assert envelope["txn_id"] == payload["txn_id"]
    assert envelope["txn_id"] in seen
    assert flow.cart_total(flow.DEFAULT_ITEMS) == 1648.0


def test_replay_rejected(keypairs):
    cust, gw = keypairs
    _, envelope = _envelope(keypairs)
    seen = set()
    auth1, _ = flow.run_gateway(envelope, gw, cust.publickey(), seen)
    auth2, log2 = flow.run_gateway(envelope, gw, cust.publickey(), seen)
    assert auth1 is not None
    assert auth2 is None
    assert any("replay" in msg.lower() for _, msg in log2)


def test_attack_bitflip_blocked(keypairs):
    cust, gw = keypairs
    _, envelope = _envelope(keypairs)
    auth, _ = gateway_processes_envelope(attack_bitflip(envelope), gw, cust.publickey())
    assert auth is None


def test_attack_forge_hmac_blocked(keypairs):
    cust, gw = keypairs
    _, envelope = _envelope(keypairs)
    auth, _ = gateway_processes_envelope(attack_forge_hmac(envelope), gw, cust.publickey())
    assert auth is None


def test_attack_forge_signature_blocked(keypairs):
    cust, gw = keypairs
    _, envelope = _envelope(keypairs)
    auth, _ = gateway_processes_envelope(attack_forge_signature(envelope), gw, cust.publickey())
    assert auth is None


def test_attack_wrong_key_blocked(keypairs):
    _, envelope = _envelope(keypairs)
    recovered, msg = attack_wrong_key(envelope)
    assert recovered is False
    assert "cannot unwrap" in msg.lower()
