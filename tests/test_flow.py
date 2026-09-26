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


# --- card validation & simulated issuing bank ----------------------------------

def test_luhn_valid_and_invalid():
    assert flow.luhn_ok("4532015112830366")      # default demo Visa
    assert flow.luhn_ok("4111111111111111")      # classic Visa test PAN
    assert flow.luhn_ok("4000000000000002")      # bank-decline demo card
    assert flow.luhn_ok("4532 0151 1283 0366")   # spaces are ignored
    assert not flow.luhn_ok("4532015112830367")  # one digit off -> checksum fails
    assert not flow.luhn_ok("12345")             # too short anyway


def test_card_network_detection():
    assert flow.card_network("4532015112830366") == "Visa"
    assert flow.card_network("5555555555554444") == "Mastercard"
    assert flow.card_network("371449635398431") == "Amex"
    assert flow.card_network("6069551234567890") == "RuPay"
    assert flow.card_network("9999") == "Unknown network"


def test_validate_card_field_rules():
    ok, errors = flow.validate_card({"number": "4532015112830366", "holder": "R",
                                     "expiry": "12/27", "cvv": "328"})
    assert ok and errors == []
    bad = {"number": "4532015112830367", "holder": " ", "expiry": "13/27", "cvv": "12"}
    ok, errors = flow.validate_card(bad)
    assert not ok
    assert any("Luhn" in e for e in errors)
    assert any("holder" in e.lower() for e in errors)
    assert any("MM/YY" in e for e in errors)
    assert any("CVV" in e for e in errors)
    _, errors = flow.validate_card({"number": "4532015112830366", "holder": "R",
                                    "expiry": "01/20", "cvv": "328"})
    assert any("expired" in e for e in errors)


def test_bank_check_decline_list():
    ok, msg = flow.bank_check({"number": "4000000000000002", "holder": "Riya",
                               "expiry": "12/27", "cvv": "328"})
    assert not ok and "insufficient funds" in msg
    ok, msg = flow.bank_check({"number": "4532 0151 1283 0366", "holder": "Riya",
                                "expiry": "12/27", "cvv": "328"})
    assert ok and "Authorized" in msg


# --- UPI / QR payments ----------------------------------------------------------

def test_upi_string_and_signature_roundtrip(keypairs):
    _, gw = keypairs
    s = flow.build_upi_string("TXN-TEST123", 1348.0)
    assert s.startswith("upi://pay?pa=securepay%40campus")
    assert "am=1348.00" in s and "tr=TXN-TEST123" in s and "cu=INR" in s
    sig = flow.sign_upi_request(s, gw)
    assert flow.verify_upi_request(s, sig, gw.publickey())


def test_attack_qr_swap_blocked(keypairs):
    _, gw = keypairs
    s = flow.build_upi_string("TXN-TEST123", 1348.0)
    sig = flow.sign_upi_request(s, gw)
    ok, tampered, msg = flow.attack_qr_swap(s, sig, gw.publickey())
    assert not ok                                   # tampered QR must fail
    assert "fraudster@upi" in tampered              # attacker's VPA injected
    assert "13480.00" in tampered                   # amount multiplied by 10
    assert "FAILED" in msg
    assert flow.verify_upi_request(s, sig, gw.publickey())  # genuine still passes


def test_upi_payload_has_no_card_block():
    from securepay.crypto import build_transaction_payload
    card_block = {"method": "UPI", "upi_vpa": flow.MERCHANT_UPI["pa"],
                  "txn_ref": "TXN-1", "status": "PAID via UPI app (simulated)"}
    payload = build_transaction_payload(CUSTOMER, flow.DEFAULT_ITEMS,
                                        card_block, 1648.0, txn_id="TXN-1")
    assert payload["payment"]["method"] == "UPI"
    assert payload["payment"]["txn_ref"] == "TXN-1"
    assert "card_number" not in payload["payment"]
    assert payload["txn_id"] == "TXN-1"             # explicit txn_id respected
