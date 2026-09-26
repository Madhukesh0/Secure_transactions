"""
Business flow: transaction building, gateway protocol, attack simulations.

Pure Python (no Streamlit calls) - headless-testable. Wraps the primitives
in securepay.crypto into the two sides of the protocol plus five attacks.
"""

import copy
import json
import re
from datetime import datetime

from securepay.crypto import (
    b64d,
    b64e,
    build_transaction_payload,
    customer_sends_transaction,
    decrypt_session_key,
    gateway_processes_envelope,
    generate_rsa_keypair,
    mask_card,
    new_txn_id,
    sign,
    verify,
)
from securepay import db

DEFAULT_ITEMS = [
    {"sku": "BO-MATHE-205", "title": "Engineering Mathematics Textbook", "qty": 1, "price": 650.00},
    {"sku": "BO-DS-301", "title": "Data Structures in Python", "qty": 2, "price": 499.00},
]

# Campus bookstore shelf shown on the Checkout page (adds sku -> cart rows).
CATALOG = [
    {"sku": "BO-MATHE-205", "title": "Engineering Mathematics Textbook",
     "price": 650.00, "icon": "📐"},
    {"sku": "BO-DS-301", "title": "Data Structures in Python",
     "price": 499.00, "icon": "🐍"},
    {"sku": "BO-CRYPTO-703", "title": "Cryptography & Network Security (Stallings 8e)",
     "price": 799.00, "icon": "🔐"},
    {"sku": "ST-CNS-25", "title": "CNS Lab Notebook & Pen Set",
     "price": 149.00, "icon": "📓"},
    {"sku": "MG-TSHIRT-L", "title": "CSE Department T-shirt (L)",
     "price": 349.00, "icon": "👕"},
]

ENVELOPE_B64_FIELDS = ("encrypted_aes_key", "iv", "ciphertext", "signature", "mac")

ATTACKS = [
    "Bit-flip in the ciphertext (tamper with the amount/items)",
    "Forge the HMAC payment token",
    "Forge the customer's RSA-PSS signature",
    "Intercept on the wire: try a wrong RSA private key",
    "Replay a previously delivered envelope",
    "Swap the UPI QR (amount ×10, attacker VPA)",
]


# --- keys / cart ------------------------------------------------------------

def generate_keys():
    """Fresh RSA-2048 keypairs for Customer and Payment Gateway."""
    return generate_rsa_keypair(2048), generate_rsa_keypair(2048)


# --- card validation & simulated issuing bank ---------------------------------
# A real checkout asks the issuing bank for authorization before accepting a
# payment. That network is out of scope here, so the demo reproduces the same
# gate locally: field rules, the Luhn checksum, and a decline-list of test
# cards. The Gateway page afterwards still verifies the cryptography.

BANK_TEST_CARDS = {
    "4000000000000002": "Declined by issuing bank: insufficient funds (simulated)",
    "4000000000009995": "Declined by issuing bank: card reported lost/stolen (simulated)",
}


def luhn_ok(number) -> bool:
    """Standard Luhn checksum — every real card number passes it."""
    digits = re.sub(r"\D", "", str(number))
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_network(number) -> str:
    """BIN-prefix detection: Visa / Mastercard / Amex / RuPay."""
    digits = re.sub(r"\D", "", str(number))
    if re.match(r"^4", digits):
        return "Visa"
    if re.match(r"^(5[1-5]|2[2-7])", digits):
        return "Mastercard"
    if re.match(r"^3[47]", digits):
        return "Amex"
    if re.match(r"^(60|65|81|82|508)", digits):
        return "RuPay"
    return "Unknown network"


def validate_card(card: dict):
    """Same field rules a real checkout enforces. Returns (ok, [errors])."""
    errors = []
    if not str(card.get("holder", "")).strip():
        errors.append("Card holder name is required.")
    digits = re.sub(r"\D", "", str(card.get("number", "")))
    if not 13 <= len(digits) <= 19:
        errors.append("Card number must be 13–19 digits.")
    elif not luhn_ok(digits):
        errors.append("Card number fails the Luhn checksum — not a valid card.")
    m = re.fullmatch(r"(0[1-9]|1[0-2])/(\d{2})", str(card.get("expiry", "")).strip())
    if not m:
        errors.append("Expiry must be in MM/YY format.")
    else:
        mm, yy = int(m.group(1)), 2000 + int(m.group(2))
        now = datetime.now()
        if (yy, mm) < (now.year, now.month):
            errors.append("This card has expired.")
    if not re.fullmatch(r"\d{3,4}", str(card.get("cvv", "")).strip()):
        errors.append("CVV must be 3–4 digits.")
    return (not errors), errors


def bank_check(card: dict):
    """Simulated issuing-bank authorization. Returns (authorized, message)."""
    ok, errors = validate_card(card)
    if not ok:
        return False, errors[0]
    digits = re.sub(r"\D", "", str(card.get("number", "")))
    if digits in BANK_TEST_CARDS:
        return False, BANK_TEST_CARDS[digits]
    return True, "Authorized by issuing bank (simulated) — funds held for capture"


# --- UPI / QR payments ----------------------------------------------------------
# A real UPI QR encodes a deep-link (upi://pay?pa=<payee>&am=<amount>…). The
# fraud vector is QR swapping: an attacker re-prints the QR with their own VPA
# or a higher amount, and the customer cannot see the difference by eye. The
# demo defends it the same way a production system would — the gateway signs
# the payment request (RSA-PSS); any scanner can verify it with the public key,
# and a tampered string fails instantly.

MERCHANT_UPI = {"pa": "securepay@campus", "pn": "SecurePay Campus Store"}
UPI_ATTACKER_VPA = "fraudster@upi"


def build_upi_string(txn_id, amount, note="SecurePay order"):
    """Standard UPI deep-link — scannable by any UPI app."""
    from urllib.parse import urlencode

    params = {
        "pa": MERCHANT_UPI["pa"],
        "pn": MERCHANT_UPI["pn"],
        "am": f"{float(amount):.2f}",
        "cu": "INR",
        "tn": note,
        "tr": txn_id,
    }
    return "upi://pay?" + urlencode(params)


def sign_upi_request(upi_string, gateway_priv):
    """Gateway's RSA-PSS signature over the payment request (Base64)."""
    return b64e(sign(gateway_priv, upi_string.encode()))


def verify_upi_request(upi_string, signature_b64, gateway_pub):
    """Check a payment request against the gateway's signature."""
    try:
        return verify(gateway_pub, upi_string.encode(), b64d(signature_b64))
    except (ValueError, TypeError):
        return False


def tamper_upi_string(upi_string):
    """What a QR-swap attacker does: 10x the amount, attacker's own VPA."""
    tampered = re.sub(
        r"am=([\d.]+)",
        lambda m: "am=" + format(float(m.group(1)) * 10, ".2f"),
        upi_string,
    )
    return re.sub(r"pa=[^&]+", "pa=" + UPI_ATTACKER_VPA, tampered)


def attack_qr_swap(upi_string, signature_b64, gateway_pub):
    """Attack #6: re-print the QR from a tampered string. The attacker cannot
    produce the gateway's signature, so verification fails.
    Returns (ok, tampered_string, message)."""
    tampered = tamper_upi_string(upi_string)
    ok = verify_upi_request(tampered, signature_b64, gateway_pub)
    if ok:
        msg = "Forged QR accepted — the attacker would have received the money!"
    else:
        msg = ("Signature verification FAILED — this QR was not generated by "
               "the gateway. Do not pay.")
    return ok, tampered, msg


def build_upi_order(customer, items, total, customer_priv, gateway_pub, gateway_priv):
    """UPI path: txn-id → signed payment request → the same encrypted envelope
    as the card path (the payload's payment block carries the UPI reference)."""
    txn_id = new_txn_id(customer["email"])
    upi_string = build_upi_string(txn_id, total)
    signature = sign_upi_request(upi_string, gateway_priv)
    card_block = {
        "method": "UPI",
        "upi_vpa": MERCHANT_UPI["pa"],
        "txn_ref": txn_id,
        "status": "PAID via UPI app (simulated)",
    }
    payload, envelope = build_envelope(customer, card_block, items,
                                       customer_priv, gateway_pub, txn_id=txn_id)
    request = {"txn_id": txn_id, "string": upi_string,
               "signature": signature, "amount": total}
    return request, payload, envelope


def normalize_items(raw):
    """Editor output -> clean list[dict]; drops blank rows."""
    if hasattr(raw, "to_dict"):  # pandas DataFrame
        raw = raw.to_dict("records")
    items = []
    for row in raw:
        title = str(row.get("title") or "").strip()
        sku = str(row.get("sku") or "").strip()
        if not (title or sku):
            continue
        try:
            qty = max(int(float(row.get("qty") or 1)), 1)
        except (TypeError, ValueError):
            qty = 1
        try:
            price = float(row.get("price") or 0.0)
        except (TypeError, ValueError):
            price = 0.0
        items.append({"sku": sku, "title": title, "qty": qty, "price": price})
    return items


def cart_total(items):
    return sum(i["qty"] * i["price"] for i in items)


# --- customer side ----------------------------------------------------------

def build_envelope(customer, card, items, customer_priv, gateway_pub, txn_id=None):
    """Customer side: payload -> sign + hybrid-encrypt -> envelope."""
    payload = build_transaction_payload(customer, items, card, cart_total(items),
                                        txn_id=txn_id)
    envelope = customer_sends_transaction(payload, customer_priv, gateway_pub)
    return payload, envelope


def mask_payload(payload):
    """Masked copy of the plaintext for safe display (card and UPI blocks)."""
    p = json.loads(json.dumps(payload))
    pay = p.get("payment", {})
    if "card_number" in pay:
        pay["card_number"] = mask_card(pay["card_number"])
    if "cvv" in pay:
        pay["cvv"] = "***"
    return p


# --- gateway side -----------------------------------------------------------

def run_gateway(envelope, gateway_priv, customer_pub, seen_ids):
    """Gateway flow + replay protection (already-seen TXN-IDs are refused)."""
    txn_id = envelope.get("txn_id")
    if txn_id in seen_ids:
        return None, [(
            "Replay check",
            f"TXN-ID {txn_id} was already processed -> REJECTED (replay)",
        )]
    auth, log = gateway_processes_envelope(envelope, gateway_priv, customer_pub)
    if auth:
        seen_ids.add(txn_id)
    return auth, log


def process_and_record(envelope, gateway_priv, customer_pub, seen_ids):
    """run_gateway + persist the decision to SQLite (audit trail)."""
    from securepay.ui import first_failure  # deferred: ui imports streamlit
    auth, log = run_gateway(envelope, gateway_priv, customer_pub, seen_ids)
    reason = None
    if auth is None:
        reason = first_failure(log) or next(
            (m for _, m in log if "reject" in m.lower()), "rejected"
        )
    db.record_transaction(
        envelope.get("txn_id"),
        "APPROVED" if auth else "REJECTED",
        envelope, auth=auth, reason=reason,
    )
    return auth, log


# --- attacks ----------------------------------------------------------------

def attack_bitflip(envelope):
    import base64
    t = copy.deepcopy(envelope)
    raw = bytearray(b64d(t["ciphertext"]))
    raw[len(raw) - 25] ^= 0x01          # flip a bit away from the padding
    t["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    return t


def attack_forge_hmac(envelope):
    import base64
    t = copy.deepcopy(envelope)
    raw = bytearray(b64d(t["mac"]))
    raw[0] ^= 0xFF
    t["mac"] = base64.b64encode(bytes(raw)).decode()
    return t


def attack_forge_signature(envelope):
    import base64
    t = copy.deepcopy(envelope)
    raw = bytearray(b64d(t["signature"]))
    raw[-1] ^= 0x01
    t["signature"] = base64.b64encode(bytes(raw)).decode()
    return t


def attack_wrong_key(envelope):
    """Attacker tries to unwrap the session key with a foreign keypair."""
    foreign = generate_rsa_keypair(2048)
    try:
        decrypt_session_key(foreign, b64d(envelope["encrypted_aes_key"]))
        return True, "OAEP unwrap unexpectedly SUCCEEDED with the wrong private key"
    except Exception as e:
        return False, (
            "Foreign private key CANNOT unwrap the session key "
            f"({type(e).__name__}) - key exchange holds"
        )
