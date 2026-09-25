"""
Business flow: transaction building, gateway protocol, attack simulations.

Pure Python (no Streamlit calls) - headless-testable. Wraps the primitives
in securepay.crypto into the two sides of the protocol plus five attacks.
"""

import copy
import json

from securepay.crypto import (
    b64d,
    build_transaction_payload,
    customer_sends_transaction,
    decrypt_session_key,
    gateway_processes_envelope,
    generate_rsa_keypair,
    mask_card,
)
from securepay import db

DEFAULT_ITEMS = [
    {"sku": "BO-MATHE-205", "title": "Engineering Mathematics Textbook", "qty": 1, "price": 650.00},
    {"sku": "BO-DS-301", "title": "Data Structures in Python", "qty": 2, "price": 499.00},
]

ENVELOPE_B64_FIELDS = ("encrypted_aes_key", "iv", "ciphertext", "signature", "mac")

ATTACKS = [
    "Bit-flip in the ciphertext (tamper with the amount/items)",
    "Forge the HMAC payment token",
    "Forge the customer's RSA-PSS signature",
    "Intercept on the wire: try a wrong RSA private key",
    "Replay a previously delivered envelope",
]


# --- keys / cart ------------------------------------------------------------

def generate_keys():
    """Fresh RSA-2048 keypairs for Customer and Payment Gateway."""
    return generate_rsa_keypair(2048), generate_rsa_keypair(2048)


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

def build_envelope(customer, card, items, customer_priv, gateway_pub):
    """Customer side: payload -> sign + hybrid-encrypt -> envelope."""
    payload = build_transaction_payload(customer, items, card, cart_total(items))
    envelope = customer_sends_transaction(payload, customer_priv, gateway_pub)
    return payload, envelope


def mask_payload(payload):
    """Masked copy of the plaintext for safe display."""
    p = json.loads(json.dumps(payload))
    p["payment"]["card_number"] = mask_card(p["payment"]["card_number"])
    p["payment"]["cvv"] = "***"
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
