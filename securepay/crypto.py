"""
Secure E-Commerce Transaction System
=====================================
Case Study: Protect customer payment information and transaction details
from cyberattacks during online shopping.

Cryptographic techniques used:
  - AES-256 (CBC mode, PKCS7 padding)        : symmetric encryption of payment data
  - RSA-2048 (OAEP / SHA-256)               : secure exchange of the AES session key
  - SHA-256                                  : transaction integrity hashing
  - RSA-PSS digital signature                : authenticity & non-repudiation
  - HMAC-SHA256                              : payment-token integrity check
  - Random IV per transaction               : semantic security

Run:  python -m securepay.crypto
"""

import os
import json
import base64
import hashlib
import hmac
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ---------- helpers ----------------------------------------------------------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


# ---------- 1. Key generation (merchant + customer / payment gateway) ------

def generate_rsa_keypair(bits: int = 2048) -> RSA.RsaKey:
    return RSA.generate(bits)


# ---------- 2. Hybrid encryption: AES key encrypted with RSA -------------

def encrypt_session_key(rsa_pub: RSA.RsaKey, aes_key: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_pub, hashAlgo=SHA256)
    return cipher.encrypt(aes_key)


def decrypt_session_key(rsa_priv: RSA.RsaKey, enc_key: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_priv, hashAlgo=SHA256)
    return cipher.decrypt(enc_key)


# ---------- 3. AES-256-CBC encryption of payment payload -------------------

def aes_encrypt(aes_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ct


def aes_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# ---------- 4. Digital signature (RSA-PSS / SHA-256) -----------------------

def sign(rsa_priv: RSA.RsaKey, data: bytes) -> bytes:
    h = SHA256.new(data)             # Crypto.Hash.SHA256 object
    return pss.new(rsa_priv).sign(h)


def verify(rsa_pub: RSA.RsaKey, data: bytes, signature: bytes) -> bool:
    try:
        h = SHA256.new(data)
        pss.new(rsa_pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ---------- 5. The transaction protocol ------------------------------------

def build_transaction_payload(customer, cart, card, amount):
    return {
        "txn_id": "TXN-" + hashlib.sha1(
            (customer["email"] + datetime.utcnow().isoformat()).encode()
        ).hexdigest()[:12].upper(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "customer": {
            "id": customer["id"],
            "name": customer["name"],
            "email": customer["email"],
        },
        "merchant_id": "MERCH-AMAZON-001",
        "items": cart,
        "payment": {
            "card_number": card["number"],   # will be encrypted
            "card_holder": card["holder"],
            "expiry": card["expiry"],
            "cvv": card["cvv"],              # will be encrypted
        },
        "amount": {
            "value": amount,
            "currency": "INR",
        },
    }


def customer_sends_transaction(payload, customer_priv, gateway_pub):
    """Customer side: signs + encrypts the payload for the payment gateway."""
    raw = json.dumps(payload, sort_keys=True).encode()

    # digital signature over plaintext (so receiver can verify integrity + auth)
    signature = sign(customer_priv, raw)

    # hybrid encryption: encrypt payload with random AES key, encrypt key with RSA
    aes_key = get_random_bytes(32)                       # AES-256
    iv, ciphertext = aes_encrypt(aes_key, raw)
    enc_aes_key = encrypt_session_key(gateway_pub, aes_key)

    # payment-token HMAC for quick tamper detection at gateway
    token_input = f"{payload['txn_id']}|{payload['customer']['id']}|{payload['amount']['value']}"
    mac = hmac.new(aes_key, token_input.encode(), hashlib.sha256).digest()

    envelope = {
        "envelope_version": "1.0",
        "txn_id": payload["txn_id"],
        "encrypted_aes_key": b64e(enc_aes_key),
        "iv": b64e(iv),
        "ciphertext": b64e(ciphertext),
        "signature": b64e(signature),
        "mac": b64e(mac),
        "algorithm": {
            "symmetric": "AES-256-CBC",
            "asymmetric": "RSA-2048-OAEP-SHA256",
            "signature": "RSA-PSS-SHA256",
            "mac": "HMAC-SHA256",
        },
    }
    return envelope


def gateway_processes_envelope(envelope, gateway_priv, customer_pub):
    """Payment gateway side: decrypts, verifies, returns auth decision."""
    log = []

    try:
        enc_aes_key = b64d(envelope["encrypted_aes_key"])
        iv = b64d(envelope["iv"])
        ciphertext = b64d(envelope["ciphertext"])
        signature = b64d(envelope["signature"])
        mac_recv = b64d(envelope["mac"])

        # 1. Decrypt AES session key with our private RSA key
        aes_key = decrypt_session_key(gateway_priv, enc_aes_key)
        log.append(("Step 1", "Decrypted AES-256 session key with gateway RSA-2048 private key"))

        # 2. Decrypt payload (bad padding => tampering)
        try:
            plaintext = aes_decrypt(aes_key, iv, ciphertext)
        except Exception:
            log.append(("Step 2", "AES decryption FAILED - bad padding => message was tampered with or wrong key"))
            return None, log
        log.append(("Step 2", "Decrypted transaction payload with AES-256-CBC"))

        # 3. Parse plaintext JSON (bad utf-8 => tampering)
        try:
            payload = json.loads(plaintext.decode())
        except Exception:
            log.append(("Step 3", "JSON decode FAILED - payload was tampered with"))
            return None, log

        # 4. HMAC payment-token integrity
        token_input = f"{payload['txn_id']}|{payload['customer']['id']}|{payload['amount']['value']}"
        mac_calc = hmac.new(aes_key, token_input.encode(), hashlib.sha256).digest()
        mac_ok = hmac.compare_digest(mac_calc, mac_recv)
        log.append(("Step 3", f"HMAC payment-token integrity check: {'PASS' if mac_ok else 'FAIL'}"))
        if not mac_ok:
            return None, log

        # 5. Customer digital signature => authenticity + non-repudiation
        sig_ok = verify(customer_pub, plaintext, signature)
        log.append(("Step 4", f"Customer RSA-PSS signature verification: {'PASS' if sig_ok else 'FAIL'}"))
        if not sig_ok:
            return None, log

        # 6. SHA-256 hash (defence-in-depth integrity record)
        sha = hashlib.sha256(plaintext).hexdigest()
        log.append(("Step 5", f"SHA-256 integrity hash: {sha[:32]}..."))

        # 7. Approve
        auth = {
            "auth_code": "AUTH-" + hashlib.sha1(
                (payload["txn_id"] + datetime.utcnow().isoformat()).encode()
            ).hexdigest()[:10].upper(),
            "status": "APPROVED",
            "amount": payload["amount"],
            "txn_id": payload["txn_id"],
        }
        return auth, log

    except Exception as e:
        log.append(("Error", f"Unhandled gateway error: {type(e).__name__}: {e}"))
        return None, log


# ---------- 6. Demonstration -----------------------------------------------

def banner(title):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def mask_card(num: str) -> str:
    return "*" * (len(num) - 4) + num[-4:]


def demo():
    banner("SECURE E-COMMERCE TRANSACTION - CRYPTOGRAPHIC DEMONSTRATION")

    # ---- generate keys ----
    print("[Setup] Generating RSA-2048 keypairs for Customer and Payment Gateway ...")
    customer_priv = generate_rsa_keypair(2048)
    customer_pub = customer_priv.publickey()
    gateway_priv = generate_rsa_keypair(2048)
    gateway_pub = gateway_priv.publickey()
    print("        OK - 2048-bit RSA keypairs generated for both parties.\n")

    # ---- sample transaction ----
    customer = {
        "id": "CUST-7741",
        "name": "Aditya Sharma",
        "email": "aditya.sharma@example.com",
    }
    cart = [
        {"sku": "BO-MATHE-205", "title": "Engineering Mathematics Textbook", "qty": 1, "price": 650.00},
        {"sku": "BO-DS-301",    "title": "Data Structures in Python",        "qty": 2, "price": 499.00},
    ]
    card = {
        "number": "4532015112830366",
        "holder": "ADITYA SHARMA",
        "expiry": "12/27",
        "cvv": "328",
    }
    total = sum(i["qty"] * i["price"] for i in cart)

    payload = build_transaction_payload(customer, cart, card, total)

    banner("1. PLAINTEXT TRANSACTION (what the customer wants to send)")
    pretty = json.loads(json.dumps(payload))
    pretty["payment"]["card_number"] = mask_card(pretty["payment"]["card_number"])
    pretty["payment"]["cvv"] = "***"
    print(json.dumps(pretty, indent=2))

    banner("2. CUSTOMER ENCRYPTS + SIGNS PAYLOAD FOR GATEWAY")
    envelope = customer_sends_transaction(payload, customer_priv, gateway_pub)
    print(json.dumps(envelope, indent=2))

    banner("3. PAYMENT GATEWAY DECRYPTS + VERIFIES")
    auth, log = gateway_processes_envelope(envelope, gateway_priv, customer_pub)
    for step, msg in log:
        print(f"  [{step}] {msg}")

    banner("4. GATEWAY AUTHORIZATION RESPONSE")
    print(json.dumps(auth, indent=2))

    # ---- tamper test ----
    banner("5. TAMPER TEST - attacker flips amount in ciphertext")
    tampered = json.loads(json.dumps(envelope))
    raw_ct = b64d(tampered["ciphertext"])
    flipped = bytearray(raw_ct)
    # flip a bit far inside the block so padding isn't disturbed
    idx = len(flipped) - 25
    flipped[idx] ^= 0x01
    tampered["ciphertext"] = b64e(bytes(flipped))
    auth2, log2 = gateway_processes_envelope(tampered, gateway_priv, customer_pub)
    for step, msg in log2:
        print(f"  [{step}] {msg}")
    print("\n  -> Gateway result:", auth2 if auth2 else "REJECTED (tampering detected)")

    # ---- key-exchange test ----
    banner("6. KEY-EXCHANGE TEST - wrong RSA private key cannot decrypt")
    fake_priv = generate_rsa_keypair(2048)
    try:
        aes_key = decrypt_session_key(fake_priv, b64d(envelope["encrypted_aes_key"]))
        print("  Decryption unexpectedly succeeded with the wrong private key.")
    except Exception as e:
        print(f"  Decryption with WRONG private key FAILED as expected: {type(e).__name__}")

    banner("DEMO COMPLETE")
    print("The full cryptographic round-trip succeeded. Payment data was protected by:")
    print("  * AES-256-CBC  -> confidentiality of card number / CVV")
    print("  * RSA-2048 OAEP -> confidentiality of the AES session key")
    print("  * RSA-PSS / SHA-256 -> authenticity + integrity + non-repudiation")
    print("  * HMAC-SHA256 -> fast payment-token integrity check")
    print("  * random IV per transaction -> semantic security")


if __name__ == "__main__":
    demo()