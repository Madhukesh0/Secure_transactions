"""Primitive and protocol tests for securepay.crypto."""

import base64

import pytest

from securepay.crypto import (
    aes_decrypt,
    aes_encrypt,
    build_transaction_payload,
    customer_sends_transaction,
    decrypt_session_key,
    encrypt_session_key,
    gateway_processes_envelope,
    generate_rsa_keypair,
    sign,
    verify,
)


def test_aes_roundtrip():
    key = bytes(range(32))
    iv, ct = aes_encrypt(key, b"hello securepay")
    assert aes_decrypt(key, iv, ct) == b"hello securepay"


def test_aes_rejects_tampered_ciphertext():
    key = bytes(range(32))
    iv, ct = aes_encrypt(key, b"hello securepay")
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01  # corrupts the padding block
    with pytest.raises(ValueError):
        aes_decrypt(key, iv, bytes(tampered))


def test_oaep_roundtrip(keypair):
    priv, pub = keypair
    aes_key = bytes(range(32))
    wrapped = encrypt_session_key(pub, aes_key)
    assert decrypt_session_key(priv, wrapped) == aes_key


def test_oaep_rejects_wrong_private_key(keypair):
    _, pub = keypair
    foreign = generate_rsa_keypair(1024)
    wrapped = encrypt_session_key(pub, bytes(range(32)))
    with pytest.raises(ValueError):
        decrypt_session_key(foreign, wrapped)


def test_pss_signature_roundtrip(keypair):
    priv, pub = keypair
    sig = sign(priv, b'{"order": 1}')
    assert verify(pub, b'{"order": 1}', sig)
    assert not verify(pub, b'{"order": 2}', sig)
    assert not verify(pub, b'{"order": 1}', sig[:-1] + bytes([sig[-1] ^ 1]))


CUSTOMER = {"id": "CUST-1", "name": "Test User", "email": "test@example.com"}
CARD = {"number": "4532015112830366", "holder": "TEST USER",
        "expiry": "12/27", "cvv": "328"}
CART = [{"sku": "X1", "title": "Widget", "qty": 2, "price": 5.0}]


def _envelope(keypair):
    priv, pub = keypair
    payload = build_transaction_payload(CUSTOMER, CART, CARD, 10.0)
    return payload, customer_sends_transaction(payload, priv, pub)


def test_gateway_approves_honest_envelope(keypair):
    priv, pub = keypair
    payload, envelope = _envelope(keypair)
    assert envelope["txn_id"] == payload["txn_id"]
    auth, log = gateway_processes_envelope(envelope, priv, pub)
    assert auth is not None
    assert auth["status"] == "APPROVED"
    assert auth["amount"]["value"] == 10.0


def test_gateway_rejects_bitflip(keypair):
    priv, pub = keypair
    _, envelope = _envelope(keypair)
    raw = bytearray(base64.b64decode(envelope["ciphertext"]))
    raw[-25] ^= 0x01
    envelope["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    auth, log = gateway_processes_envelope(envelope, priv, pub)
    assert auth is None
    assert any("FAILED" in msg for _, msg in log)
