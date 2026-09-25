"""Report page: threat model, primitives, deliverables, references."""

import streamlit as st

from securepay import ui

ui.page_header(
    "Documentation",
    "Case Study Report",
    "The threat model, the controls, and where to see each one live. "
    "Full write-up: docs/report.md / docs/secure_ecommerce_report.docx · "
    "slides: docs/secure_ecommerce_deck.pptx.",
)

# --- 01: problem statement --------------------------------------------------
ui.section("01", "Problem statement")
st.markdown(
    '<div class="sp-prose"><p><em>Protect customer payment information and '
    "transaction details from cyberattacks during online shopping.</em> "
    "Decomposed into five security goals, each mapped to a cryptographic "
    "control below.</p></div>",
    unsafe_allow_html=True,
)

# --- 02: threat -> control --------------------------------------------------
ui.section("02", "Threat → control → where to see it")
st.markdown(
    """| Goal | Threat | Control | Where to see it |
|---|---|---|---|
| **P-1** Confidentiality | eavesdropping on card / CVV | AES-256-CBC + RSA-OAEP key wrap | Checkout: only ciphertext on the wire |
| **P-2** Integrity | tampering with amount / items | HMAC-SHA256 + RSA-PSS + CBC padding | Attack Lab: bit-flip & forged HMAC |
| **P-3** Authenticity | impersonating the customer | RSA-PSS signature verification | Attack Lab: forged signature |
| **P-4** Non-repudiation | customer denying the order | RSA-PSS under the customer's key | Gateway: signature verification step |
| **P-5** Replay protection | re-submitting an old envelope | TXN-ID remembered at the gateway | Attack Lab: replay · Database: REJECTED row |"""
)

# --- 03: primitives ---------------------------------------------------------
ui.section("03", "Cryptographic primitives")
st.markdown(
    """| Primitive | Purpose |
|---|---|
| **AES-256-CBC** + PKCS#7 padding | symmetric encryption of the full transaction payload |
| Random 128-bit IV per transaction | semantic security — no IV reuse |
| **RSA-2048 OAEP / SHA-256** | asymmetric wrapping of the AES session key |
| **RSA-PSS / SHA-256** signature | customer signs the plaintext JSON |
| **SHA-256** | tamper-evident hash of the payload |
| **HMAC-SHA256** | fast payment-token integrity check at the gateway |"""
)

# --- 04: deliverables -------------------------------------------------------
ui.section("04", "Deliverables")
st.markdown(
    """| File | Purpose |
|---|---|
| `securepay/crypto.py` | core crypto library + CLI demo (`python -m securepay.crypto`) |
| `app.py` | router / entry point (st.navigation) |
| `app_pages/*.py` | one script per section |
| `securepay/ui.py` / `securepay/flow.py` | design system / protocol logic |
| `securepay/db.py` + `securepay.db` | SQLite audit-trail layer + database |
| `tests/` | pytest suite for crypto, flow and persistence |
| `docs/report.md` / `docs/secure_ecommerce_report.docx` | written report |
| `docs/secure_ecommerce_deck.pptx` / `docs/deck_spec.json` | seminar deck + JSON source |
| `docs/demo_output.txt` | captured stdout of a full CLI run |"""
)

# --- 05: references ---------------------------------------------------------
ui.section("05", "References")
st.markdown(
    """1. William Stallings, *Cryptography and Network Security*, 8th ed., Pearson
2. NIST FIPS 197 — AES · NIST FIPS 180-4 — SHA-256 · NIST FIPS 186-4 — RSA-PSS
3. RFC 8017 — PKCS #1 v2.2 · RFC 2104 — HMAC
4. PCI-DSS v4.0 · PyCryptodome documentation"""
)

ui.footer()
