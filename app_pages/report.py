"""Docs page: how the platform works, how to use it, sample workflow,
threat model, primitives, project structure, references."""

import streamlit as st

from securepay import ui

ui.page_header(
    "Documentation",
    "SecurePay — Documentation",
    "Start here. What this platform is, how the cryptography works, how to "
    "use it, and a sample workflow you can reproduce step by step. Full "
    "write-up: docs/report.md · slides: docs/secure_ecommerce_deck.pptx.",
)

# --- 01: what is this ---------------------------------------------------------
ui.section("01", "What is SecurePay?")
st.markdown(
    '<div class="sp-prose"><p>SecurePay is a working miniature of a secure '
    "online checkout, built for the case study <em>“Protect customer "
    "payment information and transaction details from cyberattacks during "
    "online shopping.”</em> A customer signs in, shops from a small catalog, "
    "and pays at checkout — by <b>card</b> (validated live and authorized by "
    "a simulated bank) or by <b>UPI QR</b> (a signature-verified payment "
    "request). Either way, the moment they pay, the order is <b>digitally "
    "signed</b>, <b>hybrid-encrypted</b> (AES-256 + RSA), and locked so only "
    "the <b>payment gateway</b> can open it. The gateway verifies the "
    "cryptography, asks a simulated issuing bank for authorization when a "
    "card is used, and approves or rejects — writing every decision to a "
    "permanent SQLite audit trail. Nothing is mocked: every algorithm runs "
    "for real via PyCryptodome.</p></div>",
    unsafe_allow_html=True,
)

# --- 02: how it works -----------------------------------------------------------
ui.section("02", "How it works — the transaction flow")
st.code(
    """CUSTOMER (browser)                                PAYMENT GATEWAY (server)
════════════════════                              ═══════════════════════════

  Shop → Cart → Checkout
         │
         ▼
  1. ORDER JSON ──────────────┐   items, amount, card, customer,
         │                    │   txn-id + UTC timestamp
         ▼                    │
  2. SIGN     RSA-PSS/SHA-256 │   customer's private key
         │                    │   → authenticity + non-repudiation
         ▼                    │
  3. ENCRYPT  AES-256-CBC ────┤   fresh random 128-bit IV
         │                    │   → confidentiality
         ▼                    │
  4. WRAP KEY RSA-OAEP/SHA-256┤   AES key locked with the
         │                    │   gateway's public key
         ▼                    ▼
  5. SEND ═══════ envelope ════►  {wrapped_key, iv, ciphertext, signature, mac}
                                       │
                                       ▼
      ┌── 6. UNWRAP    RSA-OAEP with the gateway's private key → AES key
      ├── 7. DECRYPT   AES-256-CBC → plaintext order JSON
      ├── 8. VERIFY    HMAC payment-token + RSA-PSS signature
      ├── 9. BANK      card: simulated issuing-bank authorization (Luhn first)
      │                UPI:  verify the RSA-PSS signature inside the upi://pay QR
      └──10. DECIDE    APPROVED + auth-code  /  DECLINED  /  REJECTED
                       every outcome → SQLite audit trail (securepay.db)""",
    language="text",
)
st.markdown(
    '<div class="sp-prose"><p><b>Why both AES and RSA?</b> AES is fast but '
    "its key cannot be safely shared over the internet; RSA solves key "
    "exchange but is too slow for whole payloads. So RSA carries only the "
    "small AES key, and AES carries the data — the same hybrid design used "
    "by TLS. The signature proves who sent the order and that it was not "
    "changed; the HMAC is a second, faster integrity seal; the txn-id and "
    "timestamp stop replay attacks.</p></div>",
    unsafe_allow_html=True,
)

# --- 03: how to use ------------------------------------------------------------
ui.section("03", "How to use the platform")
st.code(
    """┌─────────┐   ┌──────┐   ┌──────┐   ┌──────────┐   ┌─────────┐
│ Account │ → │ Shop │ → │ Cart │ → │ Checkout │ → │ Gateway │
│ sign in │   │ pick │   │ ±qty │   │ pay+bank │   │ verify  │
└─────────┘   └──────┘   └──────┘   └──────────┘   └─────────┘
                                        then: Attack Lab → Database""",
    language="text",
)
st.markdown(
    """| Page | What you do there |
|---|---|
| **Account** 👤 | Sign up (auto-generates your `CUST-XXXXXX` id) or sign in. Passwords are stored only as salted PBKDF2 hashes. Guest checkout also works. |
| **Shop** 🛍️ | Browse 5 campus-bookstore products; **Add to cart** on any card. |
| **Cart** 🛒 | Adjust quantities with − / +, remove ✕, or clear. The total here is exactly what the signed payload will carry. |
| **Checkout** 💳📱 | Order summary + payment form (pre-filled if signed in). **Card:** live Luhn + network detection, simulated issuing-bank authorization, decline test cards. **UPI QR:** a `upi://pay` request signed with RSA-PSS, rendered as a QR — a tampered QR fails verification (Attack Lab #6). On approval the order is signed & encrypted and you see **what travels on the wire**. |
| **Gateway** 🏦 | Unwrap → decrypt → verify HMAC → verify signature → decision, with a step-by-step log. |
| **Attack Lab** ⚔️ | Fire six realistic attacks and watch each one blocked by a named control — including the UPI QR-swap. |
| **Database** 🗄️ | The permanent SQLite audit trail: transactions, attacks, accounts (hash-only passwords), JSON export. |"""
)

# --- 04: sample workflow ---------------------------------------------------------
ui.section("04", "Sample workflow — reproduce this end to end")
st.markdown(
    """| Step | Do this | You should see |
|---|---|---|
| 1 | Account → **Sign up** (name, email, password ≥ 6 chars) | Signed in — sidebar shows `👤 CUST-XXXXXX` |
| 2 | Shop → **Add to cart** on 2 products | Cart bar appears with item count + total |
| 3 | Cart → change a quantity with **+** | Total updates instantly |
| 4 | Checkout → press **🔒 Sign & encrypt** | *“Authorized by issuing bank (simulated)”* → envelope + wire view (`TXN-…`) |
| 5 | **Continue to Gateway** → process | Steps 1–4 all **PASS** → **APPROVED** + auth code |
| 6 | Attack Lab → run **Bit-flip** | **REJECTED** — tampering detected |
| 7 | Database | Every decision and attack saved as permanent rows |"""
)
ui.note(
    "Test cards for step 4 (demo data — never a real card): see the table below."
)
st.markdown(
    """| Card number | Network | Result at the bank check |
|---|---|---|
| `4532 0151 1283 0366` | Visa | ✅ Authorized — order is signed & encrypted |
| `4000 0000 0000 0002` | Visa | ❌ Declined: insufficient funds |
| `4000 0000 0000 9995` | Visa | ❌ Declined: card reported lost/stolen |
| `4532 0151 1283 0367` | Visa | ❌ Rejected at checkout: Luhn checksum fails |"""
)
ui.note(
    "Any future expiry (MM/YY) and any 3–4 digit CVV work in the demo. "
    "Authentication ≠ authorization: a rejected envelope means the message "
    "failed cryptography (tamper/forgery); a declined card means a genuine "
    "order the bank refused."
)

# --- 05: threat -> control -------------------------------------------------------
ui.section("05", "Threat → control → where to see it")
st.markdown(
    """| Goal | Threat | Control | Where to see it |
|---|---|---|---|
| **P-1** Confidentiality | eavesdropping on card / CVV | AES-256-CBC + RSA-OAEP key wrap | Checkout: only ciphertext on the wire |
| **P-2** Integrity | tampering with amount / items | HMAC-SHA256 + RSA-PSS + CBC padding | Attack Lab: bit-flip & forged HMAC |
| **P-3** Authenticity | impersonating the customer | RSA-PSS signature verification | Attack Lab: forged signature |
| **P-4** Non-repudiation | customer denying the order | RSA-PSS under the customer's key | Gateway: signature verification step |
| **P-5** Replay protection | re-submitting an old envelope | TXN-ID remembered at the gateway | Attack Lab: replay · Database: REJECTED row |
| **+** Credential theft | stealing stored passwords | PBKDF2-HMAC-SHA256, salted, 200k iterations | Database: customers table shows hashes only |
| **+** Garbage card numbers | typos / fake cards at entry | Luhn checksum + field rules + bank decline-list | Checkout: live caption + bank messages |
| **+** QR-swap fraud (UPI) | attacker re-prints the QR with their VPA / a higher amount | RSA-PSS signature over the `upi://pay` request | Attack Lab #6: tampered QR fails verification |"""
)

# --- 06: primitives ---------------------------------------------------------------
ui.section("06", "Cryptographic primitives")
st.markdown(
    """| Primitive | Purpose |
|---|---|
| **AES-256-CBC** + PKCS#7 padding | symmetric encryption of the full transaction payload |
| Random 128-bit IV per transaction | semantic security — no IV reuse |
| **RSA-2048 OAEP / SHA-256** | asymmetric wrapping of the AES session key |
| **RSA-PSS / SHA-256** signature | customer signs the plaintext JSON |
| **SHA-256** | tamper-evident hash of the payload |
| **HMAC-SHA256** | fast payment-token integrity check at the gateway |
| **PBKDF2-HMAC-SHA256** (200k iter + salt) | account passwords — plaintext never stored |
| **Luhn checksum** | sanity check of entered card numbers before the bank call |"""
)

# --- 07: project structure --------------------------------------------------------
ui.section("07", "Project structure & deliverables")
st.markdown(
    """| File | Purpose |
|---|---|
| `securepay/crypto.py` | core crypto library: AES, RSA-OAEP, RSA-PSS, HMAC, PBKDF2 + CLI demo (`python -m securepay.crypto`) |
| `securepay/flow.py` | protocol logic: cart & catalog, card validation, simulated bank, UPI signed QR, gateway decisions, 6 attacks |
| `securepay/db.py` + `securepay.db` | SQLite audit trail: transactions, attacks, customer accounts |
| `securepay/ui.py` | shared design system + cart state |
| `app.py` | router / entry point (st.navigation) |
| `app_pages/*.py` | overview, account, shop, cart, checkout, gateway, attack_lab, database, docs |
| `tests/` | pytest suite (31 tests): crypto, flow, bank check, UPI QR, persistence, accounts |
| `docs/report.md` / `docs/secure_ecommerce_report.docx` | written report |
| `docs/secure_ecommerce_deck.pptx` / `docs/deck_spec.json` | seminar deck + JSON source |
| `docs/demo_output.txt` | captured stdout of a full CLI run |

Run it: `streamlit run app.py` · CLI demo: `python -m securepay.crypto` · tests: `python -m pytest`"""
)

# --- 08: references ----------------------------------------------------------------
ui.section("08", "References")
st.markdown(
    """1. William Stallings, *Cryptography and Network Security*, 8th ed., Pearson
2. NIST FIPS 197 — AES · NIST FIPS 180-4 — SHA-256 · NIST FIPS 186-4 — RSA-PSS
3. RFC 8017 — PKCS #1 v2.2 · RFC 2104 — HMAC · RFC 2898 — PBKDF2
4. PCI-DSS v4.0 · PyCryptodome documentation · Luhn algorithm (US Patent 2,950,048, public domain)"""
)

ui.footer()
