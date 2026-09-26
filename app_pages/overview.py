"""Overview page: problem, protocol pipeline, security goals, live stats."""

import streamlit as st

from securepay import db, ui

ui.page_header(
    "",
    "SecurePay — a cryptographic checkout",
    "Protect customer payment information and transaction details from "
    "cyberattacks during online shopping. Every click in this app runs "
    "real cryptography (PyCryptodome) — nothing is mocked or simulated.",
)
st.markdown(
    " ".join(
        ui.pill(t, tone)
        for t, tone in [
            ("🔒 AES-256", "info"), ("🔑 RSA-2048", "info"),
            ("✍️ RSA-PSS", "info"), ("🧾 HMAC-SHA256", "info"),
            ("🔐 PBKDF2", "info"), ("✅ REAL CRYPTO — 0 MOCKS", "success"),
        ]
    ),
    unsafe_allow_html=True,
)

# --- 01: protocol pipeline --------------------------------------------------
ui.section("01", "The protocol — customer side to gateway side")
steps = [
    ("01", "Payload", "JSON order: items, amount, card number, CVV, PII, UTC timestamp, TXN-ID."),
    ("02", "Sign", "Customer signs the plaintext with RSA-PSS / SHA-256 (authenticity + non-repudiation)."),
    ("03", "Encrypt", "AES-256-CBC with a fresh random 128-bit IV encrypts the payload (confidentiality)."),
    ("04", "Wrap key", "The AES session key is wrapped with the gateway's RSA-2048 OAEP public key."),
    ("05", "Verify", "Gateway unwraps, decrypts, checks the HMAC payment-token and the signature."),
    ("06", "Decision", "APPROVED with an auth code, or REJECTED — every outcome lands in SQLite."),
]
cols = st.columns(3)
for i, (n, t, d) in enumerate(steps):
    with cols[i % 3]:
        st.markdown(ui.step_card(n, t, d), unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# --- 02: security goals -----------------------------------------------------
ui.section("02", "Five security goals")
goals = [
    ("P-1", "Confidentiality", "Card number, CVV and PII are unreadable to anyone but the gateway."),
    ("P-2", "Integrity", "Any byte-level tamper with amount or items is detected."),
    ("P-3", "Authenticity", "The gateway proves the order really came from the customer."),
    ("P-4", "Non-repudiation", "The customer cannot later deny having placed the order."),
    ("P-5", "Replay protection", "A recorded envelope cannot be re-submitted for a second charge."),
]
cols = st.columns(5)
for i, (gid, t, d) in enumerate(goals):
    with cols[i]:
        st.markdown(ui.goal_card(gid, t, d), unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# --- 03: live audit trail ---------------------------------------------------
ui.section("03", "Live audit trail")
s = db.stats()
m1, m2, m3, m4 = st.columns(4)
m1.metric("Transactions", s["transactions"])
m2.metric("Approved", s["approved"])
m3.metric("Attack attempts", s["attacks"])
m4.metric("Attacks blocked", s["blocked"])

st.markdown("<br>", unsafe_allow_html=True)
if st.button("🛍️ Start shopping →", type="primary", width="stretch"):
    ui.goto("shop")

ui.footer()
