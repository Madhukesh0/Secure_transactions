"""Checkout page: customer builds, signs and hybrid-encrypts an order."""

import json

import streamlit as st

from securepay import ui
from securepay.crypto import b64d
from securepay.flow import (
    DEFAULT_ITEMS,
    ENVELOPE_B64_FIELDS,
    build_envelope,
    cart_total,
    mask_payload,
    normalize_items,
)

ui.page_header(
    "Step 01 · Customer side",
    "Checkout",
    "Fill the order like any online shop. On submit the payload is signed "
    "(RSA-PSS), encrypted (AES-256-CBC) and its session key wrapped "
    "(RSA-OAEP) — then you see exactly what travels on the wire.",
)

# --- 01: cart ---------------------------------------------------------------
ui.section("01", "Cart")
edited = st.data_editor(
    DEFAULT_ITEMS,
    num_rows="dynamic",
    width="stretch",
    column_config={
        "sku": st.column_config.TextColumn("SKU"),
        "title": st.column_config.TextColumn("Title"),
        "qty": st.column_config.NumberColumn("Qty", min_value=1, step=1),
        "price": st.column_config.NumberColumn("Price (INR)", min_value=0.0, format="%.2f"),
    },
)
items = normalize_items(edited)

# --- 02: payment & customer details ----------------------------------------
ui.section("02", "Payment & customer details")
with st.form("checkout_form"):
    c1, c2, c3 = st.columns(3)
    cust_id = c1.text_input("Customer ID", "CUST-7741")
    name = c2.text_input("Name", "Aditya Sharma")
    email = c3.text_input("Email", "aditya.sharma@example.com")
    card_no = c1.text_input("Card number", "4532015112830366")
    holder = c2.text_input("Card holder", "ADITYA SHARMA")
    expiry = c3.text_input("Expiry (MM/YY)", "12/27")
    cvv = c1.text_input("CVV", "328", type="password")
    c2.markdown(
        f'<div style="text-align:center">'
        f'<div class="sp-sub" style="margin-bottom:.2rem">Order total</div>'
        f'<div style="font-size:1.7rem;font-weight:800;letter-spacing:-.02em">'
        f'₹{cart_total(items):,.2f}</div></div>',
        unsafe_allow_html=True,
    )
    submitted = st.form_submit_button(
        "🔒 Sign & encrypt for the gateway", type="primary"
    )

if submitted:
    if not items:
        st.warning("Cart is empty — add at least one item.")
    else:
        customer = {"id": cust_id, "name": name, "email": email}
        card = {"number": card_no, "holder": holder, "expiry": expiry, "cvv": cvv}
        with st.spinner("RSA-PSS signing + AES-256 encrypting + RSA-OAEP key wrap..."):
            payload, envelope = build_envelope(
                customer, card, items,
                st.session_state.customer_priv,
                st.session_state.gateway_priv.publickey(),
            )
        st.session_state.payload = payload
        st.session_state.envelope = envelope
        st.session_state.pop("last_result", None)
        st.session_state.pop("attack_result", None)
        st.success(f"Envelope ready for **{envelope['txn_id']}** — continue to the gateway.")

# --- 03: on the wire --------------------------------------------------------
env = st.session_state.get("envelope")
if env:
    ui.section("03", "What travels on the wire")
    left, right = st.columns(2)
    with left:
        st.markdown("**Plaintext before encryption (masked)**")
        st.json(mask_payload(st.session_state.payload))
    with right:
        st.markdown("**Encrypted envelope — all an eavesdropper sees**")
        view = {}
        for k, v in env.items():
            if k in ENVELOPE_B64_FIELDS and isinstance(v, str) and len(v) > 64:
                view[k] = v[:64] + "..."
            else:
                view[k] = v
        st.json(view)
        with st.expander("Show complete envelope JSON"):
            st.code(json.dumps(env, indent=2), language="json")
    pt_bytes = len(json.dumps(st.session_state.payload))
    ct_bytes = len(b64d(env["ciphertext"]))
    ui.note(
        f"{pt_bytes} bytes of plaintext → {ct_bytes} bytes of ciphertext "
        f"({len(json.dumps(env))} bytes on the wire incl. Base64) · "
        "fresh random 128-bit IV every transaction"
    )
    if st.session_state.get("last_result") is None:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Continue to Gateway →", type="primary"):
            ui.goto("gateway")

ui.footer()
