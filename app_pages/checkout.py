"""Checkout page: pay by card (bank check) or UPI QR (signed request), then sign + hybrid-encrypt."""

import json
import re
import time

import streamlit as st

from securepay import ui
from securepay.crypto import b64d
from securepay.flow import (
    ENVELOPE_B64_FIELDS,
    bank_check,
    build_envelope,
    build_upi_order,
    card_network,
    cart_total,
    luhn_ok,
    mask_payload,
    validate_card,
)

ui.page_header(
    "Step 03 · Pay securely",
    "Checkout",
    "Pay like on any real shopping site — by card or UPI QR — then "
    "cryptography takes over: the order is signed (RSA-PSS), encrypted "
    "(AES-256-CBC) and its session key wrapped (RSA-OAEP). You see exactly "
    "what travels on the wire.",
)

items = ui.cart_items()

if not items:
    st.warning("Your cart is empty — add something from the shop first.")
    if st.button("← Back to the shop", type="primary"):
        ui.goto("shop")
else:
    # --- 01: order summary ---------------------------------------------------
    ui.section("01", "Order summary")
    for it in items:
        r = st.columns([5, 2, 2])
        r[0].markdown(f"**{it['title']}** × {it['qty']}")
        r[2].markdown(f"₹{it['qty'] * it['price']:,.2f}")
    s = st.columns([5, 2, 2])
    s[2].markdown(f"**Total: ₹{cart_total(items):,.2f}**")

    # --- 02: payment method & details ----------------------------------------
    ui.section("02", "Payment")
    user = st.session_state.get("user") or {}
    method = st.radio("Pay with", ["💳 Card", "📱 UPI QR"],
                      horizontal=True, label_visibility="collapsed")

    if method == "📱 UPI QR":
        with st.form("upi_form"):
            st.markdown(
                '<div class="sp-prose"><p>The gateway builds a <b>UPI payment '
                "request</b> for this exact amount and signs it with its "
                "RSA-PSS key before rendering the QR. A scanner can verify "
                "that signature with the gateway's public key — a tampered QR "
                "(changed amount or payee) fails instantly. No card data "
                "exists on this rail.</p></div>",
                unsafe_allow_html=True,
            )
            c1, c2 = st.columns([3, 1])
            c1.markdown(
                f'<div class="sp-note">Merchant: <code>securepay@campus</code>'
                f" · reference travels inside the QR (<code>tr=</code>)</div>",
                unsafe_allow_html=True,
            )
            c2.markdown(
                f'<div style="text-align:center">'
                f'<div class="sp-sub" style="margin-bottom:.2rem">Amount</div>'
                f'<div style="font-size:1.7rem;font-weight:800;letter-spacing:-.02em">'
                f'₹{cart_total(items):,.2f}</div></div>',
                unsafe_allow_html=True,
            )
            upi_submitted = st.form_submit_button(
                "📱 Generate signed payment QR & encrypt order", type="primary"
            )

        if upi_submitted:
            customer = {
                "id": user.get("id", "CUST-7741"),
                "name": user.get("name", "Aditya Sharma"),
                "email": user.get("email", "aditya.sharma@example.com"),
            }
            with st.spinner("Signing the payment request (RSA-PSS) + encrypting the order..."):
                request, payload, envelope = build_upi_order(
                    customer, items, cart_total(items),
                    st.session_state.customer_priv,
                    st.session_state.gateway_priv.publickey(),
                    st.session_state.gateway_priv,
                )
            st.session_state.payload = payload
            st.session_state.envelope = envelope
            st.session_state.upi_request = request
            st.session_state.pop("upi_paid", None)
            st.session_state.pop("last_result", None)
            st.session_state.pop("attack_result", None)
            st.success(f"Signed payment request **{request['txn_id']}** created — order envelope encrypted.")

        req = st.session_state.get("upi_request")
        if req:
            left, right = st.columns(2)
            with left:
                st.image(ui.qr_png(req["string"]), width=260,
                         caption="Scan with GPay / PhonePe / Paytm — payee is a "
                                 "demo address, so no real money moves")
            with right:
                st.markdown("**Payment request (encoded inside the QR)**")
                st.code(req["string"], language="text")
                st.markdown("**Gateway RSA-PSS signature (Base64)**")
                st.code(req["signature"][:72] + "…", language="text")
            if not st.session_state.get("upi_paid"):
                if st.button("✅ Simulate: customer paid via UPI app"):
                    st.session_state.upi_paid = True
                    st.rerun()
            else:
                st.success("Merchant's UPI app confirms the payment (simulated). "
                           "The money moved over NPCI — below, the order envelope "
                           "is what the gateway verifies.")
    else:
        with st.form("checkout_form"):
            c1, c2, c3 = st.columns(3)
            cust_id = c1.text_input("Customer ID", user.get("id", "CUST-7741"),
                                    disabled=bool(user))
            name = c2.text_input("Name", user.get("name", "Aditya Sharma"))
            email = c3.text_input("Email", user.get("email", "aditya.sharma@example.com"))
            card_no = c1.text_input("Card number", "4532 0151 1283 0366",
                                    help="Spaces are fine — validated with the Luhn checksum as you type.")
            digits = re.sub(r"\D", "", card_no)
            if digits:
                c1.caption(
                    f"**{card_network(digits)}** · "
                    + ("Luhn ✓ valid card number" if luhn_ok(digits)
                       else "Luhn ✗ invalid card number")
                )
            holder = c2.text_input("Card holder", "ADITYA SHARMA")
            expiry = c3.text_input("Expiry (MM/YY)", "12/27",
                                   help="Must be a future month — the bank check rejects expired cards.")
            cvv = c1.text_input("CVV", "328", type="password",
                                help="Demo only — never enter a real card's CVV.")
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
            customer = {"id": cust_id, "name": name, "email": email}
            card = {"number": digits, "holder": holder,
                    "expiry": expiry, "cvv": cvv}
            ok, errors = validate_card(card)
            if not ok:
                for e in errors:
                    st.error("💳 " + e)
            else:
                with st.spinner("Contacting the issuing bank… (simulated)"):
                    time.sleep(0.8)   # makes the 'bank round-trip' visible in the demo
                    bank_ok, bank_msg = bank_check(card)
                if not bank_ok:
                    st.error("💳 " + bank_msg)
                else:
                    st.success("💳 " + bank_msg)
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

    if not user:
        ui.note("Guest checkout — create an account on the <b>Account</b> page "
                "and the customer ID, name and email fill themselves.")

    # --- 03: on the wire ------------------------------------------------------
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
