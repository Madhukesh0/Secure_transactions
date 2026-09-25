"""Attack Lab: five attacks against a live envelope, each blocked by a control."""

import streamlit as st

from securepay import db, ui
from securepay.crypto import gateway_processes_envelope
from securepay.flow import (
    ATTACKS,
    attack_bitflip,
    attack_forge_hmac,
    attack_forge_signature,
    attack_wrong_key,
    process_and_record,
)

env = st.session_state.get("envelope")
if not env:
    ui.page_header(
        "Step 03 · Adversary",
        "Attack Lab",
        "Five realistic attacks against a live envelope.",
    )
    st.info("Create an envelope first on the **Checkout** page.")
    if st.button("Go to Checkout →", type="primary"):
        ui.goto("checkout")
    ui.footer()
else:
    ui.page_header(
        "Step 03 · Adversary",
        "Attack Lab",
        "Five realistic attacks against a live envelope. Each one should be "
        "blocked — watch which specific control catches it, then check the "
        "Database page for the persisted record.",
    )

    # --- 01: choose ---------------------------------------------------------
    ui.section("01", "Choose an attack")
    choice = st.radio("Pick an attack", ATTACKS, label_visibility="collapsed")

    # --- 02: launch ---------------------------------------------------------
    ui.section("02", "Launch")
    if st.button("⚔️ Launch attack", type="primary"):
        gw_priv = st.session_state.gateway_priv
        cust_pub = st.session_state.customer_priv.publickey()
        out_log, blocked, fail = [], False, None

        if choice.startswith("Bit-flip"):
            with st.spinner("Attacker flips one bit, gateway processes the result..."):
                auth, out_log = gateway_processes_envelope(
                    attack_bitflip(env), gw_priv, cust_pub)
            blocked = auth is None
            fail = ui.first_failure(out_log)
        elif choice.startswith("Forge the HMAC"):
            with st.spinner("Attacker forges the payment token..."):
                auth, out_log = gateway_processes_envelope(
                    attack_forge_hmac(env), gw_priv, cust_pub)
            blocked = auth is None
            fail = ui.first_failure(out_log)
        elif choice.startswith("Forge the customer"):
            with st.spinner("Attacker tampers with the signature..."):
                auth, out_log = gateway_processes_envelope(
                    attack_forge_signature(env), gw_priv, cust_pub)
            blocked = auth is None
            fail = ui.first_failure(out_log)
        elif choice.startswith("Intercept"):
            with st.spinner("Attacker generates a keypair and attempts OAEP unwrap..."):
                recovered, msg = attack_wrong_key(env)
            out_log = [("Key exchange", msg)]
            blocked = not recovered
            fail = None if recovered else msg
        else:  # replay
            txn = env["txn_id"]
            out_log = []
            if txn not in st.session_state.seen_ids:
                with st.spinner("Legitimate first delivery..."):
                    auth1, log1 = process_and_record(env, gw_priv, cust_pub,
                                                     st.session_state.seen_ids)
                out_log.append((
                    "Delivery #1",
                    "authentic first submission → "
                    + (f"APPROVED ({auth1['auth_code']})" if auth1 else "rejected"),
                ))
                out_log.extend(log1)
            with st.spinner("Attacker re-sends the identical envelope..."):
                auth2, log2 = process_and_record(env, gw_priv, cust_pub,
                                                 st.session_state.seen_ids)
            out_log.append((
                "Delivery #2",
                "identical envelope re-sent by the attacker (replay)",
            ))
            out_log.extend(log2)
            blocked = auth2 is None
            fail = ui.first_failure(log2)

        db.record_attack(choice, blocked, fail, env.get("txn_id"))
        st.session_state.attack_result = {
            "log": out_log, "blocked": blocked, "fail": fail,
        }

    # --- 03: result ---------------------------------------------------------
    res = st.session_state.get("attack_result")
    if res:
        ui.section("03", "What the gateway saw")
        for step, msg in res["log"]:
            ui.emit(step, msg)
        st.markdown("<br>", unsafe_allow_html=True)
        if res["blocked"]:
            suffix = f": {res['fail']}" if res["fail"] else ""
            st.success(f"### 🛡️ ATTACK BLOCKED{suffix}")
            ui.note("Persisted to the <code>attacks</code> table — see it on "
                    "the Database page.")
        else:
            st.error("### 💀 ATTACK SUCCEEDED — the gateway accepted a malicious envelope")

    ui.footer()
