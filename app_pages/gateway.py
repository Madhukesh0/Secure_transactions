"""Gateway page: unwrap, decrypt, verify, authorize — or refuse."""

import streamlit as st

from securepay import ui
from securepay.flow import process_and_record

env = st.session_state.get("envelope")
if not env:
    ui.page_header(
        "Step 02 · Gateway side",
        "Payment Gateway",
        "The gateway holds the only RSA private key that unwraps session keys.",
    )
    st.info("No envelope yet — create one on the **Checkout** page.")
    if st.button("Go to Checkout →", type="primary"):
        ui.goto("checkout")
    ui.footer()
else:
    ui.page_header(
        "Step 02 · Gateway side",
        "Payment Gateway",
        "It decrypts the envelope, checks the HMAC payment-token, verifies "
        "the customer's signature and issues an authorization — or refuses.",
    )

    # --- 01: protocol -------------------------------------------------------
    ui.section("01", "Protocol")
    st.markdown(
        """1. `aes_key = RSA-2048-OAEP-SHA256-decrypt(gateway_priv, wrapped_key)`
2. `payload = AES-256-CBC-decrypt(aes_key, iv, ciphertext)` — bad padding ⇒ tampered
3. `json.loads(payload)` — broken UTF-8 ⇒ tampered
4. re-compute `HMAC-SHA256(aes_key, txn_id|customer|amount)` — mismatch ⇒ reject
5. `RSA-PSS-verify(customer_pub, payload, signature)` — failure ⇒ reject
6. on success: issue auth code, append the decision to SQLite""",
    )

    # --- 02: execution ------------------------------------------------------
    ui.section("02", "Execution")
    st.caption(
        f"Processing `{env['txn_id']}` — accepted TXN-IDs are remembered, "
        "so re-sending this same envelope will be refused (replay protection)."
    )
    if st.button("⚙️ Decrypt & verify", type="primary"):
        with st.spinner("RSA-OAEP unwrap → AES-CBC decrypt → HMAC check → RSA-PSS verify..."):
            auth, log = process_and_record(
                env,
                st.session_state.gateway_priv,
                st.session_state.customer_priv.publickey(),
                st.session_state.seen_ids,
            )
        st.session_state.last_result = {"auth": auth, "log": log}

    res = st.session_state.get("last_result")
    if res is None:
        ui.note("Run the button above to execute the gateway protocol.")
    else:
        for step, msg in res["log"]:
            ui.emit(step, msg)

        # --- 03: decision ---------------------------------------------------
        ui.section("03", "Authorization")
        auth = res["auth"]
        if auth:
            st.success(f"### ✅ APPROVED — auth code `{auth['auth_code']}`")
            st.json(auth)
            if st.button("Now try to break it → Attack Lab →", type="primary"):
                ui.goto("attack_lab")
        else:
            st.error("### ❌ REJECTED — the gateway refused this transaction")

    ui.footer()
