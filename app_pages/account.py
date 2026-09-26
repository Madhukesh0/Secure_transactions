"""Account page: sign up / sign in / sign out — customers persisted in SQLite.

Password security story for the case study: passwords are never stored —
only a salted PBKDF2-HMAC-SHA256 hash (securepay.crypto.hash_password).
"""

import streamlit as st

from securepay import db, ui

ui.page_header(
    "Your account",
    "Account",
    "Create an account or sign in — your customer ID is generated here and "
    "travels inside every order you sign. Passwords are never stored: only a "
    "salted PBKDF2-HMAC-SHA256 hash (200,000 iterations) lands in SQLite.",
)

user = st.session_state.get("user")

if user:
    ui.section("01", "Signed in")
    c1, c2, c3 = st.columns(3)
    c1.metric("Customer ID", user["id"])
    c2.metric("Name", user["name"])
    c3.metric("Email", user["email"])
    ui.note(
        "Checkout pre-fills these details on every order. On the Database page "
        "you can inspect the <code>customers</code> table: the password exists "
        "only as <code>pbkdf2_sha256$…</code> — the plaintext is nowhere."
    )
    if st.button("Sign out"):
        st.session_state.pop("user", None)
        st.rerun()
else:
    sign_in, sign_up = st.tabs(["Sign in", "Sign up"])

    with sign_in:
        with st.form("signin_form"):
            st.text_input("Email", key="si_email", placeholder="you@example.com")
            st.text_input("Password", type="password", key="si_password")
            if st.form_submit_button("Sign in", type="primary", use_container_width=True):
                candidate = db.login_customer(
                    st.session_state.si_email, st.session_state.si_password
                )
                if candidate:
                    st.session_state.user = candidate
                    st.rerun()
                else:
                    st.error("Wrong email or password.")

    with sign_up:
        with st.form("signup_form"):
            st.text_input("Name", key="su_name", placeholder="Your full name")
            st.text_input("Email", key="su_email", placeholder="you@example.com")
            st.text_input("Password (min 6 characters)", type="password",
                          key="su_password")
            if st.form_submit_button("Create account", type="primary",
                                     use_container_width=True):
                try:
                    fresh = db.register_customer(
                        st.session_state.su_name,
                        st.session_state.su_email,
                        st.session_state.su_password,
                    )
                    st.session_state.user = fresh
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))

    ui.note("Guest checkout still works without an account — Checkout then "
            "uses demo customer details.")

ui.footer()
