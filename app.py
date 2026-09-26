"""
SecurePay - Secure E-Commerce MVP (BCS703 case study).

Entry point / router. Uses Streamlit's official multi-page API
(st.navigation + st.Page): every section is a separate script under
app_pages/, gets its own URL (/Checkout, /Gateway, ...) and works with
the browser back/forward buttons.

Project layout
--------------
  app.py               router: page config, session state, sidebar shell
  securepay/           the Python package:
      crypto.py          primitives + protocol (case-study core, + CLI demo)
      flow.py            transaction protocol + attack simulations (pure)
      db.py              SQLite audit trail (securepay.db)
      ui.py              design system: masthead, cards, footer, logs, goto()
  app_pages/           one file per section:
      overview.py  account.py  shop.py  cart.py  checkout.py
      gateway.py  attack_lab.py  database.py  report.py
  tests/               pytest suite (crypto / flow / db)
  docs/                report, deck, specs, captured CLI output

Run:  streamlit run app.py
"""

import os
import sys

# project root on sys.path so every page script can import the securepay package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from securepay import db, ui
from securepay.flow import generate_keys

st.set_page_config(
    page_title="SecurePay · Secure E-Commerce MVP",
    page_icon="🔐",
    layout="wide",
)

db.init_db()   # idempotent - creates securepay.db on first run

# --- session state shared by all pages -------------------------------------
if "customer_priv" not in st.session_state:
    with st.spinner("Generating RSA-2048 keypairs for Customer + Payment Gateway..."):
        cust, gw = generate_keys()
    st.session_state.customer_priv = cust
    st.session_state.gateway_priv = gw
st.session_state.setdefault("seen_ids", set())

# --- sidebar: brand ---------------------------------------------------------
with st.sidebar:
    st.markdown('<p class="sp-brand">🔐 SecurePay</p>', unsafe_allow_html=True)
    st.markdown('<p class="sp-brand-sub">Secure E-Commerce MVP</p>',
                unsafe_allow_html=True)
    _user = st.session_state.get("user")
    if _user:
        _initials = "".join(w[0] for w in _user["name"].split()[:2]).upper()
        st.markdown(
            f'<div class="sp-user"><span class="sp-avatar">{_initials}</span>'
            f'<div><b>{_user["name"]}</b>'
            f'<span class="sp-note">{_user["id"]}</span></div></div>',
            unsafe_allow_html=True,
        )

# --- official navigation: one Page per section ------------------------------
_cart_n = len(ui.cart_items())
_cart_label = f"Cart ({_cart_n})" if _cart_n else "Cart"
navigation = st.navigation(
    [
        st.Page("app_pages/overview.py",   title="Overview",   icon="🏠", default=True),
        st.Page("app_pages/account.py",    title="Account",    icon="👤"),
        st.Page("app_pages/shop.py",       title="Shop",       icon="🛍️"),
        st.Page("app_pages/cart.py",       title=_cart_label,  icon="🛒"),
        st.Page("app_pages/checkout.py",   title="Checkout",   icon="💳"),
        st.Page("app_pages/gateway.py",    title="Gateway",    icon="🏦"),
        st.Page("app_pages/attack_lab.py", title="Attack Lab", icon="⚔️"),
        st.Page("app_pages/database.py",   title="Database",   icon="🗄️"),
        st.Page("app_pages/report.py",     title="Docs",       icon="📖"),
    ],
    expanded=True,
)

# --- sidebar: key management ------------------------------------------------
with st.sidebar:
    st.markdown('<p class="sp-sub">Session keys</p>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sp-keys">👤 Customer — RSA-2048 · ✅ ready<br>'
        '🏦 Gateway — RSA-2048 · ✅ ready</div>',
        unsafe_allow_html=True,
    )
    if st.button("↻ Rotate keypairs", width="stretch"):
        with st.spinner("Regenerating RSA-2048 keypairs..."):
            cust, gw = generate_keys()
        st.session_state.customer_priv = cust
        st.session_state.gateway_priv = gw
        for k in ("envelope", "payload", "last_result", "attack_result",
                  "upi_request", "upi_paid"):
            st.session_state.pop(k, None)
        st.session_state.seen_ids = set()
        st.rerun()
    if st.button("🧹 Reset demo (session only)", width="stretch"):
        for k in ("envelope", "payload", "last_result", "attack_result", "cart",
                  "upi_request", "upi_paid"):
            st.session_state.pop(k, None)
        st.session_state.seen_ids = set()
        st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        '<p class="sp-note">AES-256-CBC · RSA-2048-OAEP-SHA256 · '
        'RSA-PSS-SHA256 · HMAC-SHA256 · fresh IV per transaction</p>',
        unsafe_allow_html=True,
    )

# --- render -----------------------------------------------------------------
ui.inject_css()
navigation.run()
