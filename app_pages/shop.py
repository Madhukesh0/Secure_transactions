"""Shop page: product shelf — pick items, they land in the cart."""

import streamlit as st

from securepay import ui
from securepay.flow import CATALOG, cart_total

ui.page_header(
    "Step 01 · Browse & add to cart",
    "Shop",
    "Browse the campus bookstore and add products to your cart. Nothing "
    "cryptographic happens on this page yet — signing and encryption start "
    "at checkout.",
)

for col, prod in zip(st.columns(len(CATALOG)), CATALOG):
    with col:
        st.markdown(
            f'<div class="sp-step sp-product">'
            f'<div class="sp-step-n">{prod["icon"]} {prod["sku"]}</div>'
            f'<div class="sp-step-t">{prod["title"]}</div>'
            f'<div class="sp-step-d"><span class="sp-price">₹{prod["price"]:,.2f}</span>'
            f' · in stock</div></div>',
            unsafe_allow_html=True,
        )
        if st.button(
            "Add to cart", key=f"add_{prod['sku']}", use_container_width=True
        ):
            ui.cart_add(prod["sku"])
            st.toast(f"Added — {prod['title']}", icon="🛒")

items = ui.cart_items()
if items:
    ui.section("✓", "Your cart is ready")
    left, right = st.columns([3, 1])
    left.metric(
        f"{sum(i['qty'] for i in items)} item(s) in cart",
        f"₹{cart_total(items):,.2f}",
    )
    if right.button("Go to cart →", type="primary", use_container_width=True):
        ui.goto("cart")

ui.footer()
