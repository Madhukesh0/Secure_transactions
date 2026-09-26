"""Cart page: review and adjust the cart, then continue to payment."""

import streamlit as st

from securepay import ui
from securepay.flow import cart_total

ui.page_header(
    "Step 02 · Review your cart",
    "Your cart",
    "Adjust quantities or remove items — the order total here is exactly what "
    "the signed customer payload will carry to the gateway.",
)

items = ui.cart_items()

if not items:
    st.info("Your cart is empty — the shelf is waiting.")
    if st.button("← Back to the shop", type="primary"):
        ui.goto("shop")
else:
    head = st.columns([4.2, 1.6, 0.55, 0.55, 0.55, 1.6, 0.55])
    head[0].markdown('<p class="sp-sub">Item</p>', unsafe_allow_html=True)
    head[1].markdown('<p class="sp-sub">Price</p>', unsafe_allow_html=True)
    head[5].markdown('<p class="sp-sub">Total</p>', unsafe_allow_html=True)
    for it in items:
        c = st.columns([4.2, 1.6, 0.55, 0.55, 0.55, 1.6, 0.55])
        c[0].markdown(
            f"**{it['title']}**<br>"
            f"<span class='sp-note'>{it['sku']}</span>",
            unsafe_allow_html=True,
        )
        c[1].markdown(f"₹{it['price']:,.2f}")
        c[2].button("−", key=f"dec_{it['sku']}", on_click=ui.cart_dec, args=(it["sku"],))
        c[3].markdown(
            f"<div style='text-align:center;font-weight:700'>{it['qty']}</div>",
            unsafe_allow_html=True,
        )
        c[4].button("+", key=f"inc_{it['sku']}", on_click=ui.cart_add, args=(it["sku"],))
        c[5].markdown(f"₹{it['qty'] * it['price']:,.2f}")
        c[6].button("✕", key=f"rm_{it['sku']}", on_click=ui.cart_remove, args=(it["sku"],))

    tcol, _ = st.columns([8.05, 1.5])
    tcol.markdown(
        f'<div style="text-align:right;font-size:1.1rem;font-weight:800">'
        f'Cart total: ₹{cart_total(items):,.2f}</div>',
        unsafe_allow_html=True,
    )
    tcol.button("Clear cart", on_click=ui.cart_clear)

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Proceed to payment →", type="primary"):
        ui.goto("checkout")

ui.footer()
