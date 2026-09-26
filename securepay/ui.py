"""
Shared design system and cross-page helpers for SecurePay.

Every page imports from here: masthead, numbered sections, cards, footer,
log rendering, and goto() for programmatic navigation.
"""

import streamlit as st

from securepay.flow import CATALOG, cart_total

# page key -> script path (used by goto / st.switch_page)
NAV_TARGETS = {
    "overview": "app_pages/overview.py",
    "shop": "app_pages/shop.py",
    "cart": "app_pages/cart.py",
    "checkout": "app_pages/checkout.py",
    "gateway": "app_pages/gateway.py",
    "attack_lab": "app_pages/attack_lab.py",
    "database": "app_pages/database.py",
    "report": "app_pages/report.py",
}


def goto(page_key):
    """Navigate to another page (official multi-page API)."""
    st.switch_page(NAV_TARGETS[page_key])


# ---------------------------------------------------------------------------
# Cart state (shared by Shop / Cart / Checkout pages)
# ---------------------------------------------------------------------------

def cart_state():
    """The cart lives in session state as {sku: qty}."""
    if "cart" not in st.session_state:
        st.session_state.cart = {}
    return st.session_state.cart


def cart_add(sku, n=1):
    cart_state()[sku] = cart_state().get(sku, 0) + n


def cart_dec(sku):
    qty = cart_state().get(sku, 0) - 1
    if qty > 0:
        cart_state()[sku] = qty
    else:
        cart_state().pop(sku, None)


def cart_remove(sku):
    cart_state().pop(sku, None)


def cart_clear():
    cart_state().clear()


def cart_items():
    """Cart -> protocol item rows ({sku, title, qty, price}), catalog order."""
    by_sku = {p["sku"]: p for p in CATALOG}
    return [
        {"sku": sku, "title": by_sku[sku]["title"],
         "qty": qty, "price": by_sku[sku]["price"]}
        for sku, qty in cart_state().items()
        if sku in by_sku
    ]


def qr_png(data: str):
    """Render data as a QR code (PIL image — feed straight into st.image)."""
    import qrcode

    return qrcode.make(data).get_image()


# ---------------------------------------------------------------------------
# Design system
# ---------------------------------------------------------------------------

CSS = """
<style>
/* ---- design tokens --------------------------------------------------- */
:root {
  --sp-bg: #FFFFFF;
  --sp-surface: #F6F7FB;
  --sp-border: rgba(15, 23, 42, .12);
  --sp-text: #0F172A;
  --sp-muted: #64748B;
  --sp-accent: #4F46E5;
  --sp-accent-soft: #EEF2FF;
  --sp-success: #059669;
  --sp-danger: #DC2626;
  --sp-warn: #D97706;
  --sp-radius: 12px;
  --sp-shadow-sm: 0 1px 2px rgba(15, 23, 42, .06);
  --sp-shadow-md: 0 4px 14px rgba(15, 23, 42, .10);
}

/* ---- typography ------------------------------------------------------- */
h1 { font-size: 2.1rem !important; font-weight: 800 !important;
     letter-spacing: -0.025em !important; line-height: 1.12 !important;
     margin: .05rem 0 .45rem !important; color: var(--sp-text); }
h2 { font-size: 1.32rem !important; font-weight: 750 !important;
     letter-spacing: -0.015em !important; margin: 2.1rem 0 .55rem !important; }
h3 { font-size: 1.02rem !important; font-weight: 680 !important;
     margin: 1.2rem 0 .4rem !important; }
p, li { line-height: 1.62; color: var(--sp-text); }

.sp-eyebrow { font-size: .71rem; font-weight: 750; letter-spacing: .16em;
   text-transform: uppercase; color: var(--sp-accent);
   margin: 0 0 .45rem; }
.sp-sub { font-size: .71rem; font-weight: 750; letter-spacing: .13em;
   text-transform: uppercase; color: var(--sp-muted); margin: 0 0 .5rem; }
.sp-lead { font-size: 1.04rem; line-height: 1.72;
   color: var(--sp-muted); max-width: 74ch; margin: 0 0 1.5rem; }
.sp-prose { max-width: 80ch; }
.sp-prose p { margin: .45rem 0 .9rem; }
.sp-note { font-size: .84rem; color: var(--sp-muted); line-height: 1.6; }

/* ---- status pills ------------------------------------------------------ */
.sp-pill { display: inline-flex; align-items: center; gap: .3rem;
   padding: .22rem .65rem; border-radius: 999px;
   border: 1px solid transparent;
   font-size: .72rem; font-weight: 750; letter-spacing: .04em; }

/* ---- numbered sections ------------------------------------------------- */
.sp-section { display: flex; align-items: center; gap: .6rem;
   margin: 2.2rem 0 .85rem; }
.sp-section:first-of-type { margin-top: .4rem; }
.sp-section-n { display: inline-flex; align-items: center; justify-content: center;
   min-width: 1.7rem; height: 1.7rem; padding: 0 .35rem; border-radius: 8px;
   background: var(--sp-accent-soft); border: 1px solid rgba(79, 70, 229, .25);
   font-size: .72rem; font-weight: 800; letter-spacing: .04em;
   color: var(--sp-accent); }
.sp-section-t { font-size: 1.06rem; font-weight: 750; letter-spacing: -0.015em; }

/* ---- cards -------------------------------------------------------------- */
.sp-step, .sp-goal { border: 1px solid var(--sp-border);
   background: var(--sp-bg); border-radius: var(--sp-radius);
   padding: .85rem .9rem; height: 100%; min-height: 108px;
   box-shadow: var(--sp-shadow-sm);
   transition: box-shadow .15s ease, transform .15s ease; }
.sp-step:hover, .sp-goal:hover { box-shadow: var(--sp-shadow-md);
   transform: translateY(-1px); }
.sp-step-n, .sp-goal-id { font-size: .72rem; font-weight: 800;
   letter-spacing: .12em; color: var(--sp-accent); margin-bottom: .3rem; }
.sp-step-t, .sp-goal-t { font-weight: 700; font-size: .92rem;
   margin-bottom: .18rem; letter-spacing: -0.01em; }
.sp-step-d, .sp-goal-d { font-size: .8rem; color: var(--sp-muted);
   line-height: 1.5; }
.sp-price { font-weight: 800; color: var(--sp-text); font-size: 1rem; }
/* shop cards: uniform title height so prices/buttons align across the row */
.sp-product .sp-step-t { min-height: 3.1em; }

/* ---- QR frame ------------------------------------------------------------ */
div[data-testid="stImage"] img { background: #fff;
   border: 1px solid var(--sp-border); border-radius: var(--sp-radius);
   padding: 10px; box-shadow: var(--sp-shadow-sm); }

/* ---- forms & metrics ------------------------------------------------------ */
[data-testid="stForm"] { border-radius: 14px; border: 1px solid var(--sp-border);
   box-shadow: var(--sp-shadow-sm); }
div[data-testid="stMetric"] { border: 1px solid var(--sp-border);
   background: var(--sp-surface); border-radius: var(--sp-radius);
   padding: .8rem 1rem; }
[data-testid="stMetricLabel"] { text-transform: uppercase; letter-spacing: .1em;
   font-size: .68rem !important; font-weight: 750; color: var(--sp-muted); }
[data-testid="stMetricValue"] { font-weight: 800 !important;
   font-size: 1.5rem !important; letter-spacing: -0.02em; }

/* ---- sidebar ---------------------------------------------------------------- */
[data-testid="stSidebar"] { background: var(--sp-surface);
   border-right: 1px solid var(--sp-border); }
[data-testid="stSidebar"] [data-testid="stRadio"] label {
   border: 1px solid transparent; border-radius: 10px;
   padding: .48rem .7rem; font-weight: 620; font-size: .93rem;
   line-height: 1.3; margin-bottom: 3px;
   transition: background .12s, border-color .12s; }
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
   background: rgba(15, 23, 42, .06); }
[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
   background: var(--sp-accent-soft);
   border-color: rgba(79, 70, 229, .35); }
[data-testid="stSidebarNav"] a {
   border: 1px solid transparent; border-radius: 10px;
   padding: .48rem .7rem; margin-bottom: 3px;
   font-weight: 620 !important; font-size: .93rem !important;
   transition: background .12s, border-color .12s; }
[data-testid="stSidebarNav"] a:hover { background: rgba(15, 23, 42, .06); }
[data-testid="stSidebarNav"] a[aria-current="page"] {
   background: var(--sp-accent-soft);
   border-color: rgba(79, 70, 229, .35); }
.sp-brand { font-size: 1.3rem; font-weight: 800; letter-spacing: -0.025em;
   margin: 0 0 .1rem;
   background: linear-gradient(90deg, #4F46E5, #7C3AED);
   -webkit-background-clip: text; background-clip: text;
   -webkit-text-fill-color: transparent; }
.sp-brand-sub { font-size: .7rem; font-weight: 700; letter-spacing: .14em;
   text-transform: uppercase; color: var(--sp-muted); margin: 0 0 1.1rem; }
.sp-keys { font-size: .82rem; line-height: 1.75; margin-bottom: .6rem; }
.sp-user { display: flex; gap: .55rem; align-items: center;
   background: var(--sp-bg); border: 1px solid var(--sp-border);
   border-radius: 10px; padding: .5rem .65rem; margin-bottom: .8rem;
   box-shadow: var(--sp-shadow-sm); }
.sp-avatar { width: 30px; height: 30px; border-radius: 50%;
   background: var(--sp-accent); color: #fff; font-weight: 800;
   font-size: .72rem; display: inline-flex; align-items: center;
   justify-content: center; flex-shrink: 0; }
.sp-user b { font-size: .88rem; display: block; line-height: 1.2; }

/* ---- tables ------------------------------------------------------------------ */
table { width: 100%; border-collapse: collapse; font-size: .87rem; }
th { text-align: left; font-size: .68rem !important; letter-spacing: .1em;
   text-transform: uppercase; font-weight: 750; color: var(--sp-muted);
   padding: .55rem .7rem;
   border-bottom: 2px solid var(--sp-border); }
td { padding: .62rem .7rem; vertical-align: top; line-height: 1.55;
   border-bottom: 1px solid rgba(15, 23, 42, .08); }
tr:hover td { background: rgba(79, 70, 229, .035); }

/* ---- buttons -------------------------------------------------------------------- */
div[data-testid="stButton"] > button,
div[data-testid="stFormSubmitButton"] > button,
div[data-testid="stDownloadButton"] > button {
   border-radius: 10px; font-weight: 650; border: 1px solid var(--sp-border);
   box-shadow: var(--sp-shadow-sm);
   transition: filter .12s, box-shadow .12s, transform .12s; }
div[data-testid="stButton"] > button:hover,
div[data-testid="stFormSubmitButton"] > button:hover,
div[data-testid="stDownloadButton"] > button:hover {
   filter: brightness(1.04); box-shadow: var(--sp-shadow-md);
   transform: translateY(-1px); }
button[kind="primary"], button[kind="primaryForm"] {
   background: var(--sp-accent); border-color: var(--sp-accent); }
button:focus-visible, a:focus-visible {
   outline: 2px solid var(--sp-accent); outline-offset: 2px; }

/* ---- footer ------------------------------------------------------------------------ */
.sp-footer { border-top: 1px solid var(--sp-border);
   margin-top: 3rem; padding-top: .9rem; font-size: .78rem;
   letter-spacing: .02em; color: var(--sp-muted); }
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page building blocks
# ---------------------------------------------------------------------------

def page_header(eyebrow, title, lead):
    """Consistent page masthead: tracked eyebrow / big title / muted lead."""
    if eyebrow:
        st.markdown(f'<p class="sp-eyebrow">{eyebrow}</p>', unsafe_allow_html=True)
    st.markdown(f"<h1>{title}</h1>", unsafe_allow_html=True)
    st.markdown(f'<p class="sp-lead">{lead}</p>', unsafe_allow_html=True)


def sub(text):
    st.markdown(f'<p class="sp-sub">{text}</p>', unsafe_allow_html=True)


def section(num, title):
    """Numbered section header - separates a page into clear blocks."""
    st.markdown(
        f'<div class="sp-section"><span class="sp-section-n">{num}</span>'
        f'<span class="sp-section-t">{title}</span></div>',
        unsafe_allow_html=True,
    )


def note(text):
    st.markdown(f'<p class="sp-note">{text}</p>', unsafe_allow_html=True)


def footer():
    st.markdown(
        '<div class="sp-footer">Secure E-Commerce Transactions · '
        'demo/test data only (standard test card PAN)</div>',
        unsafe_allow_html=True,
    )


def step_card(num, title, desc):
    return (
        f'<div class="sp-step">'
        f'<div class="sp-step-n">{num}</div>'
        f'<div class="sp-step-t">{title}</div>'
        f'<div class="sp-step-d">{desc}</div></div>'
    )


def goal_card(gid, title, desc):
    return (
        f'<div class="sp-goal">'
        f'<div class="sp-goal-id">{gid}</div>'
        f'<div class="sp-goal-t">{title}</div>'
        f'<div class="sp-goal-d">{desc}</div></div>'
    )


_TONES = {
    "success": ("#ECFDF5", "#065F46", "rgba(16, 185, 129, .45)"),
    "danger": ("#FEF2F2", "#991B1B", "rgba(239, 68, 68, .45)"),
    "warn": ("#FFFBEB", "#92400E", "rgba(245, 158, 11, .5)"),
    "info": ("#EEF2FF", "#3730A3", "rgba(99, 102, 241, .4)"),
}


def pill(text, tone="info"):
    """Semantic status chip: pill('APPROVED', 'success') → styled <span>."""
    bg, fg, border = _TONES[tone]
    return (
        f'<span class="sp-pill" style="background:{bg};color:{fg};'
        f'border-color:{border}">{text}</span>'
    )


# ---------------------------------------------------------------------------
# Log rendering (used by Gateway + Attack Lab)
# ---------------------------------------------------------------------------

def log_tone(step, msg):
    low = f"{step} {msg}".lower()
    if any(k in low for k in ("fail", "error", "reject")):
        return "error"
    if "pass" in low or "approve" in low:
        return "success"
    return "info"


def first_failure(log):
    for step, msg in log:
        if log_tone(step, msg) == "error":
            return f"{step} - {msg}"
    return None


def emit(step, msg):
    tone = log_tone(step, msg)
    line = f"**{step}** — {msg}"
    if tone == "error":
        st.error(line)
    elif tone == "success":
        st.success(line)
    else:
        st.info(line)
