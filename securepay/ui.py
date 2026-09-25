"""
Shared design system and cross-page helpers for SecurePay.

Every page imports from here: masthead, numbered sections, cards, footer,
log rendering, and goto() for programmatic navigation.
"""

import streamlit as st

# page key -> script path (used by goto / st.switch_page)
NAV_TARGETS = {
    "overview": "app_pages/overview.py",
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
# Design system
# ---------------------------------------------------------------------------

CSS = """
<style>
/* ---- typography scale ---------------------------------------------- */
h1 { font-size: 2.15rem !important; font-weight: 800 !important;
     letter-spacing: -0.025em !important; line-height: 1.12 !important;
     margin: .05rem 0 .45rem !important; }
h2 { font-size: 1.32rem !important; font-weight: 750 !important;
     letter-spacing: -0.015em !important; margin: 2.1rem 0 .55rem !important; }
h3 { font-size: 1.02rem !important; font-weight: 680 !important;
     letter-spacing: -0.008em !important; margin: 1.2rem 0 .4rem !important; }
p, li { line-height: 1.62; }

.sp-eyebrow { font-size: .71rem; font-weight: 750; letter-spacing: .16em;
   text-transform: uppercase; color: var(--muted-foreground, #8a8f98);
   margin: 0 0 .45rem; }
.sp-sub { font-size: .71rem; font-weight: 750; letter-spacing: .13em;
   text-transform: uppercase; color: var(--muted-foreground, #8a8f98);
   margin: 0 0 .5rem; }
.sp-lead { font-size: 1.04rem; line-height: 1.72;
   color: var(--muted-foreground, #9aa0a8); max-width: 74ch;
   margin: 0 0 1.5rem; }
.sp-prose { max-width: 80ch; }
.sp-prose p { margin: .45rem 0 .9rem; }
.sp-note { font-size: .84rem; color: var(--muted-foreground, #8a8f98);
   line-height: 1.6; }

/* ---- numbered sections ---------------------------------------------- */
.sp-section { display: flex; align-items: center; gap: .6rem;
   margin: 2.2rem 0 .85rem; }
.sp-section:first-of-type { margin-top: .4rem; }
.sp-section-n { display: inline-flex; align-items: center; justify-content: center;
   min-width: 1.7rem; height: 1.7rem; padding: 0 .35rem; border-radius: 8px;
   border: 1px solid rgba(128,128,128,.35); background: rgba(128,128,128,.07);
   font-size: .72rem; font-weight: 800; letter-spacing: .04em;
   color: var(--muted-foreground, #8a8f98); }
.sp-section-t { font-size: 1.06rem; font-weight: 750; letter-spacing: -0.015em; }

/* ---- cards ---------------------------------------------------------- */
.sp-step { border: 1px solid var(--border, rgba(128,128,128,.28));
   background: rgba(128,128,128,.05); border-radius: 12px;
   padding: .8rem .85rem; height: 100%; min-height: 108px; }
.sp-step-n { font-size: .72rem; font-weight: 800; letter-spacing: .12em;
   color: var(--muted-foreground, #8a8f98); margin-bottom: .3rem; }
.sp-step-t { font-weight: 700; font-size: .92rem; margin-bottom: .18rem;
   letter-spacing: -0.01em; }
.sp-step-d { font-size: .8rem; color: var(--muted-foreground, #8a8f98);
   line-height: 1.5; }
.sp-goal { border: 1px solid var(--border, rgba(128,128,128,.28));
   background: rgba(128,128,128,.05); border-radius: 12px;
   padding: .75rem .85rem; height: 100%; min-height: 104px; }
.sp-goal-id { font-size: .7rem; font-weight: 800; letter-spacing: .12em;
   color: var(--muted-foreground, #8a8f98); margin-bottom: .25rem; }
.sp-goal-t { font-weight: 700; font-size: .9rem; margin-bottom: .12rem; }
.sp-goal-d { font-size: .78rem; color: var(--muted-foreground, #8a8f98);
   line-height: 1.48; }

/* ---- forms & metrics ------------------------------------------------- */
[data-testid="stForm"] { border-radius: 14px; }
div[data-testid="stMetric"] { border: 1px solid var(--border, rgba(128,128,128,.28));
   background: rgba(128,128,128,.05); border-radius: 12px;
   padding: .8rem 1rem; }
[data-testid="stMetricLabel"] { text-transform: uppercase; letter-spacing: .1em;
   font-size: .68rem !important; font-weight: 750;
   color: var(--muted-foreground, #8a8f98); }
[data-testid="stMetricValue"] { font-weight: 800 !important;
   font-size: 1.5rem !important; letter-spacing: -0.02em; }

/* ---- sidebar --------------------------------------------------------- */
[data-testid="stSidebar"] { border-right: 1px solid var(--border, rgba(128,128,128,.22)); }
[data-testid="stSidebar"] [data-testid="stRadio"] label {
   border: 1px solid transparent; border-radius: 10px;
   padding: .48rem .7rem; font-weight: 620; font-size: .93rem;
   line-height: 1.3; margin-bottom: 3px; transition: background .12s, border-color .12s; }
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
   background: rgba(128,128,128,.10); }
[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
   background: rgba(128,128,128,.14);
   border-color: rgba(128,128,128,.38); }

/* ---- official st.navigation sidebar items ---------------------------- */
[data-testid="stSidebarNav"] a {
   border: 1px solid transparent; border-radius: 10px;
   padding: .48rem .7rem; margin-bottom: 3px;
   font-weight: 620 !important; font-size: .93rem !important;
   transition: background .12s, border-color .12s; }
[data-testid="stSidebarNav"] a:hover {
   background: rgba(128,128,128,.10); }
[data-testid="stSidebarNav"] a[aria-current="page"] {
   background: rgba(128,128,128,.14);
   border-color: rgba(128,128,128,.38); }
.sp-brand { font-size: 1.3rem; font-weight: 800; letter-spacing: -0.025em;
   margin: 0 0 .1rem; }
.sp-brand-sub { font-size: .7rem; font-weight: 700; letter-spacing: .14em;
   text-transform: uppercase; color: var(--muted-foreground, #8a8f98);
   margin: 0 0 1.1rem; }
.sp-keys { font-size: .82rem; line-height: 1.75; margin-bottom: .6rem; }

/* ---- markdown tables -------------------------------------------------- */
table { width: 100%; border-collapse: collapse; font-size: .87rem; }
th { text-align: left; font-size: .68rem !important; letter-spacing: .1em;
   text-transform: uppercase; font-weight: 750;
   color: var(--muted-foreground, #8a8f98);
   padding: .55rem .7rem; border-bottom: 2px solid var(--border, rgba(128,128,128,.45)); }
td { padding: .62rem .7rem; vertical-align: top; line-height: 1.55;
   border-bottom: 1px solid var(--border, rgba(128,128,128,.18)); }

/* ---- buttons ---------------------------------------------------------- */
div[data-testid="stButton"] > button { border-radius: 10px; font-weight: 650;
   transition: filter .12s; }
div[data-testid="stButton"] > button:hover { filter: brightness(1.07); }
div[data-testid="stDownloadButton"] > button { border-radius: 10px; font-weight: 650; }

/* ---- footer ----------------------------------------------------------- */
.sp-footer { border-top: 1px solid var(--border, rgba(128,128,128,.25));
   margin-top: 3rem; padding-top: .9rem; font-size: .78rem;
   letter-spacing: .02em; color: var(--muted-foreground, #8a8f98); }
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page building blocks
# ---------------------------------------------------------------------------

def page_header(eyebrow, title, lead):
    """Consistent page masthead: tracked eyebrow / big title / muted lead."""
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
        '<div class="sp-footer">BCS703 · Cryptography &amp; Network Security · '
        'Secure E-Commerce Transactions case study · demo/test data only '
        '(standard test card PAN)</div>',
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
