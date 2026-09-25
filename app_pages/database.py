"""Database page: SQLite audit trail - metrics, tables, export, clear."""

import json

import streamlit as st

from securepay import db, ui

ui.page_header(
    "Step 04 · Persistence",
    "SQLite Audit Trail",
    "Every gateway decision and every attack attempt is written to "
    "securepay.db (stdlib sqlite3, WAL mode). The log survives refreshes "
    "and restarts — direct evidence that replay protection outlives a session.",
)
ui.note(f"File: <code>{db.DB_PATH}</code>")

# --- 01: overview -----------------------------------------------------------
ui.section("01", "Overview")
s = db.stats()
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Transactions", s["transactions"])
m2.metric("Approved", s["approved"])
m3.metric("Rejected", s["rejected"])
m4.metric("Attacks", s["attacks"])
m5.metric("Blocked", s["blocked"])

# --- 02: transactions -------------------------------------------------------
txs = db.list_transactions()
ui.section("02", "transactions — one row per gateway decision")
if txs:
    with st.container(border=True):
        st.dataframe(
            [{k: row[k] for k in
              ("id", "ts", "txn_id", "decision", "auth_code",
               "amount", "currency", "reason")}
             for row in txs],
            width="stretch", height=220,
        )
        with st.expander("Raw envelope stored with the newest row"):
            st.code(txs[0]["envelope"], language="json")
else:
    st.info("Empty — run a transaction on the Gateway page.")
    if st.button("Go to Checkout →", type="primary"):
        ui.goto("checkout")

# --- 03: attacks ------------------------------------------------------------
atks = db.list_attacks()
ui.section("03", "attacks — one row per attack attempt")
if atks:
    with st.container(border=True):
        st.dataframe(
            [{k: row[k] for k in
              ("id", "ts", "attack", "blocked", "reason", "txn_id")}
             for row in atks],
            width="stretch", height=220,
        )
else:
    st.info("Empty — launch an attack on the Attack Lab page.")
    if st.button("Go to Attack Lab →", type="primary"):
        ui.goto("attack_lab")

# --- 04: export & maintenance ----------------------------------------------
ui.section("04", "Export & maintenance")
e1, e2, e3 = st.columns(3)
e1.download_button("⬇️ Export transactions (JSON)", json.dumps(txs, indent=2),
                   file_name="transactions.json", mime="application/json",
                   width="stretch")
e2.download_button("⬇️ Export attacks (JSON)", json.dumps(atks, indent=2),
                   file_name="attacks.json", mime="application/json",
                   width="stretch")
if e3.button("🗑️ Clear database", width="stretch"):
    db.clear_all()
    st.rerun()

ui.footer()
