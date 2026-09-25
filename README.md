# SecurePay — Secure E-Commerce Mini Project (BCS703)

Interactive demo for the case study *Secure E-Commerce Transactions*: a
customer signs (RSA-PSS) and hybrid-encrypts (AES-256 + RSA-OAEP) an order, a
payment gateway decrypts and verifies it, and an Attack Lab shows five
realistic attacks being blocked by named controls. All cryptography is real
(PyCryptodome) — nothing is mocked — and every gateway decision / attack
attempt is persisted to a SQLite audit trail.

Sidebar navigation with six pages, a small CSS design system, and
flow-forward buttons between steps.

> Demo/test data only. The card number is a standard test PAN — never enter a real card.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate              # Windows (bash: source .venv/Scripts/activate)
pip install -r requirements.txt
streamlit run app.py                # opens http://localhost:8501
```

More entry points:

```bash
python -m securepay.crypto          # CLI demo: full protocol + tamper/key tests
python -m securepay.db              # seed + print the SQLite audit trail
python -m pytest                    # run the test suite
```

## The six pages

1. **Overview** — problem statement, 6-step protocol pipeline, five security
   goals as cards, live audit-trail metrics, CTA into the flow
2. **Checkout** — fill an order, watch it get signed (RSA-PSS) and
   hybrid-encrypted (AES-256 + RSA-OAEP); masked plaintext vs. wire view
3. **Gateway** — numbered protocol, unwrap → decrypt → HMAC → signature,
   APPROVED/REJECTED with a verification log
4. **Attack Lab** — bit-flip, forged HMAC, forged signature, wrong key,
   replay — each blocked by a specific, named control
5. **Database** — SQLite audit trail (`securepay.db`): every gateway decision
   and attack persisted, survives refresh/restart, JSON export, clear button
6. **Report** — threat→control mapping, primitives, deliverables, references

## Project layout

```text
app.py                  Streamlit entry point / router (st.navigation)
app_pages/              one script per page (overview, checkout, gateway,
                        attack_lab, database, report)
securepay/              the Python package
├── crypto.py           primitives + transaction protocol (+ CLI demo)
├── flow.py             transaction orchestration + attack simulations
├── db.py               SQLite audit-trail layer
└── ui.py               design system shared by the pages
tests/                  pytest suite: crypto / flow / db (throwaway DB per test)
docs/                   report.md · secure_ecommerce_report.docx ·
                        secure_ecommerce_deck.pptx · deck_spec.json ·
                        report_spec.json · demo_output.txt
.streamlit/config.toml  Streamlit config
requirements.txt        streamlit + pycryptodome (deploy installs from here)
pyproject.toml          project metadata + pytest config
securepay.db            SQLite database (auto-created on first run)
```

## Tests

```bash
python -m pytest
```

The suite covers primitive round-trips and tamper detection (AES-CBC padding,
OAEP unwrap with a wrong key, PSS signature over modified data), the gateway
protocol (honest approval, replay refusal, all five attack simulations) and
the SQLite layer (runs against a throwaway database file per test).

## Database

`securepay/db.py` wraps the stdlib `sqlite3` driver (no extra dependency).
Schema (WAL mode, one connection per thread, thread-safe inserts):

- `transactions(id, txn_id, ts, decision, auth_code, amount, currency, reason, envelope)`
  — one row per gateway decision; `envelope` stores the full arrival JSON
- `attacks(id, ts, attack, blocked, reason, txn_id)` — one row per attack attempt
- `meta(key, value)` — schema version

Every click in the Gateway and Attack Lab pages writes here automatically, so
the audit trail is evidence that replay protection persists beyond a session.

## Deploy — Streamlit Community Cloud

1. Push this repo to GitHub (`app.py` and `requirements.txt` stay at the repo root).
2. Open [share.streamlit.io](https://share.streamlit.io) → **New app** → pick repo/branch.
3. Set **Main file path** to `app.py` → **Deploy**. Dependencies install from `requirements.txt`.
