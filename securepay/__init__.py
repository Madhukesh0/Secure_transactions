"""
SecurePay — secure e-commerce transaction mini project (BCS703 case study).

Package layout:
  crypto.py  cryptographic primitives + transaction protocol (+ CLI demo)
  flow.py    transaction orchestration and attack simulations
  db.py      SQLite audit trail (securepay.db)
  ui.py      Streamlit design system (imported only by the web app)
"""

__version__ = "1.0.0"

from securepay import crypto, db, flow  # noqa: F401
