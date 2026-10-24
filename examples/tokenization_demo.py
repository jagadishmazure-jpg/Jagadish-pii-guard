"""Tokenize two synthetic tables, join on tokens, then play the attacker.

All values are synthetic or public test numbers; keys are demo constants.
Output is deterministic so CI can check it against the README.
"""
import json

from piiguard import detect
from piiguard.sealed_store import SealedStore, open_sealed
from piiguard.tokenization import AccessDenied, Detokenizer, TokenVault, VaultlessTokenizer, tokenize_record

STORAGE_KEY = b"demo-storage-key-0001-not-secret"   # lives with the database
TOKEN_KEY = b"demo-token-key-0002-not-secret!!"     # lives in a separate key service
VAULT_KEY, INDEX_KEY, AUDIT_KEY = b"demo-vault-key-0003-xxxxxxxx", b"demo-index-key-0004-xxxx", b"demo-audit-0005-xxxx"

customers = [
    {"id": 1, "name": "Ann Lee", "card": "4111 1111 1111 1111", "ssn": "123-45-6789",
     "phone": "(555) 014-2398", "email": "ann.lee@example.com"},
    {"id": 2, "name": "Raj Iyer", "card": "5500 0000 0000 0004", "ssn": "234-56-7890",
     "phone": "(555) 019-7731", "email": "raj.iyer@example.org"},
    {"id": 3, "name": "Mia Cho", "card": "3782 822463 10005", "ssn": "345-67-8901",
     "phone": "(555) 016-4420", "email": "mia.cho@example.net"},
]
payments = [{"card": "4111 1111 1111 1111", "amount": 42.10}, {"card": "3782 822463 10005", "amount": 9.99},
            {"card": "4111 1111 1111 1111", "amount": 5.00}, {"card": "6011 1111 1111 1117", "amount": 70.00}]

vl, vault = VaultlessTokenizer(TOKEN_KEY), TokenVault(VAULT_KEY, INDEX_KEY)
tok_customers = [tokenize_record(c, vl, vault) for c in customers]
tok_payments = [tokenize_record(p, vl, vault) for p in payments]
for r in tok_customers:
    print("customer:", {k: r[k] for k in ("id", "card", "ssn", "phone")}, "email:", r["email"][:9] + "...")

# Join on tokens, compare with the join on raw values.
raw_join = sorted((c["id"], p["amount"]) for c in customers for p in payments if c["card"] == p["card"])
tok_join = sorted((c["id"], p["amount"]) for c in tok_customers for p in tok_payments if c["card"] == p["card"])
print(f"\njoin on raw cards: {raw_join}")
print(f"join on tokens:    {tok_join}  identical={raw_join == tok_join}")

# Encrypted store holding tokenized rows, and a control store holding raw rows.
safe, control = SealedStore(STORAGE_KEY), SealedStore(STORAGE_KEY)
for c, t in zip(customers, tok_customers):
    safe.put(t)
    control.put(c)

secrets_ = [c[f] for c in customers for f in ("card", "ssn", "phone", "email")]


def attacker(dump):
    """Has the stolen ciphertext AND the storage key, but not the token key or vault."""
    text = json.dumps([open_sealed(STORAGE_KEY, b) for b in dump])
    return sum(s in text for s in secrets_), len(detect(text))


print("\nattacker steals encrypted store + its key:")
print("  raw rows (control):  recovered %d/%d sensitive values, %d PII-shaped spans" %
      (*attacker(control.dump())[:1], len(secrets_), attacker(control.dump())[1]))
print("  tokenized rows:      recovered %d/%d sensitive values, %d PII-shaped spans" %
      (*attacker(safe.dump())[:1], len(secrets_), attacker(safe.dump())[1]))

# Role-gated detokenization with audit.
policy = {"fraud_analyst": {"CARD", "SSN"}, "support_agent": {"EMAIL", "PHONE"}}
det = Detokenizer(vl, vault, policy, AUDIT_KEY)
print("\nfraud_analyst reveals card:", det.reveal("fraud_analyst", "CARD", tok_customers[0]["card"], "case-1"))
for role, kind in (("support_agent", "SSN"), ("marketing", "PHONE")):
    try:
        det.reveal(role, kind, tok_customers[0][kind.lower()], "case-2")
    except AccessDenied as e:
        print("denied:", e)
print("audit log:")
for ev in det.log:
    print(f"  role={ev.role:<14} kind={ev.kind:<5} token_fp={ev.token_fp} decision={ev.decision} purpose={ev.purpose}")
