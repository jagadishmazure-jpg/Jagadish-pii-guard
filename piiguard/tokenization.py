"""Tokenization: replace sensitive values with stand-ins that are useless if stolen.

Two styles, both deterministic so the same value always gets the same token
(tokens can be joined across tables without ever detokenizing):

* Vaultless: a keyed, format-preserving Feistel cipher over decimal digits.
  A 16-digit card stays 16 digits (last four kept for support calls) and an
  SSN stays NNN-NN-NNNN. The token key lives in a separate key service, never
  with the data store. Reversible only with that key.
* Vaulted: a random token is issued and the real value is kept in a token
  vault (its own store and its own key). Used for free-form values such as
  email addresses. A keyed HMAC index makes it deterministic.

Detokenization goes through `Detokenizer`, which checks the caller's role
against a policy and writes an audit event for every allow or deny. Audit
events and exceptions carry only a short keyed fingerprint, never the value.

The Feistel construction follows the shape of NIST FF1 (alternating halves,
HMAC round function, 10 rounds) but is a teaching implementation, not a
certified FF1. Use a vetted FPE library or service in production.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

from .sealed_store import SealedStore
from .validators import digits as only_digits

ROUNDS = 10


class TokenizationError(Exception):
    """Raised for bad input or policy denials. Messages never include the value."""


class AccessDenied(TokenizationError):
    pass


def _fingerprint(key: bytes, value: str) -> str:
    return hmac.new(key, b"fp" + value.encode(), hashlib.sha256).hexdigest()[:10]


# ---------------------------------------------------------------- vaultless FPE
def _round(key: bytes, tweak: bytes, i: int, half: str, width: int) -> int:
    mac = hmac.new(key, tweak + bytes([i]) + half.encode(), hashlib.sha256).digest()
    return int.from_bytes(mac, "big") % (10 ** width)


def fpe_encrypt(key: bytes, tweak: bytes, num: str) -> str:
    if not num.isdigit() or len(num) < 4:
        raise TokenizationError("format-preserving input must be at least 4 digits")
    u = len(num) // 2
    a, b = num[:u], num[u:]
    for i in range(ROUNDS):
        w = len(a)
        c = (int(a) + _round(key, tweak, i, b, w)) % (10 ** w)
        a, b = b, str(c).zfill(w)
    return a + b


def fpe_decrypt(key: bytes, tweak: bytes, tok: str) -> str:
    u = len(tok) - len(tok) // 2 if ROUNDS % 2 else len(tok) // 2
    a, b = tok[:u], tok[u:]
    for i in reversed(range(ROUNDS)):
        w = len(b)
        c = (int(b) - _round(key, tweak, i, a, w)) % (10 ** w)
        a, b = str(c).zfill(w), a
    return a + b


def _reformat(template: str, new_digits: str) -> str:
    it = iter(new_digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in template)


class VaultlessTokenizer:
    """Keyed, deterministic, format-preserving tokens for CARD, SSN and PHONE."""

    KEEP_LAST = {"CARD": 4, "SSN": 0, "PHONE": 0}

    def __init__(self, key: bytes, key_id: str = "v1"):
        if len(key) < 16:
            raise TokenizationError("token key must be at least 16 bytes")
        self._key, self.key_id = key, key_id

    def _split(self, kind: str, value: str) -> tuple[str, str]:
        if kind not in self.KEEP_LAST:
            raise TokenizationError(f"vaultless tokenization does not support {kind}")
        d = only_digits(value)
        keep = self.KEEP_LAST[kind]
        return (d[:-keep], d[-keep:]) if keep else (d, "")

    def tokenize(self, kind: str, value: str) -> str:
        head, tail = self._split(kind, value)
        return _reformat(value, fpe_encrypt(self._key, kind.encode(), head) + tail)

    def detokenize(self, kind: str, token: str) -> str:
        head, tail = self._split(kind, token)
        return _reformat(token, fpe_decrypt(self._key, kind.encode(), head) + tail)


# ---------------------------------------------------------------- vaulted
class TokenVault:
    """Random tokens; real values kept in a separate sealed vault store."""

    def __init__(self, vault_key: bytes, index_key: bytes):
        self._store = SealedStore(vault_key)
        self._index_key = index_key
        self._by_index: dict[str, str] = {}
        self._by_token: dict[str, int] = {}

    def tokenize(self, kind: str, value: str) -> str:
        idx = hmac.new(self._index_key, kind.encode() + b"|" + value.encode(), hashlib.sha256).hexdigest()
        if idx in self._by_index:
            return self._by_index[idx]
        token = f"tok_{kind.lower()}_{secrets.token_hex(8)}"
        self._store.put({"t": token, "k": kind, "v": value})
        self._by_index[idx] = token
        self._by_token[token] = len(self._by_token)
        return token

    def detokenize(self, kind: str, token: str) -> str:
        pos = self._by_token.get(token)
        if pos is None:
            raise TokenizationError("unknown token")
        row = self._store.get(pos)
        if row["k"] != kind:
            raise TokenizationError("token type mismatch")
        return row["v"]


# ---------------------------------------------------------------- access control
@dataclass
class AuditEvent:
    ts: float
    role: str
    kind: str
    token_fp: str
    decision: str
    purpose: str


@dataclass
class Detokenizer:
    """Role-gated detokenization with an audit trail that holds no raw values."""

    vaultless: VaultlessTokenizer
    vault: TokenVault
    policy: dict[str, set[str]]
    audit_key: bytes
    log: list[AuditEvent] = field(default_factory=list)

    def reveal(self, role: str, kind: str, token: str, purpose: str) -> str:
        fp = _fingerprint(self.audit_key, token)
        allowed = kind in self.policy.get(role, set())
        self.log.append(AuditEvent(time.time(), role, kind, fp, "allow" if allowed else "deny", purpose))
        if not allowed:
            raise AccessDenied(f"role '{role}' may not detokenize {kind} (token {fp})")
        if kind == "EMAIL":
            return self.vault.detokenize(kind, token)
        return self.vaultless.detokenize(kind, token)


# ---------------------------------------------------------------- record helper
SCHEMA = {"card": "CARD", "ssn": "SSN", "phone": "PHONE", "email": "EMAIL"}


def tokenize_record(rec: dict, vl: VaultlessTokenizer, vault: TokenVault) -> dict:
    out = dict(rec)
    for col, kind in SCHEMA.items():
        if col in out and out[col] is not None:
            try:
                out[col] = vault.tokenize(kind, out[col]) if kind == "EMAIL" else vl.tokenize(kind, out[col])
            except TokenizationError:
                raise TokenizationError(f"could not tokenize column '{col}'") from None
    return out
