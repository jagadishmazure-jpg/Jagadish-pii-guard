"""A tiny authenticated-encryption record store (the "encrypted at rest" layer).

Teaching stand-in, standard library only: an HMAC-SHA256 keystream (counter
mode) plus an HMAC-SHA256 tag, encrypt-then-MAC. It exists so the tests can
model "the database is encrypted" and then hand the attacker the key. In a real
system use AES-GCM from a vetted library or the database's own encryption.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os


class StoreError(Exception):
    """Raised on tampering or a wrong key. Never carries record contents."""


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out, ctr = bytearray(), 0
    while len(out) < n:
        out += hmac.new(key, b"ks" + nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:n])


def seal(key: bytes, record: dict) -> bytes:
    plain = json.dumps(record, sort_keys=True).encode()
    nonce = os.urandom(16)
    body = bytes(a ^ b for a, b in zip(plain, _keystream(key, nonce, len(plain))))
    tag = hmac.new(key, b"tag" + nonce + body, hashlib.sha256).digest()
    return nonce + body + tag


def open_sealed(key: bytes, blob: bytes) -> dict:
    nonce, body, tag = blob[:16], blob[16:-32], blob[-32:]
    want = hmac.new(key, b"tag" + nonce + body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, want):
        raise StoreError("record failed integrity check (wrong key or tampered)")
    return json.loads(bytes(a ^ b for a, b in zip(body, _keystream(key, nonce, len(body)))))


class SealedStore:
    """Rows are sealed with one storage key. dump() is what a thief would copy."""

    def __init__(self, key: bytes):
        if len(key) < 16:
            raise StoreError("storage key must be at least 16 bytes")
        self._key = key
        self._rows: list[bytes] = []

    def put(self, record: dict) -> None:
        self._rows.append(seal(self._key, record))

    def get(self, i: int) -> dict:
        return open_sealed(self._key, self._rows[i])

    def rows(self) -> list[dict]:
        return [open_sealed(self._key, b) for b in self._rows]

    def dump(self) -> list[bytes]:
        return list(self._rows)
