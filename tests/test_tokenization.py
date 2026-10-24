"""Tokenization layer: format, determinism, joins, theft of store+key, RBAC, leak-free errors and logs."""
import json
import logging
import random

import pytest

from piiguard import detect
from piiguard.sealed_store import SealedStore, StoreError, open_sealed
from piiguard.tokenization import (
    AccessDenied,
    Detokenizer,
    TokenizationError,
    TokenVault,
    VaultlessTokenizer,
    fpe_decrypt,
    fpe_encrypt,
    tokenize_record,
)

SK, TK = b"test-storage-key-000000001", b"test-token-key-0000000002"
VK, IK, AK = b"test-vault-key-00000003", b"test-index-key-00000004", b"test-audit-key-0005"
ROWS = [
    {"id": 1, "card": "4111 1111 1111 1111", "ssn": "123-45-6789", "phone": "(555) 014-2398",
     "email": "ann.lee@example.com"},
    {"id": 2, "card": "5500 0000 0000 0004", "ssn": "234-56-7890", "phone": "(555) 019-7731",
     "email": "raj.iyer@example.org"},
    {"id": 3, "card": "3782 822463 10005", "ssn": "345-67-8901", "phone": "(555) 016-4420",
     "email": "mia.cho@example.net"},
]
RAW = [r[f] for r in ROWS for f in ("card", "ssn", "phone", "email")]


@pytest.fixture
def env():
    vl, vault = VaultlessTokenizer(TK), TokenVault(VK, IK)
    det = Detokenizer(vl, vault, {"fraud_analyst": {"CARD", "SSN"}, "support_agent": {"EMAIL", "PHONE"}}, AK)
    return vl, vault, det


def test_fpe_roundtrip_many_lengths():
    rng = random.Random(7)
    for n in range(4, 20):
        for _ in range(50):
            x = "".join(rng.choice("0123456789") for _ in range(n))
            t = fpe_encrypt(TK, b"T", x)
            assert len(t) == n and t.isdigit() and fpe_decrypt(TK, b"T", t) == x


def test_format_preserved_and_last4_kept(env):
    vl, _, _ = env
    t = vl.tokenize("CARD", "4111 1111 1111 1111")
    assert len(t) == 19 and t[4] == " " and t.endswith("1111") and t != "4111 1111 1111 1111"
    s = vl.tokenize("SSN", "123-45-6789")
    assert s[3] == "-" and s[6] == "-" and s != "123-45-6789"


def test_deterministic_and_key_dependent(env):
    vl, vault, _ = env
    assert vl.tokenize("SSN", "123-45-6789") == vl.tokenize("SSN", "123-45-6789")
    assert VaultlessTokenizer(b"another-key-0000000000").tokenize("SSN", "123-45-6789") != vl.tokenize("SSN", "123-45-6789")
    assert vault.tokenize("EMAIL", "a@example.com") == vault.tokenize("EMAIL", "a@example.com")


def test_type_tweak_separates_domains(env):
    vl, _, _ = env
    assert vl.tokenize("PHONE", "123-456-7890") != vl.tokenize("SSN", "1234567890")


def test_no_collisions_on_10k_cards(env):
    vl, _, _ = env
    toks = {vl.tokenize("CARD", f"4{i:015d}") for i in range(10_000)}
    assert len(toks) == 10_000


def test_join_on_tokens_matches_raw_join(env):
    vl, vault, _ = env
    pays = [{"card": "4111 1111 1111 1111", "amt": 1}, {"card": "3782 822463 10005", "amt": 2},
            {"card": "4111 1111 1111 1111", "amt": 3}, {"card": "6011 1111 1111 1117", "amt": 4}]
    tc = [tokenize_record(r, vl, vault) for r in ROWS]
    tp = [tokenize_record(p, vl, vault) for p in pays]
    raw = sorted((c["id"], p["amt"]) for c in ROWS for p in pays if c["card"] == p["card"])
    tok = sorted((c["id"], p["amt"]) for c in tc for p in tp if c["card"] == p["card"])
    assert raw == tok == [(1, 1), (1, 3), (3, 2)]


def test_attacker_with_store_and_key_recovers_nothing(env):
    vl, vault, _ = env
    safe, control = SealedStore(SK), SealedStore(SK)
    for r in ROWS:
        safe.put(tokenize_record(r, vl, vault))
        control.put(r)
    stolen_control = json.dumps([open_sealed(SK, b) for b in control.dump()])
    stolen_safe = json.dumps([open_sealed(SK, b) for b in safe.dump()])
    assert sum(v in stolen_control for v in RAW) == len(RAW)      # encryption alone: everything leaks
    assert sum(v in stolen_safe for v in RAW) == 0                # tokenized: nothing leaks
    for r in ROWS:   # not even the middle digits of a card or any SSN digits run
        assert r["ssn"].replace("-", "") not in stolen_safe.replace("-", "")
        assert r["card"].replace(" ", "")[:12] not in stolen_safe.replace(" ", "")


def test_attacker_cannot_detokenize_without_token_key(env):
    vl, _, _ = env
    t = vl.tokenize("SSN", "123-45-6789")
    assert VaultlessTokenizer(SK).detokenize("SSN", t) != "123-45-6789"


def test_encrypted_store_rejects_wrong_key_and_tamper():
    s = SealedStore(SK)
    s.put({"a": 1})
    blob = s.dump()[0]
    with pytest.raises(StoreError):
        open_sealed(b"wrong-key-00000000000", blob)
    with pytest.raises(StoreError):
        open_sealed(SK, blob[:20] + bytes([blob[20] ^ 1]) + blob[21:])


def test_authorized_role_detokenizes(env):
    vl, vault, det = env
    t = tokenize_record(ROWS[0], vl, vault)
    assert det.reveal("fraud_analyst", "CARD", t["card"], "case") == ROWS[0]["card"]
    assert det.reveal("support_agent", "EMAIL", t["email"], "case") == ROWS[0]["email"]


@pytest.mark.parametrize("role,kind", [("support_agent", "SSN"), ("support_agent", "CARD"),
                                       ("marketing", "EMAIL"), ("", "CARD"), ("fraud_analyst", "EMAIL")])
def test_unauthorized_roles_denied_and_audited(env, role, kind):
    vl, vault, det = env
    t = tokenize_record(ROWS[0], vl, vault)
    with pytest.raises(AccessDenied):
        det.reveal(role, kind, t[kind.lower()], "probe")
    assert det.log[-1].decision == "deny" and det.log[-1].role == role


def test_vault_rejects_unknown_and_mismatched_tokens(env):
    _, vault, _ = env
    t = vault.tokenize("EMAIL", "a@example.com")
    with pytest.raises(TokenizationError):
        vault.detokenize("EMAIL", "tok_email_0000")
    with pytest.raises(TokenizationError):
        vault.detokenize("CARD", t)


def test_no_raw_pii_in_errors_audit_or_logs(env, caplog):
    vl, vault, det = env
    caplog.set_level(logging.DEBUG)
    log = logging.getLogger("piiguard.test")
    msgs = []
    t = tokenize_record(ROWS[0], vl, vault)
    for role, kind in (("marketing", "CARD"), ("marketing", "SSN"), ("marketing", "PHONE"), ("marketing", "EMAIL")):
        try:
            det.reveal(role, kind, t[kind.lower()], "probe")
        except AccessDenied as e:
            msgs.append(str(e))
            log.warning("detokenize denied: %s", e)
    for bad in ({"card": "12"}, {"ssn": "1-2"}):
        try:
            tokenize_record(bad, vl, vault)
        except TokenizationError as e:
            msgs.append(str(e))
            log.error("tokenize failed: %s", e)
    try:
        vl.tokenize("EMAIL", ROWS[0]["email"])
    except TokenizationError as e:
        msgs.append(str(e))
    msgs += [repr(ev) for ev in det.log] + [r.getMessage() for r in caplog.records]
    blob = "\n".join(msgs)
    assert len(msgs) >= 10
    assert detect(blob) == []
    for v in RAW + [t["card"], t["ssn"], t["phone"], t["email"]]:
        assert v not in blob


def test_short_keys_refused():
    with pytest.raises(TokenizationError):
        VaultlessTokenizer(b"short")
    with pytest.raises(StoreError):
        SealedStore(b"short")
