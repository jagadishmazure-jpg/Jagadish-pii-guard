"""Offline tests for piiguard. All values are synthetic or public test numbers."""
import pytest

from piiguard import Redactor, aadhaar_ok, detect, iban_ok, luhn_ok, ssn_ok
from piiguard.evaluate import GAPS, load, regex_only, score
from piiguard.validators import ipv4_ok, verhoeff_digit, verhoeff_ok


# ---------- validators ----------
@pytest.mark.parametrize("num,ok", [("4111 1111 1111 1111", True), ("4111111111111112", False),
                                    ("5500-0000-0000-0004", True), ("123", False)])
def test_luhn(num, ok):
    assert luhn_ok(num) is ok


@pytest.mark.parametrize("ssn,ok", [("123-45-6789", True), ("000-12-3456", False), ("666-45-6789", False),
                                    ("900-12-3456", False), ("123-00-6789", False), ("123-45-0000", False)])
def test_ssn_rules(ssn, ok):
    assert ssn_ok(ssn) is ok


def test_iban_mod97():
    assert iban_ok("GB82 WEST 1234 5698 7654 32")
    assert not iban_ok("GB82 WEST 1234 5698 7654 33")
    assert not iban_ok("not an iban")


def test_verhoeff_round_trip():
    for base in ["23456789012", "98765432101", "55555555555"]:
        assert verhoeff_ok(base + verhoeff_digit(base))


def test_aadhaar_rules():
    good = "23456789012" + verhoeff_digit("23456789012")
    assert aadhaar_ok(good)
    assert not aadhaar_ok("1" + good[1:])          # cannot start with 0 or 1
    assert not aadhaar_ok(good[:-1] + str((int(good[-1]) + 1) % 10))


def test_ipv4():
    assert ipv4_ok("10.20.30.40") and not ipv4_ok("10.0.0.256") and not ipv4_ok("01.2.3.4")


# ---------- detection ----------
def test_detects_multiple_entities_in_order():
    found = detect("Email bob@example.org or call 555-013-4477.")
    assert [(f.entity, f.text) for f in found] == [("EMAIL", "bob@example.org"), ("PHONE", "555-013-4477")]


def test_invalid_checksums_are_not_flagged():
    assert detect("Order number 4111 1111 1111 1112 shipped today.") == []
    assert detect("Reference 000-12-3456 is a placeholder.") == []


def test_overlap_prefers_higher_priority():
    found = detect("Card 4111 1111 1111 1111")
    assert [f.entity for f in found] == ["CARD"]


def test_pan_format_requires_valid_holder_type():
    assert [f.entity for f in detect("PAN ABCPE1234F")] == ["PAN_IN"]
    assert detect("SKU ABCDE1234F") == []


# ---------- redaction ----------
TEXT = "Card 4111 1111 1111 1111, email ann.lee@example.com, SSN 123-45-6789."


def test_label_mode_removes_values():
    r = Redactor("label").redact(TEXT)
    assert r.text == "Card [CARD], email [EMAIL], SSN [SSN]."
    assert r.counts == {"CARD": 1, "EMAIL": 1, "SSN": 1}


def test_mask_mode_keeps_last_four():
    r = Redactor("mask").redact("Card 4111 1111 1111 1111.")
    assert r.text == "Card ****1111."


def test_findings_are_safe_to_log():
    r = Redactor("label").redact(TEXT)
    assert all(len(f) == 3 and isinstance(f[1], int) for f in r.findings)
    assert "4111" not in repr(r.findings) and "ann.lee" not in repr(r.findings)


def test_pseudonyms_are_stable_and_keyed():
    a = Redactor("pseudonymise", key="A" * 24).redact(TEXT).text
    a2 = Redactor("pseudonymise", key="A" * 24).redact(TEXT).text
    b = Redactor("pseudonymise", key="B" * 24, key_id="v2").redact(TEXT).text
    assert a == a2 and a != b
    assert "<EMAIL:v1:" in a and "<EMAIL:v2:" in b
    assert "ann.lee" not in a and "4111" not in a


def test_pseudonymise_needs_a_key(monkeypatch):
    monkeypatch.delenv("PIIGUARD_KEY", raising=False)
    with pytest.raises(ValueError, match="needs a key"):
        Redactor("pseudonymise")
    with pytest.raises(ValueError, match="16 bytes"):
        Redactor("pseudonymise", key="short")


def test_key_from_environment(monkeypatch):
    monkeypatch.setenv("PIIGUARD_KEY", "E" * 24)
    monkeypatch.setenv("PIIGUARD_KEY_ID", "2026-10")
    assert "<SSN:2026-10:" in Redactor("pseudonymise").redact("SSN 123-45-6789").text


def test_entity_filter():
    r = Redactor("label", entities={"EMAIL"}).redact(TEXT)
    assert "[EMAIL]" in r.text and "4111 1111 1111 1111" in r.text


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        Redactor("encrypt")


def test_text_without_pii_is_unchanged():
    s = "Meeting at 10:30 on 2026-10-17 in room 4."
    assert Redactor("label").redact(s).text == s


# ---------- evaluation ----------
def test_eval_set_scores():
    res = score(load())
    assert res["ALL"]["tp"] == 16 and res["ALL"]["fp"] == 0 and res["ALL"]["fn"] == 0


def test_validators_remove_false_positives():
    with_v, without = score(load())["ALL"], score(load(), regex_only())["ALL"]
    assert without["fp"] > with_v["fp"]


def test_known_gaps_are_still_missed():
    """These are documented limitations. If one starts passing, update the docs."""
    assert score(load(GAPS))["ALL"]["fn"] == len(load(GAPS))
