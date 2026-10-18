"""Detectors: a regex finds candidates, a validator (if any) confirms them.

Order matters only for overlap resolution: when two findings overlap, the one
with the higher ``priority`` wins (a card number beats a phone number made of
the same digits).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .validators import aadhaar_ok, iban_ok, ipv4_ok, luhn_ok, ssn_ok


@dataclass(frozen=True)
class Detector:
    entity: str
    pattern: re.Pattern
    validator: Callable[[str], bool] | None
    priority: int


@dataclass(frozen=True)
class Finding:
    entity: str
    start: int
    end: int
    text: str


DETECTORS: tuple[Detector, ...] = (
    Detector("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None, 90),
    Detector("CARD", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), luhn_ok, 80),
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), iban_ok, 75),
    Detector("AADHAAR", re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"), aadhaar_ok, 70),
    Detector("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), ssn_ok, 65),
    Detector("PAN_IN", re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b"), None, 60),
    Detector("PHONE", re.compile(r"(?<![\w-])(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"), None, 50),
    Detector("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), ipv4_ok, 40),
)


def detect(text: str, detectors: tuple[Detector, ...] = DETECTORS) -> list[Finding]:
    """All validated findings, overlaps resolved by priority, sorted by position."""
    candidates = []
    for det in detectors:
        for m in det.pattern.finditer(text):
            if det.validator is None or det.validator(m.group(0)):
                candidates.append((det.priority, m.start(), m.end(), det.entity, m.group(0)))
    candidates.sort(key=lambda c: (-c[0], c[1]))
    taken: list[tuple[int, int]] = []
    kept = []
    for _prio, start, end, entity, value in candidates:
        if any(start < e and s < end for s, e in taken):
            continue
        taken.append((start, end))
        kept.append(Finding(entity, start, end, value))
    return sorted(kept, key=lambda f: f.start)
