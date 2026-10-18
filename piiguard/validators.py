"""Checksum and validity rules. Each takes the matched text and returns bool."""
from __future__ import annotations

import re


def digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def luhn_ok(text: str) -> bool:
    """Payment card check digit (ISO/IEC 7812). 13-19 digits."""
    d = digits(text)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def ssn_ok(text: str) -> bool:
    """US SSN structure: area not 000, 666 or 900-999; group not 00; serial not 0000."""
    d = digits(text)
    if len(d) != 9:
        return False
    area, group, serial = int(d[:3]), int(d[3:5]), int(d[5:])
    return area not in (0, 666) and area < 900 and group != 0 and serial != 0


def iban_ok(text: str) -> bool:
    """IBAN mod-97 check (ISO 13616)."""
    s = re.sub(r"\s", "", text).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    moved = s[4:] + s[:4]
    number = "".join(str(int(c, 36)) for c in moved)
    return int(number) % 97 == 1


# Verhoeff tables (dihedral group D5), used by the Aadhaar check digit.
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
      [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
      [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
      [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
      [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
      [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_ok(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_digit(number: str) -> str:
    """Check digit to append to ``number`` (used to build synthetic test IDs)."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def aadhaar_ok(text: str) -> bool:
    """12 digits, first digit 2-9, valid Verhoeff check digit."""
    d = digits(text)
    return len(d) == 12 and d[0] not in "01" and verhoeff_ok(d)


def ipv4_ok(text: str) -> bool:
    parts = text.split(".")
    return len(parts) == 4 and all(p.isdigit() and int(p) <= 255 and str(int(p)) == p for p in parts)
