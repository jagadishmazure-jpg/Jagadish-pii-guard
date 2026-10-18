"""Redaction modes.

* ``label``: replace with ``[EMAIL]``, ``[CARD]`` ... (irreversible)
* ``mask``: keep the last 4 characters, ``****1111`` (irreversible, still recognisable)
* ``pseudonymise``: keyed HMAC-SHA256 token ``<EMAIL:v1:3f2a9c1b>`` that is
  stable for the same value and key, so records can still be joined, but
  cannot be reversed without the key. The key comes from ``PIIGUARD_KEY`` (at
  least 16 bytes) or the constructor; there is no unkeyed fallback.

The result never contains the original values; ``findings`` keeps only the
entity type and position so it is safe to log.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from .detectors import DETECTORS, Detector, detect

MODES = ("label", "mask", "pseudonymise")


@dataclass(frozen=True)
class RedactionResult:
    text: str
    findings: tuple  # ((entity, start, end), ...) positions in the ORIGINAL text
    counts: dict


class Redactor:
    def __init__(self, mode: str = "label", key: str | bytes | None = None,
                 key_id: str | None = None, entities: set[str] | None = None,
                 detectors: tuple[Detector, ...] = DETECTORS) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if mode == "pseudonymise":
            key = key if key is not None else os.environ.get("PIIGUARD_KEY")
            if key is None:
                raise ValueError("pseudonymise needs a key: set PIIGUARD_KEY or pass key=")
            key = key.encode() if isinstance(key, str) else key
            if len(key) < 16:
                raise ValueError("key must be at least 16 bytes")
        self.mode = mode
        self._key = key
        self.key_id = key_id or os.environ.get("PIIGUARD_KEY_ID", "v1")
        self.entities = entities
        self.detectors = tuple(d for d in detectors if entities is None or d.entity in entities)

    def _replacement(self, entity: str, value: str) -> str:
        if self.mode == "label":
            return f"[{entity}]"
        if self.mode == "mask":
            tail = value[-4:] if len(value) > 6 else ""
            return "****" + tail
        tag = hmac.new(self._key, f"{entity}:{value}".encode(), hashlib.sha256).hexdigest()[:8]
        return f"<{entity}:{self.key_id}:{tag}>"

    def redact(self, text: str) -> RedactionResult:
        findings = detect(text, self.detectors)
        out, last = [], 0
        counts: dict[str, int] = {}
        for f in findings:
            out.append(text[last:f.start])
            out.append(self._replacement(f.entity, f.text))
            last = f.end
            counts[f.entity] = counts.get(f.entity, 0) + 1
        out.append(text[last:])
        return RedactionResult("".join(out), tuple((f.entity, f.start, f.end) for f in findings), counts)
