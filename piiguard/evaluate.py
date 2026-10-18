"""Precision and recall on the labelled synthetic set in ``data/eval_set.json``.

Also runs the same detectors with their validators switched off ("regex
only"), to show what the checksum and validity rules are worth. Every value in
the set is synthetic: card numbers are public test numbers, the IBAN is the
standard documentation example, and the Aadhaar-style IDs are generated with a
valid check digit, not taken from anyone.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from .detectors import DETECTORS, detect

DATA = Path(__file__).resolve().parent.parent / "data" / "eval_set.json"
GAPS = DATA.with_name("known_gaps.json")


def load(path: Path = DATA) -> list[dict]:
    return json.loads(path.read_text())


def score(items: list[dict], detectors=DETECTORS) -> dict:
    per: dict[str, dict[str, int]] = {}
    for item in items:
        gold = {(s["entity"], s["value"]) for s in item["spans"]}
        got = {(f.entity, f.text) for f in detect(item["text"], detectors)}
        for ent in {e for e, _ in gold | got}:
            g = {x for x in gold if x[0] == ent}
            p = {x for x in got if x[0] == ent}
            row = per.setdefault(ent, {"tp": 0, "fp": 0, "fn": 0})
            row["tp"] += len(g & p)
            row["fp"] += len(p - g)
            row["fn"] += len(g - p)
    tot = {k: sum(r[k] for r in per.values()) for k in ("tp", "fp", "fn")}
    per["ALL"] = tot
    for row in per.values():
        row["precision"] = row["tp"] / (row["tp"] + row["fp"]) if row["tp"] + row["fp"] else 1.0
        row["recall"] = row["tp"] / (row["tp"] + row["fn"]) if row["tp"] + row["fn"] else 1.0
    return per


def regex_only():
    return tuple(replace(d, validator=None) for d in DETECTORS)


def report() -> str:
    items = load()
    full, naive = score(items), score(items, regex_only())
    lines = [f"{len(items)} labelled sentences, {full['ALL']['tp'] + full['ALL']['fn']} PII values",
             "", "| Entity | TP | FP | FN | precision | recall |", "|---|---:|---:|---:|---:|---:|"]
    for ent in sorted(k for k in full if k != "ALL") + ["ALL"]:
        r = full[ent]
        lines.append(f"| {ent} | {r['tp']} | {r['fp']} | {r['fn']} | {r['precision']:.3f} | {r['recall']:.3f} |")
    a = naive["ALL"]
    lines += ["", f"Regex only (validators off): precision {a['precision']:.3f}, recall {a['recall']:.3f}, "
              f"false positives {a['fp']} (with validators: {full['ALL']['fp']})"]
    gaps = load(GAPS)
    missed = score(gaps)["ALL"]["fn"]
    lines += ["", f"Known gaps (kept as failing cases on purpose): {missed} of {len(gaps)} missed"]
    lines += [f"- {g['why']}" for g in gaps]
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
