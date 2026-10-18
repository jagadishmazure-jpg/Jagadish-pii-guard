"""Detect and redact PII three ways, then score the detectors.

All values are synthetic or public test numbers. The pseudonymisation key
below is a demo value; real keys come from PIIGUARD_KEY (e.g. Key Vault).
"""
from piiguard import Redactor, detect
from piiguard.evaluate import report

text = ("Hi, I'm writing about card 4111 1111 1111 1111. Email ann.lee@example.com or call "
        "(555) 014-2398. SSN 123-45-6789. Order 4111 1111 1111 1112 is not a card.")
print("input:   ", text)
print("findings:", [(f.entity, f.start, f.end) for f in detect(text)])
print("label:   ", Redactor("label").redact(text).text)
print("mask:    ", Redactor("mask").redact(text).text)
print("pseudo:  ", Redactor("pseudonymise", key="demo-key-not-a-secret-0001").redact(text).text)
print()
print(report())
