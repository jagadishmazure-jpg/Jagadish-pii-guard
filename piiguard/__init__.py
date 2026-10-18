"""piiguard: find and remove personal data before text reaches a model or a log.

Detectors combine a regex with a checksum or validity rule where one exists
(Luhn for cards, mod-97 for IBANs, Verhoeff for Aadhaar-style IDs, range rules
for SSNs), which cuts false positives compared with regex alone.
"""
from .detectors import DETECTORS, Finding, detect
from .redact import RedactionResult, Redactor
from .validators import aadhaar_ok, iban_ok, luhn_ok, ssn_ok

__all__ = ["DETECTORS", "Finding", "detect", "Redactor", "RedactionResult",
           "aadhaar_ok", "iban_ok", "luhn_ok", "ssn_ok"]
__version__ = "0.1.0"
