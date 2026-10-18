# Entities, validators and redaction modes

## How detection works

Each detector is a regex that finds candidates and, where one exists, a
validator that confirms them. A candidate that fails its validator is dropped.
When two findings overlap, the one with the higher priority wins (a 16-digit
card number beats a phone pattern inside it).

| Entity | Pattern (summary) | Validator | Priority |
|---|---|---|---:|
| EMAIL | local@domain.tld | none | 90 |
| CARD | 13 to 19 digits, spaces or dashes allowed | Luhn checksum | 80 |
| IBAN | country code, 2 check digits, 4-char groups | ISO 13616 mod-97 | 75 |
| AADHAAR | 12 digits in 4-4-4 groups | Verhoeff checksum, first digit 2 to 9 | 70 |
| SSN | ddd-dd-dddd | SSA rules: area not 000, 666 or 9xx; group not 00; serial not 0000 | 65 |
| PAN_IN | 5 letters, 4 digits, 1 letter, 4th letter a holder type | none | 60 |
| PHONE | North American format with separators | none | 50 |
| IPV4 | dotted quad | every octet 0 to 255 | 40 |

The validators are why the eval shows 0 false positives instead of 8 with the
regexes alone. From the eval set: the order number `4111 1111 1111 1112`
fails Luhn, `000-12-3456` and `666-45-6789` fail the SSN area rule, the
mistyped IBAN `GB82 WEST 1234 5698 7654 33` fails mod-97, and `10.0.0.256`
fails the octet check.

## Redaction modes

| Mode | Output | Reversible | Use |
|---|---|---|---|
| `label` | `[CARD]` | no | Logs, prompts to a model |
| `mask` | `****1111` (last 4 kept) | no | Support screens |
| `pseudonymise` | `<CARD:v1:889b78c3>` | only by someone with the key, by re-computing | Joins and analytics across records |

Pseudonyms are HMAC-SHA256 of the value with a secret key from `PIIGUARD_KEY`
(at least 16 bytes) and a key id from `PIIGUARD_KEY_ID` (default `v1`). The
key id is part of the token, so tokens from an old key are recognisable after
rotation. Without a key, `pseudonymise` refuses to run instead of falling
back to a plain hash, because an unkeyed hash of a card or SSN can be reversed
by brute force over the small input space.

## Known gaps

`data/known_gaps.json` holds cases the detector misses on purpose, and a test
asserts they are still missed, so a change that starts catching them is
noticed and the file is updated:

- phone numbers with no separators (too easy to confuse with IDs)
- obfuscated emails such as "ann at example dot com"
- names, which need an NER model (planned)
