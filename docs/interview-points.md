# Interview points

Short, honest talking points for Jagadish-pii-guard. Every number quoted is from the
real run shown in the README.

- Validators, not bigger regexes, are what cut false positives: precision 0.652 to 1.000 on the same set.
- An unkeyed hash of an SSN is reversible by brute force over about a billion values; a keyed HMAC is not without the key.
- Overlap resolution matters: a card number contains a phone-shaped substring.
- I keep known misses as tests so the README cannot quietly over-claim.

## Likely follow-up questions

- How would you rotate the pseudonym key? (New key id; old tokens stay valid for joins until re-keyed in a backfill.)
- Why not only use a cloud PII service? (Locale gaps and cost; validators are cheap and deterministic.)
- What about PII in model output? (Run the same detector on responses before display and logging.)
