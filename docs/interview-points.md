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

## Tokenization

- **Why tokenize if the data is already encrypted?** Encryption fails as a unit once the key leaks. In this repo's test the thief gets the store and its key and still recovers 0 of 12 values, because the stored fields are tokens and the token key lives elsewhere.
- **Vaulted or vaultless?** Vaultless (keyed format-preserving cipher) needs no lookup table and fits fixed-width columns. A vault suits free-form values and lets you delete one mapping to forget a person, at the cost of another store to run.
- **How do analysts join?** Tokens are deterministic, so equal values give equal tokens. The cost: equality and frequency leak.
- **Who can reverse a token?** Only roles in the policy, per field type, and every attempt is audited with a keyed fingerprint, never the value.
- **Follow-up: weakest point?** The token key. A 9-digit SSN space is small enough to enumerate if that key leaks.
