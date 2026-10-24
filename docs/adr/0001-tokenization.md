# ADR 0001: Tokenize on top of encryption, two token styles

**Status:** accepted (offline build)

**Context.** Encrypted tables are readable by anyone holding the key, and the
key usually sits close to the data. We need stored card, SSN, phone and email
values to stay useless after a full theft of store and storage key, while
analysts can still join tables.

**Decision.**
- Vaultless keyed format-preserving tokens for fixed-format numbers (card, SSN, phone): no lookup table to protect or scale, and tokens fit existing columns.
- A token vault for free-form values (email), where format preservation is awkward.
- Both deterministic, so joins work.
- Detokenization only through a role-checked, audited path.
- Standard library only, so the repo stays dependency-free; production should swap in a vetted FF1 and AES-GCM.

**Consequences.** Equality and frequency leak through deterministic tokens.
Token-key compromise is the critical risk. Vault lookups add a store to run
and back up.
