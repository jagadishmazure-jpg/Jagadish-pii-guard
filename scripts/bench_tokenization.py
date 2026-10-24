"""Measure tokenize/detokenize latency on this machine (not part of the CI doc check)."""
import platform
import statistics
import time

from piiguard.tokenization import TokenVault, VaultlessTokenizer

N = 5000
vl, vault = VaultlessTokenizer(b"bench-token-key-0001-xxxxxxxx"), TokenVault(b"bench-vault-key-01-xx", b"bench-index-key-1-xx")


def bench(fn, inputs):
    ts = []
    for x in inputs:
        t = time.perf_counter()
        fn(x)
        ts.append((time.perf_counter() - t) * 1e6)
    ts.sort()
    return statistics.median(ts), ts[int(len(ts) * 0.95)]


cards = [f"4{i:015d}" for i in range(N)]
ssns = [f"{100 + i % 600:03d}-{10 + i % 89:02d}-{1000 + i:04d}" for i in range(N)]
emails = [f"user{i}@example.com" for i in range(N)]
ct = [vl.tokenize("CARD", c) for c in cards]
st = [vl.tokenize("SSN", s) for s in ssns]
rows = [
    ("vaultless CARD tokenize", bench(lambda x: vl.tokenize("CARD", x), cards)),
    ("vaultless CARD detokenize", bench(lambda x: vl.detokenize("CARD", x), ct)),
    ("vaultless SSN tokenize", bench(lambda x: vl.tokenize("SSN", x), ssns)),
    ("vaultless SSN detokenize", bench(lambda x: vl.detokenize("SSN", x), st)),
    ("vaulted EMAIL tokenize (new)", bench(lambda x: vault.tokenize("EMAIL", x), emails)),
    ("vaulted EMAIL tokenize (repeat)", bench(lambda x: vault.tokenize("EMAIL", x), emails)),
]
et = [vault.tokenize("EMAIL", e) for e in emails]
rows.append((f"vaulted EMAIL detokenize ({N}-row vault)", bench(lambda x: vault.detokenize("EMAIL", x), et)))
roundtrip = all(vl.detokenize("CARD", t) == c for t, c in zip(ct, cards))
print(f"python {platform.python_version()}, {N} values per op, roundtrip ok={roundtrip}")
print("| operation | median us | p95 us |\n|---|---:|---:|")
for name, (m, p) in rows:
    print(f"| {name} | {m:.1f} | {p:.1f} |")
