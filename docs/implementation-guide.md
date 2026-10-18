# Implementation guide: from offline build to Azure

> Status: **planned**. Nothing here has been deployed. The offline build in this
> repository is what exists today; this guide is how it would be taken to a
> real Azure environment.

## Azure service mapping

| Offline component | Azure service (planned) | Notes |
|---|---|---|
| Detection | Azure AI Language PII detection (adds names, addresses, many locales) | Keep the validators as a second check |
| Pseudonym key | Azure Key Vault secret, read by managed identity | Rotate with a new key id |
| Redaction in the request path | Azure API Management policy or a small Function in front of the model |  |
| Eval | Same harness in CI, plus a sample of real traffic labelled by reviewers |  |

## Steps

1. Put `redact()` in front of every model call and every log sink; log only labels.
2. Store the pseudonym key in Key Vault, inject it at start-up, and fail the service if it is missing.
3. Add Azure AI Language PII as a second detector for names and addresses; union the findings.
4. Grow the eval set from reviewed real samples and gate releases on recall per entity.

## Guardrails to keep when going live

- A candidate is only reported if its validator passes, which removes look-alike order numbers and placeholder SSNs.
- Pseudonymisation is keyed (HMAC-SHA256) and fails closed without a key of at least 16 bytes.
- The key id is part of every pseudonym, so tokens can be traced to the key that made them after rotation.
- Known gaps are tests, so a silent change in behaviour is caught.

## What to measure before calling it production-ready

- Recall per entity on a reviewed sample of real text (misses are the costly error).
- False-positive rate on text with look-alike numbers (order IDs, tracking numbers).
- Share of model prompts and logs containing an unredacted value, from a sampled audit.
