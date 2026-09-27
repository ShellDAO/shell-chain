# Prune pending transactions after canonical key rotation

## Context

A pending embedded-key transaction admitted before rotation can fail production
with a state-dependent public-key conflict. It must not be treated as permanently
invalid against speculative state. However, retaining it after the rotation
commits reserves its nonce and balance; the replacement key then encounters the
ordinary replacement-fee threshold despite the old transaction being unusable.
Reference-key entries can likewise remain on a node that imports the rotation.

## Decision

Retain the verified root hash in each pool entry admitted through the default
validator. After canonical production, import or fork adoption, compare that
binding with the account's current nonzero root hash. Remove conflicting entries
and their nonce descendants using the existing index and reservation cleanup.

Run pruning through the shared canonical-commit boundary. Rejected imports and
speculative account updates do not invoke it. Keep ordinary fee replacement rules
and production's state-dependent error classification unchanged. Skip entries
admitted through custom validation and accounts currently using custom validation;
unknown bindings and account-read errors are not evidence of key replacement.

## Scope

This changes local pending-transaction policy, not wire encoding, account storage,
block validity or activation rules. It requires no additional signature checks
per queued transaction at every block. The documented workflow still waits for a
successful rotation receipt before using the replacement key; same-block admission
of a future key is not introduced.
