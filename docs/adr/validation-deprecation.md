# Deprecated signatures inside existing validation policies

## Context

The whitepaper preserves existing accounts after algorithm deprecation. A
transaction-bound custom policy using PQVERIFY accepts valid ML-DSA or Dilithium
signatures while active, then returns false for the same authorized key after
deprecation. Verification precompiles share the same active-only helper.

## Decision

Introduce independent, default-off `validation_deprecation_height`. Within
custom-account and contract-paymaster validation only, allow genuine verification
of Active or Deprecated algorithms through the existing native instruction and
single/batch precompile paths. Pending algorithms remain rejected. Retain the
existing precompile wire format, including ML-DSA/Dilithium compatibility fallback.

Keep ordinary execution's policy unchanged and do not mutate the global registry
to implement the exception. Choose the verification policy for each interpreter;
all calls made within that validation environment share it. Custom code remains
responsible for key authorization and message binding. The protocol still checks
nonce and preserves discarded writes and paymaster static-call restrictions.

Persist the immutable schedule in chain configuration, require future additions
on existing chains and reject conflicting trusted snapshots before writes. The
candidate block determines activation consistently across admission, import and
replay. Native PQVERIFY additionally requires the existing instruction schedule.

## Limits

Do not increase validation gas caps or change charging. SLH-DSA custom validation
and signature-heavy paymaster policies still have separate capacity gaps. This
change does not activate a network, admit new deprecated-key root accounts or
alter consensus-signature policy.
