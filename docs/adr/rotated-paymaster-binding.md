# Bind rotated EOA sponsorship to the registered account key

A successful AccountManager key rotation preserves the account address and
updates the public-key registry and account hash. Previously, EOA sponsorship
attempted to derive that original address from the replacement key, rejecting
genuine sponsor signatures after rotation.

Use independent, default-off `paymaster_registered_root_height` activation. For
a key that no longer derives the sponsor address, require its registered bytes
to match the nonzero account public-key hash in the candidate state and verify
the original paymaster signing domain. Admission, import and replay share this
authorization entry. Previous heights retain their exact behavior.

The existing sponsor wire format carries no algorithm tag, and rotation does
not persist an algorithm identifier. Follow the existing session-root policy:
try only currently active algorithms and require genuine verification. Preserve
the original address-bound deprecation rule separately. Persisted algorithm
identity and rotated-key deprecation remain separate work; this change does not
claim to resolve those semantics. No gas budgets or transaction formats change.

Activation follows existing immutable future scheduling and trusted-snapshot
matching. Invalid signatures, stale keys and registry/account mismatches must
reject without state changes. Runtime acceptance covers exact sponsor payment,
replay after rotation and restart persistence in an isolated chain.
