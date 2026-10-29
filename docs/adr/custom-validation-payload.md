# Bounded compound authorization for custom validators

Status: implemented in source; default disabled, no live activation.

A custom account validator receives `bytes sig` and can verify multiple owners.
Two ML-DSA-65 signatures require 6,618 bytes. Previously both JSON and native
RLP decoded that data as one ML-DSA signature and rejected it above 4,096 bytes,
before the installed validator could run. Changing the outer algorithm tag
would also change the signing domain and misrepresent the authorization.

Keep the existing envelope and signing domains. Decode authorization data under
the existing global 51,200-byte ceiling, then enforce the algorithm limit in
shared account-aware validation. Only an account with installed validation code,
validated at or after `custom_validation_payload_height`, may use the larger
payload. Ordinary accounts and inactive custom accounts keep their prior size
limits. Cryptographic verifiers retain their exact signature-length checks.
The contract owns the compound payload layout and must verify every required
owner against the canonical transaction hash; decoding does not authenticate it.

Use the existing future-only, immutable protocol activation mechanism. Candidate
validation uses the next block height; execution and import use the actual block
header. Genesis, startup scheduling, state import and trusted snapshots preserve
the schedule. Omission keeps legacy validity rules. Nodes must upgrade before a
network activates the feature; old binaries cannot import the new transactions.

This change retains the 500,000-gas custom-validation cap, transaction-size cap
and separate parsing and aggregate pool-memory limits. A payload within the byte
ceiling may still exceed the gas budget. It does not add signature aggregation,
a new algorithm, contract deployment semantics, or a live activation height.

The focused tests cover default, pre-activation, boundary, post-activation,
ordinary-account and snapshot/startup constraints. The real two-owner flow is
`tests/e2e/native-aa-registry.mjs --custom-multisig`, documented in the account
abstraction guide, with both cryptographic precompile checks and independent
block import followed by process restart.
