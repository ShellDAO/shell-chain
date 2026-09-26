# Publish algorithm proposals only after quorum

Status: accepted for optional client support; live activation requires coordination.

The white paper requires quorum before committing a candidate to the algorithm
registry. Legacy proposal submission immediately changes an active algorithm to
pending, disabling signatures after a single unapproved vote. The independent
activation guard prevents premature maturity but does not prevent this transition.

Add the optional `algorithm_proposal_staging_height` schedule using existing
future-only, immutable configuration and trusted snapshot checks. Proposals first
created at or after that boundary keep candidate height and verifier hash under
separate canonical storage keys. A nonzero candidate height identifies an open
staged proposal; existing timelock validation excludes zero. Subsequent votes must
match both parameters. Before quorum, leave live registry entries and their
canonical status, activation height and verifier hash unchanged.

On quorum, publish the pending specification through the same helper as legacy
proposal creation, record required/approved markers, and clear the candidate
keys. Approval is independent of whether the older quorum schedule is configured.
Use existing vote accounting and execution rollback; introduce no new RPC or
signature format. Canonical storage gives restart, import and isolated historical
replay the same candidate state.

Preserve legacy execution and proposals already pending at the upgrade. A separate
schedule is necessary because networks can already select the earlier quorum
upgrade, whose recorded roots must remain valid. No default or live height changes.
Approved pending algorithms still reject signatures until maturity. Seven-day
expiry, complete proposal identity, verifier matching and emergency policy remain
separate work; the staging upgrade does not claim complete governance compliance.
