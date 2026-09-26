# Algorithm activation quorum compatibility

Status: accepted for optional client support; live activation requires coordination.

Legacy proposal creation marks an algorithm pending on its first vote. Maturity
processing does not require the weighted voting operation to have returned true,
so a single validator can trigger eventual activation without quorum. Changing
that rule retroactively would change historical state roots.

Persist the independent optional `algorithm_quorum_activation_height` schedule.
Only proposals first created at or after the configured block store a required
marker; reaching the existing weighted quorum stores an approval marker. Maturity
processing requires approval only for those marked proposals. Both markers belong
to canonical trie state, so restart, import and replay share the same decision.
Do not recalculate quorum at maturity: later validator-set changes must not revoke
an already approved proposal. Clear prior approval on every new guarded proposal.
Pending proposal parameters remain immutable under existing validation.

Preserve legacy proposals, absent configuration, and pre-upgrade execution. This
intentionally leaves old pending proposals outside the guard, even when their
later votes or maturity cross the upgrade. Operators must account for them during
rollout. Reuse atomic future-only startup scheduling and trusted snapshot checks.
No default genesis value or live activation height is introduced.

This change does not repair the first-vote pending transition, seven-day voting
window, full proposal identity, verifier-hash validation or emergency policy.
Those require separate implementations and compatibility decisions. In
particular, this guard does not claim complete white-paper governance compliance.

Verification separates native voting and registry restoration from producer and
importer maturity fixtures. Controlled fixture heights do not represent an actual
multi-day network run or a deployed upgrade.
