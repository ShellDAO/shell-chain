# Outer AA storage originals and refunds

Status: accepted for unreleased node source

The retained Cancun rules define original storage and the signed refund counter
for one transaction. The adapter's synthetic revm transaction per inner call
reset both. Access warmth alone leaves dirty writes priced as fresh writes and
cannot cancel a prior inner clear refund.

Select the correction through independent `aa_storage_metering_height`, absent by
default. Preserve the established access-only schedule and old historical fees;
storage metering includes the warmth required by Cancun. Schedule persistence,
future-only first activation and trusted snapshot checks follow the existing gates.
No online activation is selected.

Track original words by complete native identity and slot in a local outer map.
Seed each inner journal with the outer original and the currently persisted word.
Capture originals before commit normalization. For persistence only, compare the
finished word to the inner entry value, so restoring the outer original still
writes over an intermediate committed value. Revm retains ownership of nested
checkpoints, value restoration and frame refunds.

Capture each successful inner's signed raw refund before revm caps it. Suppress
inner refunds and apply `min(raw_refund, outer_gas_spent / 5)` once after successful
outer execution. Failed outer execution discards all refunds, including a failure
at final payer-reserve reconciliation. The exposed gas-spent budget remains gross.
The SSTORE stipend guard is unchanged. Legacy beneficiary pricing/scope is retained
but its refund-adjusted inner credit is deferred until outer success; it cannot
be spent by later calls as an intermediate fee award. Reconciled fee rewards still
flow through the existing system reward path.

All maps and counters are local to this invocation. Full native keys prevent
legacy interpreter aliases from mixing originals. New outer transactions and
process reopen start from persisted state; old receipt/trace replay selects the
original block's activation. Batch gas estimation retains its documented limits.

Validation uses the genuine public failure and the same stopped database with
future schedules, plus literal opcode costs and matched no-refund receipt controls
from EIP-2200/2929/3529. Zero-original controls force the outer cap to bind. Tests
cover signed cancellation, original/current persistence, native aliases, delegate
rollback, stipend edges, failed batches, fee modes, self-beneficiary and sponsored
payer, schedule ownership, independent import, history and physical reopen.
