# Algorithm governance timelock compatibility

Status: accepted for optional client support; live activation requires coordination.

The white paper specifies a 30-day block delay, or 1,296,000 blocks at two seconds
per block. Legacy clients accepted proposals with a 500,000-block delay measured
from the canonical parent. Replacing that constant globally would invalidate
historical transactions and change replayed state roots.

Persist an independent optional `algorithm_timelock_activation_height` in the
existing chain configuration. Keep legacy validation before that height and when
it is absent. At and after the selected block, each activation vote must leave
1,296,000 blocks from the executing header number. Reject overflow. The explicit
header context prevents a later chain tip from changing historical validation.
The convenience native-call API derives the next block from its supplied store;
block execution always supplies its header directly.

Reuse existing atomic startup scheduling and trusted snapshot validation. Existing
chains can add only a future schedule, and saved schedules cannot be altered.
No genesis default or online activation height changes. Existing accepted proposals
are not rescheduled, and the activation processor remains unchanged. Every vote
still undergoes timelock validation, so operators must finish pending shorter-delay
voting rounds before this upgrade or propose sufficient headroom beforehand.

The seven-day voting window, complete proposal identity and emergency signature
policy are separate protocol gaps. This change closes only the configurable
minimum-delay requirement; it does not claim complete algorithm-governance parity.

Verification covers legacy and target boundaries, invalid votes leaving state
unchanged, configuration persistence and conflicts, snapshot trust, and historical
RPC replay after the canonical head has crossed the upgrade boundary.
