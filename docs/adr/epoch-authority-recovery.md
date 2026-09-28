# Epoch authority recovery

## Problem

The consensus guide makes Registry changes effective only at epoch boundaries.
At a mid-epoch restart, the builder retained genesis authorities. Reopening the
head Registry instead would also be wrong because it may contain pending
membership or weight changes. A real two-node sequence with epoch length five
activated weight three at block five and queued weight five at block six; a
caught-up follower restarted at block seven with weight one.

## Decision

Derive the last reload height from the executed canonical head and configured
epoch length. Boundary heads use the existing reload path. Between boundaries,
load the canonical boundary header, verify its number/hash, validate its state,
and install only that snapshot's Registry members and weights in consensus.
Keep head world state unchanged. Zero-length epochs retain per-block behavior.

Missing canonical history, unavailable state or an empty historical Registry
is a startup error, never a reason to substitute genesis or pending head state.
Old block bodies are unnecessary. Existing nodes or trusted snapshots whose
required boundary state has already been pruned need a suitable recovery
snapshot; this change cannot recreate deleted state. Consensus parameters must
match the original chain configuration.

Cap rolling trie pruning at the most recent finalized epoch boundary. This
retains its canonical mapping and state, including while a newer unfinalized
head is in another epoch. It preserves valid rollback/reorg recovery without
adding a second unauthenticated authority cache or new snapshot fields. The
retained state window can exceed keep_recent by the current epoch; operators
must account for their configured epoch length. Finalization of the next
boundary releases the previous window. Other retention rules remain in force.

## Validation and limits

Startup regressions distinguish active members from pending additions/removals
and weights, cover body-pruned history and reject missing boundary data without
writes. Pruning regression retains the finalized boundary beneath a newer head
and releases it after finalization advances. The portable Registry script runs
real signed changes on independent producer/follower nodes through multiple
boundaries and idle-tip restarts. The running consensus rules are unchanged;
no protocol activation or public package release is performed. Persistence of
off-chain slashing evidence and other transient consensus state is separate.
