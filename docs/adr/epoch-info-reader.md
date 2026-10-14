# Canonical epoch information reader

Status: accepted for unreleased node source

The published no-argument epoch query needs a real RPC registration and values
from the canonical chain and active consensus engine. The illustrative epoch
number five with epoch length zero is inconsistent with existing continuous
epoch semantics and must not become a fixed return value.

Read the captured head header, verify its canonical mapping, and use the existing
consensus epoch calculation for that head height. Do not use the next proposer
slot or introduce a separate epoch schedule. A zero length keeps epoch zero and
reports the head height as the block offset since genesis.

Count active engine authorities rather than the head Registry, since pending
Registry changes can differ from the effective boundary state. Derive the mean
block interval from retained canonical timestamps over at most ten intervals,
matching the existing chain-statistics observation window. Genesis has no
interval and reports zero. Missing context or retained headers is an error.

No new database fields, query writes, consensus activation, or signature changes
are needed. Separate engine and header reads do not promise an atomic snapshot
across a concurrent epoch transition or reorganization. HTTP regressions cover
genesis, epoch boundaries, continuous epochs, pruned headers, terminal height,
read-only results and missing context. The existing real signed execution/import
fixture also checks the query after body pruning and fresh-process RocksDB
recovery with continuous epochs. The two-node Registry acceptance additionally
checks real ML-DSA-65 weight, addition and removal transactions with length-five
epochs and graceful follower restarts between boundaries. Active member counts
must survive restart independently of pending head Registry changes. This does
not establish multi-authority availability, network reorganization or machine
power-loss recovery.
