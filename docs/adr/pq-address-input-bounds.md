# Activate PQ address derivation input bounds independently

## Decision

Precompile 0x06 implements the whitepaper's algorithm-specific upper bound by
returning a zero word for an oversized public-key input. It still charges the
existing input-dependent gas before returning zero. The check limits input
shape; it does not establish cryptographic key validity or impose exact lengths.

Changing a contract-visible return value changes consensus execution. The
independent `pq_address_bounds_height` therefore defaults to absent and retains
legacy hashing until the candidate block reaches the configured height. It is
persisted in chain configuration, immutable once scheduled, and required to
match trusted configuration during state import. An existing chain may add only
a future schedule. Sharing another capability's activation would unexpectedly
change this precompile for operators who enabled that unrelated capability.

Ordinary contract execution and AA validation capture the same persisted gate.
Block import and historical replay select it using the block being executed.
The separate native PQADDR opcode retains its existing semantics. Network
activation and publication of a binary containing this change remain separate
operator actions.

## Verification

The focused tests cover upper bounds and gas, ordinary and AA contract calls,
schedule persistence and rejection before writes, and snapshot conflicts:

```sh
cargo test -p shell-pqvm pq_address_bounds
cargo test -p shell-cli pq_address_bounds
cargo test -p shell-storage pq_address_bounds
cargo test -p shell-node pq_address_bounds_signed
cargo test -p shell-node --features rocksdb pq_address_bounds_survives_process_exit
```
