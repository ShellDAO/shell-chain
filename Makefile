.PHONY: bench bench-quick test ci invariant-network invariant-hash-signing invariant-aa-paymaster invariant-stark-pruning invariant-rpc e2e e2e-extended load-test chaos-test security-audit

# Run workspace Rust quality checks before every push.
ci:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace

# Run full criterion benchmarks for all workspace crates
bench:
	cargo bench --workspace

# Quick compile-check for benchmarks (no actual measurement)
bench-quick:
	cargo bench --workspace -- --test

# Run all workspace tests
test:
	cargo test --workspace --tests

# Focused protocol invariant packs for faster pre-CI checks.
invariant-network:
	cargo test -p shell-network message::tests::
	cargo test -p shell-network bandwidth::tests::

invariant-hash-signing:
	cargo test -p shell-primitives hash
	cargo test -p shell-primitives address
	cargo test -p shell-crypto signature
	cargo test -p shell-core sdk_hash_transaction_golden_vector_matches_chain

invariant-aa-paymaster:
	cargo test -p shell-node aa
	cargo test -p shell-rpc paymaster

invariant-stark-pruning:
	cargo test -p shell-node stark
	cargo test -p shell-node pruning
	cargo test -p shell-storage prun

invariant-rpc:
	cargo test -p shell-rpc rpc_
	cargo test -p shell-rpc witness

# E2E test suites (require Docker)
e2e:
	./tests/e2e/run-e2e.sh

e2e-extended:
	./tests/e2e/run-extended.sh

load-test:
	./tests/e2e/run-load-test.sh

chaos-test:
	./tests/e2e/run-chaos-test.sh

security-audit:
	./tests/e2e/run-security-audit.sh
