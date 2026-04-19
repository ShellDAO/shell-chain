.PHONY: bench bench-quick test ci e2e e2e-extended load-test chaos-test security-audit

# Mirror CI checks exactly (run before every push)
ci:
	cargo fmt --all -- --check
	cargo clippy --workspace -- -D warnings
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
