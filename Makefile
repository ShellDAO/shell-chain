# Makefile

# Set the name of the cargo project
PROJECT_NAME = shell-chain

# Target to format the code
fmt:
	cargo fmt

# Target to run clippy
clippy:
	cargo clippy

# Target to run tests
test:
	cargo test

# Target to build documentation
doc:
	cargo doc

# Target to build the project
build:
	cargo build

# Target to clean the project
clean:
	cargo clean

# Combined target to check all
check-all: fmt clippy test
	@echo "All checks passed!"
