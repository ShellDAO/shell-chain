#!/bin/bash
#
# pr-review-checks.sh — Local pre-push PR review checks
#
# This script runs the same checks that are automatically executed by the
# GitHub Actions workflow at .github/workflows/pr-review.yml whenever a pull
# request is opened or updated. You can run it locally before pushing to catch
# issues early:
#
#   bash scripts/pr-review-checks.sh
#
# Requirements: cargo, cargo-audit (install with `cargo install cargo-audit`)

set -e

# Function to print messages in color
print_in_color() {
    local color="$1"
    local message="$2"
    echo -e "\e[${color}m${message}\e[0m"
}

# Run cargo fmt
print_in_color "32" "Running cargo fmt..."
cargo fmt -- --check
print_in_color "32" "cargo fmt passed."

# Run cargo clippy
print_in_color "32" "Running cargo clippy..."
cargo clippy -- -D warnings
print_in_color "32" "cargo clippy passed."

# Run tests
print_in_color "32" "Running tests..."
cargo test
print_in_color "32" "All tests passed."

# Check documentation
print_in_color "32" "Checking documentation..."
cargo doc --no-deps
print_in_color "32" "Documentation built successfully."

# Run security audit
print_in_color "33" "Running cargo audit..."
cargo audit
print_in_color "32" "Security audit completed."

# Build verification
print_in_color "32" "Verifying build..."
cargo build --release
print_in_color "32" "Build verification successful."

print_in_color "34" "All checks passed successfully!"  
