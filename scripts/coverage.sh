#!/bin/bash
# Generate test coverage report with cargo-tarpaulin
set -e

cd "$(dirname "$0")/../depsy-lsp"

echo "Running test coverage analysis..."

# Create output directory
mkdir -p ../coverage

# Run coverage
cargo tarpaulin \
    --out Html \
    --out Json \
    --output-dir ../coverage \
    --timeout 300 \
    ${FAIL_UNDER:+--fail-under "$FAIL_UNDER"}

echo "Coverage report generated!"
echo "Open: coverage/tarpaulin-report.html"
