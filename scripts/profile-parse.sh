#!/bin/bash
# Profile dependency parsing operations with cargo-flamegraph
#
# Usage:
#   ./scripts/profile-parse.sh [FILE] [ITERATIONS]
#
# Examples:
#   ./scripts/profile-parse.sh tests/fixtures/cargo_50_deps.toml 1000
#   ./scripts/profile-parse.sh tests/fixtures/package_100_deps.json 1000

set -e

cd "$(dirname "$0")/.."

FILE="${1:-tests/fixtures/cargo_50_deps.toml}"
ITERATIONS="${2:-1000}"

if [ ! -f "$FILE" ]; then
    echo "Error: File not found: $FILE"
    exit 1
fi

echo "==================================="
echo "Profiling: Parse Operations"
echo "==================================="
echo "File: $FILE"
echo "Iterations: $ITERATIONS"
echo ""

# Check if flamegraph is installed
if ! command -v flamegraph &> /dev/null; then
    echo "Error: flamegraph not found. Install with: cargo install flamegraph"
    exit 1
fi

# Build release binary first
echo "Building release binary..."
cargo build --release --package depsy-lsp

# Generate flame graph
echo "Generating flame graph..."
flamegraph -o flamegraph-parse.svg -- \
    ./target/release/depsy-lsp profile-parse \
    --file "$FILE" \
    --iterations "$ITERATIONS"

echo ""
echo "Flame graph generated: flamegraph-parse.svg"

# Open in browser if possible
if command -v xdg-open &> /dev/null; then
    xdg-open flamegraph-parse.svg
elif command -v open &> /dev/null; then
    open flamegraph-parse.svg
else
    echo "Open flamegraph-parse.svg in your browser to view the profile"
fi
