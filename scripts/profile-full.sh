#!/bin/bash
# Profile full document processing workflow with cargo-flamegraph
#
# Usage:
#   ./scripts/profile-full.sh [FILE] [ITERATIONS]
#
# Examples:
#   ./scripts/profile-full.sh tests/fixtures/package_100_deps.json 5
#   ./scripts/profile-full.sh tests/fixtures/cargo_50_deps.toml 5

set -e

cd "$(dirname "$0")/.."

FILE="${1:-tests/fixtures/package_100_deps.json}"
ITERATIONS="${2:-5}"

if [ ! -f "$FILE" ]; then
    echo "Error: File not found: $FILE"
    exit 1
fi

echo "==================================="
echo "Profiling: Full Workflow"
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
flamegraph -o flamegraph-full.svg -- \
    ./target/release/depsy-lsp profile-full \
    --file "$FILE" \
    --iterations "$ITERATIONS"

echo ""
echo "Flame graph generated: flamegraph-full.svg"

# Open in browser if possible
if command -v xdg-open &> /dev/null; then
    xdg-open flamegraph-full.svg
elif command -v open &> /dev/null; then
    open flamegraph-full.svg
else
    echo "Open flamegraph-full.svg in your browser to view the profile"
fi
