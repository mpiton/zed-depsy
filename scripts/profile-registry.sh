#!/bin/bash
# Profile registry request operations with cargo-flamegraph
#
# Usage:
#   ./scripts/profile-registry.sh [REGISTRY] [PACKAGES] [ITERATIONS]
#
# Examples:
#   ./scripts/profile-registry.sh npm "lodash,express,react" 5
#   ./scripts/profile-registry.sh crates "serde,tokio,reqwest" 5

set -e

cd "$(dirname "$0")/.."

REGISTRY="${1:-npm}"
PACKAGES="${2:-lodash,express,react,axios,moment}"
ITERATIONS="${3:-5}"

echo "==================================="
echo "Profiling: Registry Requests"
echo "==================================="
echo "Registry: $REGISTRY"
echo "Packages: $PACKAGES"
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
flamegraph -o flamegraph-registry.svg -- \
    ./target/release/depsy-lsp profile-registry \
    --registry "$REGISTRY" \
    --packages "$PACKAGES" \
    --iterations "$ITERATIONS"

echo ""
echo "Flame graph generated: flamegraph-registry.svg"

# Open in browser if possible
if command -v xdg-open &> /dev/null; then
    xdg-open flamegraph-registry.svg
elif command -v open &> /dev/null; then
    open flamegraph-registry.svg
else
    echo "Open flamegraph-registry.svg in your browser to view the profile"
fi
