#!/bin/bash
# Run benchmarks and generate reports
#
# Usage:
#   ./run-benchmarks.sh              # Run all benchmarks
#   ./run-benchmarks.sh parsers      # Run only parser benchmarks
#   ./run-benchmarks.sh --baseline   # Save results as baseline
#   ./run-benchmarks.sh --compare    # Compare against baseline

set -e

SCRIPT_DIR="$(dirname "$0")"
cd "$SCRIPT_DIR/depsy-lsp"

BASELINE_FLAG=""
FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --baseline)
            BASELINE_FLAG="-- --save-baseline main"
            shift
            ;;
        --compare)
            BASELINE_FLAG="-- --baseline main"
            shift
            ;;
        *)
            FILTER="$1"
            shift
            ;;
    esac
done

echo "Running benchmarks..."

if [ -n "$FILTER" ]; then
    echo "Filter: $FILTER"
    cargo bench --bench benchmarks -- "$FILTER" $BASELINE_FLAG
else
    cargo bench --bench benchmarks $BASELINE_FLAG
fi

echo ""
echo "Benchmark complete!"
echo "Report available at: target/criterion/report/index.html"

# Open report in browser (optional)
if command -v xdg-open &> /dev/null; then
    echo "Opening report in browser..."
    xdg-open target/criterion/report/index.html 2>/dev/null || true
elif command -v open &> /dev/null; then
    echo "Opening report in browser..."
    open target/criterion/report/index.html 2>/dev/null || true
fi
