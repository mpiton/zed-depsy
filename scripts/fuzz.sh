#!/bin/bash
# Fuzz testing script for depsy-lsp parsers
#
# Usage:
#   ./scripts/fuzz.sh              # Run all fuzz targets (30 seconds each)
#   ./scripts/fuzz.sh cargo        # Run specific target
#   ./scripts/fuzz.sh cargo 300    # Run target for 5 minutes
#   ./scripts/fuzz.sh --list       # List available targets

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FUZZ_DIR="$PROJECT_ROOT/depsy-lsp/fuzz"

# Available fuzz targets
TARGETS=("cargo" "npm" "python" "go" "ruby" "php" "dart" "csharp")

# Default timeout per target (seconds)
DEFAULT_TIMEOUT=30

show_help() {
    echo "Fuzz testing for depsy-lsp parsers"
    echo ""
    echo "Usage:"
    echo "  $0                    Run all targets (${DEFAULT_TIMEOUT}s each)"
    echo "  $0 <target>           Run specific target (${DEFAULT_TIMEOUT}s)"
    echo "  $0 <target> <seconds> Run target for specified time"
    echo "  $0 --list             List available targets"
    echo "  $0 --help             Show this help"
    echo ""
    echo "Available targets:"
    for t in "${TARGETS[@]}"; do
        echo "  - $t"
    done
    echo ""
    echo "Requirements:"
    echo "  - Rust nightly toolchain"
    echo "  - cargo-fuzz: cargo install cargo-fuzz"
}

check_requirements() {
    if ! command -v cargo &> /dev/null; then
        echo "Error: cargo not found"
        exit 1
    fi

    if ! cargo +nightly --version &> /dev/null; then
        echo "Error: Rust nightly toolchain not found"
        echo "Install with: rustup toolchain install nightly"
        exit 1
    fi

    if ! cargo fuzz --version &> /dev/null 2>&1; then
        echo "Error: cargo-fuzz not found"
        echo "Install with: cargo install cargo-fuzz"
        exit 1
    fi
}

run_target() {
    local target=$1
    local timeout=$2

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Fuzzing: fuzz_$target (${timeout}s)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    cd "$FUZZ_DIR"

    # Run fuzzer with timeout
    cargo +nightly fuzz run "fuzz_$target" \
        -- \
        -max_total_time="$timeout" \
        -timeout=30 \
        2>&1 || true

    echo "Completed: fuzz_$target"
}

# Parse arguments
case "${1:-}" in
    --help|-h)
        show_help
        exit 0
        ;;
    --list|-l)
        echo "Available fuzz targets:"
        for t in "${TARGETS[@]}"; do
            echo "  fuzz_$t"
        done
        exit 0
        ;;
esac

check_requirements

if [ -n "${1:-}" ]; then
    # Run specific target
    TARGET="$1"
    TIMEOUT="${2:-$DEFAULT_TIMEOUT}"

    # Validate target
    valid=false
    for t in "${TARGETS[@]}"; do
        if [ "$t" = "$TARGET" ]; then
            valid=true
            break
        fi
    done

    if [ "$valid" = false ]; then
        echo "Error: Unknown target '$TARGET'"
        echo "Run '$0 --list' to see available targets"
        exit 1
    fi

    run_target "$TARGET" "$TIMEOUT"
else
    # Run all targets
    echo "Running all fuzz targets (${DEFAULT_TIMEOUT}s each)..."

    for target in "${TARGETS[@]}"; do
        run_target "$target" "$DEFAULT_TIMEOUT"
    done
fi

echo ""
echo "Fuzzing complete!"
echo ""

# Check for crashes
if [ -d "$FUZZ_DIR/artifacts" ] && [ "$(ls -A "$FUZZ_DIR/artifacts" 2>/dev/null)" ]; then
    echo "WARNING: Crash artifacts found in $FUZZ_DIR/artifacts/"
    ls -la "$FUZZ_DIR/artifacts/"
else
    echo "No crashes found."
fi
