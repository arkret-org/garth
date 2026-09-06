#!/usr/bin/env sh
# Run this repository's verification locally, because nothing else runs it.
#
# `.github/workflows/ci.yml` already carries the right commands. It has never
# been the gate: GitHub Actions is disabled at the repository level across all
# eleven repositories (`repos/arkret-org/garth/actions/permissions` reports
# `"enabled": false`; four runs exist in total, all historical). A workflow that
# cannot run is documentation, so this script is the executable copy.
#
# The feature flag is the whole point. `default = []`, and
# `tests/file_store_noop.rs` opens with
# `#![cfg(all(feature = "native", not(target_arch = "wasm32")))]`. Under a plain
# `cargo test` that file compiles to nothing, the runner prints
# `running 0 tests`, and the suite passes — a green that measured nothing. This
# script runs the native feature set and then checks that the integration suite
# actually selected tests, so the same silence cannot come back.
#
# Usage:
#   scripts/gate.sh          # check, clippy, test (native) + wasm check
#   scripts/gate.sh --quick  # skip the wasm target check

set -eu

quick=0
if [ "${1:-}" = "--quick" ]; then
    quick=1
fi

cd "$(dirname "$0")/.."

echo "==> cargo check --features native"
cargo check --features native

echo "==> cargo clippy --features native --all-targets -- -D warnings"
cargo clippy --features native --all-targets -- -D warnings

echo "==> cargo test --features native"
test_log=$(mktemp)
trap 'rm -f "$test_log"' EXIT
cargo test --features native 2>&1 | tee "$test_log"

# The anti-silence check. `cargo test` reports each target separately, so a
# feature-gated integration file that compiled to nothing still contributes a
# passing `0 tests` line. Counting the tests the integration targets actually
# ran is the difference between "the suite is green" and "the suite ran".
integration_tests=$(
    awk '
        /^ *Running tests[\\\/]/ { in_integration = 1; next }
        /^ *Running (unittests|benches)/ { in_integration = 0; next }
        /^ *Doc-tests/ { in_integration = 0; next }
        in_integration && /^test result:/ {
            for (i = 1; i <= NF; i++) {
                if ($(i + 1) ~ /^passed/) { total += $i }
            }
        }
        END { print total + 0 }
    ' "$test_log"
)

echo "==> integration tests executed: $integration_tests"
if [ "$integration_tests" -eq 0 ]; then
    echo "FATAL: every integration target ran zero tests." >&2
    echo "       The suite is green because nothing was selected, not because" >&2
    echo "       anything passed. Check the feature gates on tests/*.rs." >&2
    exit 1
fi

if [ "$quick" -eq 0 ]; then
    echo "==> cargo check --target wasm32-unknown-unknown --no-default-features --features wasm"
    cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
fi

echo "gate: PASS ($integration_tests integration tests executed)"
