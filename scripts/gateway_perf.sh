#!/usr/bin/env bash
# Gateway performance measurement (docs/gateway/PERFORMANCE_RESULTS.md).
#
# Runs the #[ignore] perf suite in release mode against LOCAL synthetic
# upstreams and prints the structured PERF lines. No network egress, no
# real credentials, nothing installed. Numbers are machine-dependent —
# record the machine next to them.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "machine: $(uname -srm)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
cargo test -p api-tracker-gateway --test perf --release -- \
  --ignored --nocapture --test-threads=1 2>&1 | grep -E "PERF|test result"
