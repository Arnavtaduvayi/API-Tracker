#!/usr/bin/env bash
# Tethra Mesh simulator soak (docs/mesh/TEST_PLAN.md).
#
# Runs the ignored `soak` test of crates/core/tests/mesh_sim.rs in release
# mode, in batches of fresh seeds, and prints any failing seed as
# `MESH_SIM_SEED=<seed> MESH_SIM_STEPS=<steps>` for replay with:
#   MESH_SIM_SEED=<seed> MESH_SIM_STEPS=<steps> \
#     cargo test -p api-tracker-core --test mesh_sim replay
#
# Usage:
#   scripts/mesh_soak.sh --seeds 5000           # a fixed number of seeds
#   scripts/mesh_soak.sh --minutes 10           # as many batches as fit
#   options: --start <first seed> (default 1000000), --steps <n> (default 3000),
#            --batch <seeds per batch> (default 1000)
#
# Pure computation: no network, no data directory, nothing outside target/.
set -euo pipefail

seeds=""
minutes=""
start=1000000
steps=3000
batch=1000

while [ $# -gt 0 ]; do
  case "$1" in
    --seeds) seeds="$2"; shift 2 ;;
    --minutes) minutes="$2"; shift 2 ;;
    --start) start="$2"; shift 2 ;;
    --steps) steps="$2"; shift 2 ;;
    --batch) batch="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$seeds" ] && [ -z "$minutes" ]; then
  echo "give --seeds <n> or --minutes <m>" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
echo "building the simulator (release)..."
cargo test --release -p api-tracker-core --test mesh_sim --no-run >/dev/null

run_batch() {
  local first="$1" count="$2"
  MESH_SIM_SEEDS="$count" MESH_SIM_START="$first" MESH_SIM_STEPS="$steps" \
    cargo test --release -p api-tracker-core --test mesh_sim soak -- --ignored --nocapture 2>&1 \
    | grep -E "mesh soak:|SOAK-FAIL" || true
}

failed=0
total=0
began=$(date +%s)
next="$start"
while :; do
  if [ -n "$seeds" ]; then
    remaining=$((seeds - total))
    [ "$remaining" -le 0 ] && break
    count=$(( remaining < batch ? remaining : batch ))
  else
    now=$(date +%s)
    [ $((now - began)) -ge $((minutes * 60)) ] && break
    count="$batch"
  fi
  out="$(run_batch "$next" "$count")"
  echo "$out"
  if echo "$out" | grep -q "SOAK-FAIL"; then
    failed=$((failed + $(echo "$out" | grep -c "SOAK-FAIL")))
  fi
  total=$((total + count))
  next=$((next + count))
done

elapsed=$(( $(date +%s) - began ))
echo "mesh soak done: $total seeds ($steps steps each) from $start in ${elapsed}s; failing seeds: $failed"
[ "$failed" -eq 0 ]
