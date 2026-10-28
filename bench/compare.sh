#!/usr/bin/env bash
# Benchmarks hushdns at one or more git refs, and optionally Technitium DNS
# Server, under the same load, then prints a Markdown comparison. The first
# target is the baseline the others are compared against.
#
#   bench/compare.sh v0.0.1 HEAD
#   bench/compare.sh --technitium v0.0.1
#   bench/compare.sh --technitium-only
#
# Every server forwards to the same local fake upstream and loads the same
# 100,000-domain blocklist. On machines with 4 or more CPUs the server runs
# on the first half of them and the load generator and upstream on the rest,
# so they don't compete for CPU. Technitium needs Docker.
#
# Options (or the matching environment variables):
#   --duration SECS      length of each run (DURATION, default 15)
#   --runs N             runs per scenario; the median is reported (RUNS, default 3)
#   --concurrency N      queries in flight (CONCURRENCY, default 64)
#   --warmup SECS        mixed load before measuring, not reported (WARMUP, default 5)
#   --scenarios LIST     comma-separated (SCENARIOS, default cached,blocked,forwarded,mixed)
#   --technitium         also benchmark Technitium, after the refs
#   --technitium-only    benchmark only Technitium
#   --out DIR            where results go (OUT, default a new temp directory)

set -euo pipefail

DURATION=${DURATION:-15}
RUNS=${RUNS:-3}
WARMUP=${WARMUP:-5}
CONCURRENCY=${CONCURRENCY:-64}
SCENARIOS=${SCENARIOS:-cached,blocked,forwarded,mixed}
BLOCKLIST_COUNT=${BLOCKLIST_COUNT:-100000}
TECHNITIUM_IMAGE=${TECHNITIUM_IMAGE:-technitium/dns-server:15.6.2@sha256:eb48ac5c135f4ab936b536f74f853d53e15ab39ef37fdbc9598a089b90d9f245}
OUT=${OUT:-}
technitium=false
refs=()

while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION=$2; shift 2 ;;
    --runs) RUNS=$2; shift 2 ;;
    --concurrency) CONCURRENCY=$2; shift 2 ;;
    --warmup) WARMUP=$2; shift 2 ;;
    --scenarios) SCENARIOS=$2; shift 2 ;;
    --technitium) technitium=true; shift ;;
    --technitium-only) technitium=true; refs=(); only_technitium=true; shift ;;
    --out) OUT=$2; shift 2 ;;
    -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) refs+=("$1"); shift ;;
  esac
done
if [ ${#refs[@]} -eq 0 ] && [ -z "${only_technitium:-}" ]; then
  echo "usage: $0 [options] REF... (see --help)" >&2
  exit 2
fi

ROOT=$(git rev-parse --show-toplevel)
OUT=${OUT:-$(mktemp -d)}
mkdir -p "$OUT/bin" "$OUT/results"
OUT=$(cd "$OUT" && pwd)
SERVER=127.0.0.1:5353
UPSTREAM=127.0.0.1:5300
LIST_PORT=8099

cpus=$(nproc)
if [ "$cpus" -ge 4 ]; then
  half=$((cpus / 2))
  SERVER_CPUS="0-$((half - 1))"
  LOAD_CPUS="$half-$((cpus - 1))"
  pin_server=(taskset -c "$SERVER_CPUS")
  pin_load=(taskset -c "$LOAD_CPUS")
else
  SERVER_CPUS=""
  pin_server=()
  pin_load=()
fi

pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  docker rm -f hushdns-bench-technitium >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Building the benchmark tool" >&2
cargo build --release --quiet --manifest-path "$ROOT/bench/Cargo.toml"
BENCH="$OUT/bin/hushdns-bench"
cp "$ROOT/bench/target/release/hushdns-bench" "$BENCH"

"$BENCH" blocklist --count "$BLOCKLIST_COUNT" "$OUT/blocklist.txt"
"${pin_load[@]}" "$BENCH" upstream --listen "$UPSTREAM" &
pids+=($!)

# Builds hushdns at a ref in its own worktree, sharing one target directory.
build_ref() {
  local ref=$1 dir="$OUT/src/$2"
  echo "Building hushdns at $ref" >&2
  rm -rf "$dir"
  git -C "$ROOT" worktree add --detach --force "$dir" "$ref" >/dev/null 2>&1
  CARGO_TARGET_DIR="$OUT/target" cargo build --release --locked --quiet --manifest-path "$dir/Cargo.toml"
  cp "$OUT/target/release/hushdns" "$OUT/bin/hushdns-$2"
  git -C "$ROOT" worktree remove --force "$dir"
}

# Runs every scenario against the server on $SERVER.
run_scenarios() {
  local label=$1 slug=$2 pid=$3
  local scenario run
  # Warms up caches, connection pools and, for Technitium, the .NET JIT.
  "${pin_load[@]}" "$BENCH" load --server "$SERVER" --scenario mixed --target "$label" \
    --duration-secs "$WARMUP" --concurrency "$CONCURRENCY" --blocklist-count "$BLOCKLIST_COUNT" \
    --out "$OUT/warmup-$slug.json" 2>/dev/null
  for scenario in ${SCENARIOS//,/ }; do
    for run in $(seq "$RUNS"); do
      "${pin_load[@]}" "$BENCH" load --server "$SERVER" --scenario "$scenario" --target "$label" \
        --duration-secs "$DURATION" --concurrency "$CONCURRENCY" --blocklist-count "$BLOCKLIST_COUNT" \
        --pid "$pid" --out "$OUT/results/$slug-$scenario-$run.json"
    done
  done
}

wait_ready() {
  # A blocked name answers NXDOMAIN once the list is loaded, and a normal one
  # answers NOERROR once forwarding works.
  "$BENCH" probe --server "$SERVER" --name "ads1.tracker1.hushbench" --rcode 3
  "$BENCH" probe --server "$SERVER" --name "ready.cached.hushbench" --rcode 0
}

bench_hushdns() {
  local ref=$1 slug
  slug=$(echo "$ref" | tr -c 'A-Za-z0-9._-' '-')
  build_ref "$ref" "$slug"
  cat > "$OUT/hushdns.toml" <<EOF
[server]
listen = ["$SERVER"]
[upstream]
servers = ["udp://$UPSTREAM"]
[blocking]
lists = ["$OUT/blocklist.txt"]
refresh_interval_secs = 0
[api]
enabled = false
EOF
  "${pin_server[@]}" "$OUT/bin/hushdns-$slug" --config "$OUT/hushdns.toml" 2>"$OUT/hushdns-$slug.log" &
  local pid=$!
  pids+=("$pid")
  wait_ready
  run_scenarios "hushdns $ref" "hushdns-$slug" "$pid"
  kill "$pid"
  wait "$pid" 2>/dev/null || true
}

bench_technitium() {
  echo "Starting Technitium ($TECHNITIUM_IMAGE)" >&2
  python3 -m http.server "$LIST_PORT" --bind 127.0.0.1 --directory "$OUT" >/dev/null 2>&1 &
  pids+=($!)
  local cpuset=()
  [ -n "$SERVER_CPUS" ] && cpuset=(--cpuset-cpus "$SERVER_CPUS")
  docker rm -f hushdns-bench-technitium >/dev/null 2>&1 || true
  docker run -d --name hushdns-bench-technitium --network host "${cpuset[@]}" \
    -e DNS_SERVER_ADMIN_PASSWORD=bench -e DNS_SERVER_DOMAIN=bench.local "$TECHNITIUM_IMAGE" >/dev/null

  local token="" i
  for i in $(seq 60); do
    token=$(curl -sf "http://127.0.0.1:5380/api/user/login?user=admin&pass=bench" \
      | python3 -c 'import sys, json; print(json.load(sys.stdin)["token"])' 2>/dev/null) && break
    sleep 1
  done
  [ -n "$token" ] || { echo "Technitium did not start" >&2; docker logs hushdns-bench-technitium >&2; exit 1; }

  # The same setup as hushdns: one plain UDP upstream, the same blocklist,
  # NXDOMAIN for blocked names, no DNSSEC validation (hushdns doesn't
  # validate, and the fake upstream has no signatures), and no per-client
  # rate limit for the load generator on localhost.
  curl -sf -X POST http://127.0.0.1:5380/api/settings/set \
    --data-urlencode "token=$token" \
    --data-urlencode "dnsServerLocalEndPoints=$SERVER" \
    --data-urlencode "recursion=Allow" \
    --data-urlencode "forwarders=$UPSTREAM" \
    --data-urlencode "forwarderProtocol=Udp" \
    --data-urlencode "dnssecValidation=false" \
    --data-urlencode "enableBlocking=true" \
    --data-urlencode "blockingType=NxDomain" \
    --data-urlencode "blockListUrls=http://127.0.0.1:$LIST_PORT/blocklist.txt" \
    --data-urlencode "qpmLimitBypassList=127.0.0.0/8" >/dev/null
  curl -sf "http://127.0.0.1:5380/api/settings/forceUpdateBlockLists?token=$token" >/dev/null

  wait_ready
  local version pid
  version=$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' hushdns-bench-technitium)
  pid=$(docker inspect -f '{{.State.Pid}}' hushdns-bench-technitium)
  run_scenarios "Technitium ${version:-latest}" technitium "$pid"
  docker rm -f hushdns-bench-technitium >/dev/null
}

baseline=""
for ref in "${refs[@]}"; do
  bench_hushdns "$ref"
  baseline=${baseline:-"hushdns $ref"}
done
if $technitium; then
  bench_technitium
  if [ -z "$baseline" ]; then
    baseline=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["target"])' "$(ls "$OUT"/results/technitium-*.json | head -1)")
  fi
fi

{
  echo "## Benchmark"
  echo
  echo "$CONCURRENCY queries in flight over UDP, ${DURATION}s per run after a ${WARMUP}s warm-up, median of $RUNS runs, a ${BLOCKLIST_COUNT}-domain blocklist. Peak memory is the highest resident size the server reached so far."
  echo "Server on CPUs ${SERVER_CPUS:-shared}, load generator and upstream on ${LOAD_CPUS:-shared}, $(nproc) CPUs in total ($(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'))."
  echo
  "$BENCH" report --baseline "$baseline" "$OUT"/results/*.json
} | tee "$OUT/report.md"
echo >&2
echo "Results are in $OUT" >&2
