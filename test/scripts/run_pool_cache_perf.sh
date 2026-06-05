#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

VPP_BIN="${VPP_BIN:-build-root/build-vpp-native/vpp/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-build-root/build-vpp-native/vpp/bin/vppctl}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/results}"
if [ "$#" -gt 1 ]; then
  echo "usage: $0 [output-csv]" >&2
  exit 2
fi
OUTPUT_CSV="${1:-${OUTPUT_CSV:-$RESULTS_DIR/pool-cache-perf.csv}}"
ROUNDS="${ROUNDS:-2000}"
WARMUP_ROUNDS="${WARMUP_ROUNDS:-100}"
SAMPLES="${SAMPLES:-30}"
BATCH_SIZES="${BATCH_SIZES:-32 256 1024}"
LOG2_SUBPOOL_SIZE="${LOG2_SUBPOOL_SIZE:-12}"
REBUILD="${REBUILD:-1}"
MULTIWORKER_MODE="${MULTIWORKER_MODE:-all}"

vpp_pid=""

absolute_path() {
  case "$1" in
  /*) printf "%s\n" "$1" ;;
  *) printf "%s/%s\n" "$ROOT_DIR" "$1" ;;
  esac
}

stop_vpp() {
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" 2>/dev/null; then
    kill "$vpp_pid" 2>/dev/null || true
    wait "$vpp_pid" 2>/dev/null || true
  fi
  vpp_pid=""
}

trap stop_vpp EXIT INT TERM

if [ "$REBUILD" = "1" ]; then
  ninja -C build-root/build-vpp-native/vpp unittest_plugin.so
fi

OUTPUT_CSV="$(absolute_path "$OUTPUT_CSV")"
mkdir -p "$(dirname "$OUTPUT_CSV")"

write_startup_config() {
  local workers="$1"
  local corelist="$2"
  local log2_subpool_size="$3"
  local config="$4"
  local runtime_dir="$5"
  local api_prefix="pool-cache-perf-log2-${log2_subpool_size}-${workers}w-$$"

  {
    printf "unix {\n"
    printf "  interactive\n"
    printf "  full-coredump\n"
    printf "  runtime-dir %s\n" "$runtime_dir"
    printf "  cli-listen %s/cli.sock\n" "$runtime_dir"
    printf "}\n\n"
    printf "api-segment {\n"
    printf "  prefix %s\n" "$api_prefix"
    printf "}\n\n"
    printf "cpu {\n"
    printf "  main-core 1\n"
    if [ -n "$corelist" ]; then
      printf "  corelist-workers %s\n" "$corelist"
    fi
    printf "}\n\n"
    printf "physmem {\n"
    printf "  max-size 64m\n"
    printf "}\n\n"
    printf "plugins {\n"
    printf "  plugin default { disable }\n"
    printf "  plugin unittest_plugin.so {\n"
    printf "    enable\n"
    printf "  }\n"
    printf "}\n"
  } >"$config"
}

wait_for_cli() {
  local sock="$1"
  local i

  for i in $(seq 1 100); do
    if [ -S "$sock" ] && "$VPPCTL_BIN" -s "$sock" show version >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done

  return 1
}

# run_worker_count <output_csv> <workers> <corelist> <log2_subpool_size> <modes> <batch_sizes>
run_worker_count() {
  local output_csv="$1"
  local workers="$2"
  local corelist="$3"
  local log2_subpool_size="$4"
  local mode_list="$5"
  local batch_list="$6"
  local run_tag="pool-cache-perf-log2-${log2_subpool_size}-${workers}w-$$"
  local runtime_dir="/tmp/${run_tag}"
  local config="/tmp/${run_tag}.conf"
  local sock="$runtime_dir/cli.sock"
  local log="/tmp/${run_tag}.vpp.log"
  local batch mode cmd

  output_csv="$(absolute_path "$output_csv")"
  rm -f "$log"
  write_startup_config "$workers" "$corelist" "$log2_subpool_size" "$config" "$runtime_dir"

  echo "==> starting VPP for ${workers} workers"
  "$VPP_BIN" -c "$config" >"$log" 2>&1 &
  vpp_pid="$!"

  if ! wait_for_cli "$sock"; then
    echo "VPP did not become ready for ${workers} workers. Log: $log" >&2
    return 1
  fi

  "$VPPCTL_BIN" -s "$sock" show threads

  for batch in $batch_list; do
    for mode in $mode_list; do
      cmd="test pool-cache perf mode $mode rounds $ROUNDS batch-size $batch warmup-rounds $WARMUP_ROUNDS samples $SAMPLES log2-subpool-size $log2_subpool_size csv $output_csv"
      echo "==> ${workers}w batch=${batch} mode=${mode}"
      "$VPPCTL_BIN" -s "$sock" "$cmd"
    done
  done

  stop_vpp
  wc -l "$output_csv"
}

#run_worker_count "$OUTPUT_CSV" 0 "" "$LOG2_SUBPOOL_SIZE" "local refill" "$BATCH_SIZES"
run_worker_count "$OUTPUT_CSV" 2 "2,3" "$LOG2_SUBPOOL_SIZE" "$MULTIWORKER_MODE" "$BATCH_SIZES"
run_worker_count "$OUTPUT_CSV" 4 "2,3,4,5" "$LOG2_SUBPOOL_SIZE" "$MULTIWORKER_MODE" "$BATCH_SIZES"
run_worker_count "$OUTPUT_CSV" 8 "2,3,4,5,6,7,8,9" "$LOG2_SUBPOOL_SIZE" "$MULTIWORKER_MODE" "$BATCH_SIZES"

echo "==> appended results to $OUTPUT_CSV"
wc -l "$OUTPUT_CSV"
