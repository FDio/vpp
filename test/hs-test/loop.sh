#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: loop.sh [--debug]

Repeat the full hs-test run until a test or cleanup fails, or Ctrl+C is pressed.
Each run starts with test-wipe and uses PARALLEL=auto MW_PARALLEL=true.
Make output is saved to a temporary log, reused for each run. On failure,
failed test names are listed from summary/report.json when jq is available.
Ctrl+C skips the failure summary and runs cleanup-hst before exiting.

  -d, --debug  Use the VPP debug build (test-debug; default: test).
  -h, --help   Show this help.
EOF
}

handle_interrupt() {
    local cleanup_status

    # Let cleanup finish even if Ctrl+C is pressed again.
    trap '' INT
    printf '\nInterrupted; running cleanup-hst...\n' >&2
    if make -C "$hs_root" cleanup-hst >>"$log_file" 2>&1; then
        printf 'Container cleanup complete. Full output: %s\n' "$log_file" >&2
    else
        cleanup_status=$?
        printf 'Container cleanup failed (exit %d); see %s.\n' \
            "$cleanup_status" "$log_file" >&2
    fi
    exit 130
}

target='test'
for arg in "$@"; do
    case "$arg" in
        -d|--debug) target='test-debug' ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
    esac
done

hs_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
log_file=$(mktemp "${TMPDIR:-/tmp}/hs-test-loop.XXXXXX.log")
trap handle_interrupt INT
printf 'Full output: %s\n' "$log_file"
run=1

while true; do
    printf '\n=== hs-test run %d (%s) ===\n' "$run" "$target"
    if make -C "$hs_root" test-wipe >"$log_file" 2>&1; then
        :
    else
        status=$?
        if (( status == 130 )); then
            handle_interrupt
        fi
        printf 'Cleanup failed (exit %d); see %s.\n' "$status" "$log_file" >&2
        exit "$status"
    fi

    if make -C "$hs_root" "$target" PARALLEL=auto MW_PARALLEL=true >>"$log_file" 2>&1; then
        printf 'hs-test run %d passed.\n' "$run"
    else
        status=$?
        # Docker may forward Ctrl+C only to Ginkgo, leaving make to return a
        # normal error status without delivering SIGINT to this script.
        if (( status == 130 )) || jq -e '
            any(.[];
                any(.SpecialSuiteFailureReasons[]?; . == "Interrupted by User") or
                any(.SpecReports[]?;
                    .State == "interrupted" and .Failure.Message == "Interrupted by User"))
        ' "$hs_root/summary/report.json" >/dev/null 2>&1; then
            handle_interrupt
        fi
        printf 'hs-test run %d failed (exit %d); stopping without wiping its logs.\n' \
            "$run" "$status" >&2
        if failed_tests=$(jq -r '
            [.[] | .SpecReports[] |
                select(.State == "failed" or .State == "timedout" or
                    .State == "panicked" or .State == "aborted" or
                    .State == "interrupted") |
                ([.ContainerHierarchyTexts[]?,
                    (if .LeafNodeText == "" then .LeafNodeType else .LeafNodeText end)] |
                    join(" "))] | unique[]
        ' "$hs_root/summary/report.json" 2>/dev/null) && [[ -n "$failed_tests" ]]; then
            printf 'Failed tests:\n%s\n' "$failed_tests" >&2
        else
            printf 'No failed-test list available.\n' >&2
        fi
        printf 'Full output: %s\n' "$log_file" >&2
        exit "$status"
    fi

    run=$((run + 1))
done
