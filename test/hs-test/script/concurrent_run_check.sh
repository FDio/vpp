#!/usr/bin/env bash
# Checks that two hs-test runs can execute at the same time without interfering.
#
# Runs the same test twice concurrently under two different RUN_IDs and reports
# whether each run got its own containers and its own log/volume directory.
#
# It deliberately skips 'make build': the two runs would otherwise rebuild the
# same docker image tags and, from a single checkout, the same VPP build tree.
# Build first (make build), then run this.
#
# This checks the isolation of two runs, not of two checkouts. Testing one commit
# twice is enough to show that two runs do not collide. Running two different VPP
# versions side by side additionally needs per-run docker image tags, which do not
# exist yet - both runs here share whatever images the checkout built.
#
# Usage: script/concurrent_run_check.sh [test-name] [run-id-a] [run-id-b]

set -u

TEST_NAME=${1:-VppEchoTcpTest}
RUN_A=${2:-checkA}
RUN_B=${3:-checkB}
OUT_DIR=$(mktemp -d)

cd "$(dirname "$0")/.." || exit 1
HS_ROOT=$PWD
export HS_ROOT

if [ ! -f .build.ok ]; then
    echo "No .build.ok - run 'make build' first." >&2
    exit 1
fi

# Ask make what it would run, so this script cannot drift from the real recipe.
# stdin is redirected because the Makefile adds 'docker run -it' when it sees a
# terminal, and the two runs below are backgrounded and so have no terminal.
for run_id in "$RUN_A" "$RUN_B"; do
    if ! make RUN_ID="$run_id" TEST="$TEST_NAME" -n test 2>/dev/null < /dev/null |
            grep '^docker run' | head -1 > "$OUT_DIR/cmd-$run_id.sh"; then
        echo "Could not determine the docker command for RUN_ID=$run_id" >&2
        exit 1
    fi
    if [ ! -s "$OUT_DIR/cmd-$run_id.sh" ]; then
        echo "make -n produced no docker command for RUN_ID=$run_id" >&2
        exit 1
    fi
done

echo "Running $TEST_NAME concurrently as '$RUN_A' and '$RUN_B'..."

bash "$OUT_DIR/cmd-$RUN_A.sh" > "$OUT_DIR/$RUN_A.log" 2>&1 < /dev/null &
pid_a=$!

# Both runs share this checkout, so both ginkgo invocations compile to - and on
# exit delete - the same hs-test.test. That is an artefact of testing from one
# checkout rather than two, and it is avoided by letting the first run get past
# compilation before starting the second. The tests themselves still overlap.
# Two separate checkouts do not need this.
for _ in $(seq 1 120); do
    if grep -qa "Running Suite" "$OUT_DIR/$RUN_A.log" 2>/dev/null; then
        break
    fi
    if ! kill -0 $pid_a 2>/dev/null; then
        break
    fi
    sleep 1
done

bash "$OUT_DIR/cmd-$RUN_B.sh" > "$OUT_DIR/$RUN_B.log" 2>&1 < /dev/null &
pid_b=$!

wait $pid_a; status_a=$?
wait $pid_b; status_b=$?

# logs can contain binary (core dumps, captures), so drop null bytes and force
# grep to treat the input as text - otherwise greps below silently match nothing
strip_colors() { tr -d '\0' < "$1" | sed 's/\x1b\[[0-9;]*m//g'; }

# Matches the per-test directory with or without the run token, so that a build
# that is missing the token is reported as a collision rather than as no data.
DIR_RE="/tmp/hst/[A-Za-z0-9_]+/[0-9]{6}_[0-9]{6}(-[0-9a-f]+)?"

report() {
    local run_id=$1 status=$2 log="$OUT_DIR/$1.log" text
    text=$(strip_colors "$log")

    echo
    echo "--- $run_id (exit $status)"
    echo "$text" | grep -aE "^(Ran [0-9]+ of|SUCCESS!|FAIL!)" | sed 's/^/    /'
    echo "    containers: $(containers_of "$run_id" | paste -sd' ')"
    echo "    log dir:    $(dirs_of "$run_id" | paste -sd' ')"
    echo "    log file:   $log"
}

# The isolation claim is that the two runs shared no container name and no
# per-test directory. Compare the sets rather than trusting the exit codes.
containers_of() {
    strip_colors "$OUT_DIR/$1.log" |
        grep -aoE "to container [a-zA-Z0-9_.-]+" | sed 's/to container //' | sort -u
}
dirs_of() {
    strip_colors "$OUT_DIR/$1.log" | grep -aoE "$DIR_RE" | sort -u
}

report "$RUN_A" $status_a
report "$RUN_B" $status_b

shared_containers=$(comm -12 <(containers_of "$RUN_A") <(containers_of "$RUN_B"))
shared_dirs=$(comm -12 <(dirs_of "$RUN_A") <(dirs_of "$RUN_B"))

echo
# A run that never created a container tells us nothing about isolation. Without
# this, two runs that both died on startup compare as "shared nothing" and would
# be reported as isolated.
for run_id in "$RUN_A" "$RUN_B"; do
    if [ -z "$(containers_of "$run_id")" ]; then
        echo "INCONCLUSIVE - '$run_id' started no containers, so there is nothing"
        echo "to compare. First lines of its log:"
        strip_colors "$OUT_DIR/$run_id.log" | head -5 | sed 's/^/    /'
        exit 1
    fi
done

if [ -n "$shared_containers" ]; then
    echo "NOT ISOLATED - both runs used these containers:"
    echo "$shared_containers" | sed 's/^/    /'
    exit 1
fi

if [ -n "$shared_dirs" ]; then
    echo "NOT ISOLATED - both runs used these directories:"
    echo "$shared_dirs" | sed 's/^/    /'
    exit 1
fi
if [ "$status_a" -ne 0 ] || [ "$status_b" -ne 0 ]; then
    echo "Runs were isolated, but at least one failed - see the logs above."
    exit 1
fi

echo "OK - both runs passed, with no shared containers or directories."
echo "Logs kept in $OUT_DIR"
