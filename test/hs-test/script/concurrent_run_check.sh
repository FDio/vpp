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
# twice is enough to show that the runs do not collide, which is what stage 1 of
# the isolation work addresses; running two different VPP versions side by side
# additionally needs per-run docker image tags, which do not exist yet.
#
# Usage: script/concurrent_run_check.sh [test-name] [run-id-a] [run-id-b]
#
# Both runs use this checkout's images by default. To check that two different VPP
# builds can run side by side, point each run at its own tag:
#
#   IMAGE_TAG_A=<tag> IMAGE_TAG_B=<tag> script/concurrent_run_check.sh

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

# Images are tagged per run, so a made-up RUN_ID has no images. Both runs default
# to the tag this checkout actually built, which makes this a test of run isolation
# rather than of building twice. Set IMAGE_TAG_A and IMAGE_TAG_B to different tags
# to check that two VPP versions can be exercised side by side.
DEFAULT_TAG=$(make -n test 2>/dev/null < /dev/null |
    grep -o -- '--image_tag=[^ ]*' | head -1 | cut -d= -f2)
if [ -z "$DEFAULT_TAG" ]; then
    echo "Could not determine this checkout's image tag." >&2
    exit 1
fi
TAG_A=${IMAGE_TAG_A:-$DEFAULT_TAG}
TAG_B=${IMAGE_TAG_B:-$DEFAULT_TAG}

for tag in "$TAG_A" "$TAG_B"; do
    for repo in hs-test/vpp hs-test/ginkgo; do
        if ! docker image inspect "$repo:$tag" > /dev/null 2>&1; then
            echo "Image $repo:$tag does not exist." >&2
            if [ "$tag" = "$DEFAULT_TAG" ]; then
                echo "Run 'make build' first." >&2
            fi
            exit 1
        fi
    done
done

if [ "$TAG_A" = "$TAG_B" ]; then
    echo "Using images tagged '$TAG_A' for both runs."
else
    echo "Using images '$TAG_A' for $RUN_A and '$TAG_B' for $RUN_B."
fi

# Ask make what it would run, so this script cannot drift from the real recipe.
# stdin is redirected because the Makefile adds 'docker run -it' when it sees a
# terminal, and the two runs below are backgrounded and so have no terminal.
tag_for() { [ "$1" = "$RUN_A" ] && echo "$TAG_A" || echo "$TAG_B"; }

for run_id in "$RUN_A" "$RUN_B"; do
    if ! make RUN_ID="$run_id" IMAGE_TAG="$(tag_for "$run_id")" TEST="$TEST_NAME" -n test \
            2>/dev/null < /dev/null |
            grep '^docker run' | head -1 > "$OUT_DIR/cmd-$run_id.sh"; then
        echo "Could not determine the docker command for RUN_ID=$run_id" >&2
        exit 1
    fi
    if [ ! -s "$OUT_DIR/cmd-$run_id.sh" ]; then
        echo "make -n produced no docker command for RUN_ID=$run_id" >&2
        exit 1
    fi

    # The Ginkgo container is started by the Makefile rather than by the test
    # binary, so it logs nothing and has to be checked in the command itself.
    if ! grep -q "hs-test/ginkgo:$(tag_for "$run_id")" "$OUT_DIR/cmd-$run_id.sh"; then
        echo "RUN_ID=$run_id would not use hs-test/ginkgo:$(tag_for "$run_id")" >&2
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
    echo "    images:     $(images_of "$run_id" | paste -sd' ')"
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
# hs-test logs the image each container is created from, so the run's own log is
# the record of what it used - no need to watch 'docker ps' and hope to catch a
# short-lived container while it is up.
images_of() {
    strip_colors "$OUT_DIR/$1.log" |
        grep -aoE "from image [^[:space:]]+" | sed 's/from image //' | sort -u
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

# When two different builds were requested, neither run may have touched the
# other's images - that is the claim per-run image tags exist to support.
if [ "$TAG_A" != "$TAG_B" ]; then
    wrong=$( { images_of "$RUN_A" | grep -v ":$TAG_A\$" || true; } )
    wrong="$wrong$( { images_of "$RUN_B" | grep -v ":$TAG_B\$" || true; } )"
    if [ -n "$wrong" ]; then
        echo "WRONG IMAGES - a run used an image that is not its own:"
        echo "$wrong" | sed 's/^/    /'
        exit 1
    fi
    if [ -z "$(images_of "$RUN_A")" ] || [ -z "$(images_of "$RUN_B")" ]; then
        echo "INCONCLUSIVE - could not observe the images one of the runs used."
        exit 1
    fi
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
