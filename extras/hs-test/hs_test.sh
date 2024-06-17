#!/usr/bin/env bash

source vars

args=
single_test=0
persist_set=0
unconfigure_set=0
debug_set=0
debug_build=
ginkgo_args=

for i in "$@"
do
case "${i}" in
    --persist=*)
        persist="${i#*=}"
        if [ "$persist" = "true" ]; then
            args="$args -persist"
            persist_set=1
        fi
        ;;
    --debug=*)
        debug="${i#*=}"
        if [ "$debug" = "true" ]; then
            args="$args -debug"
            debug_set=1
        fi
        ;;
    --debug_build=*)
        debug_build="${i#*=}"
        if [ "$debug_build" = "true" ]; then
            args="$args -debug_build"
        fi
        ;;
    --verbose=*)
        verbose="${i#*=}"
        if [ "$verbose" = "true" ]; then
            args="$args -verbose"
        fi
        ;;
    --unconfigure=*)
        unconfigure="${i#*=}"
        if [ "$unconfigure" = "true" ]; then
            args="$args -unconfigure"
            unconfigure_set=1
        fi
        ;;
    --cpus=*)
        args="$args -cpus ${i#*=}"
        ;;
    --vppsrc=*)
        args="$args -vppsrc ${i#*=}"
        ;;
    --test=*)
        tc_name="${i#*=}"
        if [ "$tc_name" != "all" ]; then
            single_test=1
            ginkgo_args="$ginkgo_args --focus $tc_name -vv"
            args="$args -verbose"
        else
            ginkgo_args="$ginkgo_args -v"
        fi
        ;;
    --parallel=*)
        ginkgo_args="$ginkgo_args -procs=${i#*=}"
        ;;
    --repeat=*)
        ginkgo_args="$ginkgo_args --repeat=${i#*=}"
        ;;
    --cpu0=*)
        cpu0="${i#*=}"
        if [ "$cpu0" = "true" ]; then
            args="$args -cpu0"
        fi
        ;;
esac
done

if [ $single_test -eq 0 ] && [ $persist_set -eq 1 ]; then
    echo "persist flag is not supported while running all tests!"
    exit 1
fi

if [ $unconfigure_set -eq 1 ] && [ $single_test -eq 0 ]; then
    echo "a single test has to be specified when unconfigure is set"
    exit 1
fi

if [ $persist_set -eq 1 ] && [ $unconfigure_set -eq 1 ]; then
    echo "setting persist flag and unconfigure flag is not allowed"
    exit 1
fi

if [ $single_test -eq 0 ] && [ $debug_set -eq 1 ]; then
    echo "VPP debug flag is not supported while running all tests!"
    exit 1
fi

mkdir -p summary
# shellcheck disable=SC2086
sudo -E go run github.com/onsi/ginkgo/v2/ginkgo --no-color --trace --json-report=summary/report.json $ginkgo_args -- $args

jq -r '.[0] | .SpecReports[] | select((.State == "failed") or (.State == "timedout") or (.State == "panicked")) | select(.Failure != null) | "TestName: \(.LeafNodeText)\nSuite:\n\(.Failure.FailureNodeLocation.FileName)\nMessage:\n\(.Failure.Message)\n Full Stack Trace:\n\(.Failure.Location.FullStackTrace)\n"' summary/report.json > summary/failed-summary.log \
	&& echo "Summary generated -> summary/failed-summary.log"
