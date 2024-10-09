#!/usr/bin/env bash

source vars

args=
focused_test=0
persist_set=0
unconfigure_set=0
debug_set=0
leak_check_set=0
debug_build=
ginkgo_args=
tc_names=()

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
        tc_list="${i#*=}"
        ginkgo_args="$ginkgo_args -v"
        if [ "$tc_list" != "all" ]; then
            focused_test=1
            IFS=',' read -r -a tc_names <<< "$tc_list"
            args="$args -verbose"
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
    --leak_check=*)
        leak_check="${i#*=}"
        if [ "$leak_check" = "true" ]; then
            args="$args -leak_check"
            leak_check_set=1
        fi
        ;;
esac
done

for name in "${tc_names[@]}"; do
    ginkgo_args="$ginkgo_args --focus $name"
done

if [ $focused_test -eq 0 ] && [ $persist_set -eq 1 ]; then
    echo "persist flag is not supported while running all tests!"
    exit 1
fi

if [ $unconfigure_set -eq 1 ] && [ $focused_test -eq 0 ]; then
    echo "a single test has to be specified when unconfigure is set"
    exit 1
fi

if [ $persist_set -eq 1 ] && [ $unconfigure_set -eq 1 ]; then
    echo "setting persist flag and unconfigure flag is not allowed"
    exit 1
fi

if [ $focused_test -eq 0 ] && [ $debug_set -eq 1 ]; then
    echo "VPP debug flag is not supported while running all tests!"
    exit 1
fi

if [ $leak_check_set -eq 1 ]; then
  if [ $focused_test -eq 0 ]; then
    echo "a single test has to be specified when leak_check is set"
    exit 1
  fi
  ginkgo_args="--focus $tc_name"
  sudo -E go run github.com/onsi/ginkgo/v2/ginkgo $ginkgo_args -- $args
  exit 0
fi

if [ -n "${BUILD_NUMBER}" ]; then
       ginkgo_args="$ginkgo_args --no-color"
fi

mkdir -p summary
# shellcheck disable=SC2086
sudo -E go run github.com/onsi/ginkgo/v2/ginkgo --json-report=summary/report.json $ginkgo_args -- $args

if [ $? != 0 ]; then
    jq -r '.[0] | .SpecReports[] | select((.State == "failed") or (.State == "timedout") or (.State == "panicked")) | select(.Failure != null) |
"TestName:
    \(.LeafNodeText)
Suite:
    \(.Failure.FailureNodeLocation.FileName)
Message:\n"
+(if .ReportEntries? then .ReportEntries[] | select(.Name == "VPP Backtrace") |
"\tVPP crashed
Full Back Trace:
\(.Value.Representation | ltrimstr("{{red}}") | rtrimstr("{{/}}"))" else
    "\(.Failure.Message)"
     + (if .Failure.Message == "A spec timeout occurred" then "\n" else
"\nFull Stack Trace:
\(.Failure.Location.FullStackTrace)\n" end) end)' summary/report.json > summary/failed-summary.log \
	&& echo "Summary generated -> summary/failed-summary.log"
else
    if [ -e "summary/failed-summary.log" ]; then
        rm summary/failed-summary.log
    fi
fi
