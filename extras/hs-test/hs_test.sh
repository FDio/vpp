#!/usr/bin/env bash

source vars

args=
focused_test=0
persist_set=0
dryrun_set=0
coverage_set=0
unconfigure_set=0
debug_set=0
leak_check_set=0
debug_build=
ginkgo_args=
tc_names=()
skip_names=()
dryrun=
no_color=

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
    --coverage=*)
        coverage="${i#*=}"
        if [ "$coverage" = "true" ]; then
            args="$args -coverage"
            coverage_set=1
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
    --skip=*)
        skip_list="${i#*=}"
        IFS=',' read -r -a skip_names <<< "$skip_list"
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
    --dryrun=*)
        dryrun="${i#*=}"
        if [ "$dryrun" = "true" ]; then
            args="$args -dryrun"
            dryrun_set=1
        fi
        ;;
    --leak_check=*)
        leak_check="${i#*=}"
        if [ "$leak_check" = "true" ]; then
            args="$args -leak_check"
            leak_check_set=1
        fi
        ;;
    --no_color=*)
        no_color="${i#*=}"
        if [ "$no_color" = "true" ]; then
            ginkgo_args="$ginkgo_args --no-color"
        fi
        ;;
esac
done

if [ ${#tc_names[@]} -gt 1 ]
then
    focused_test=0
fi

for name in "${tc_names[@]}"; do
    ginkgo_args="$ginkgo_args --focus $name"
done

for skip in "${skip_names[@]}"; do
    ginkgo_args="$ginkgo_args --skip $skip"
done

if [ $focused_test -eq 0 ] && { [ $persist_set -eq 1 ] || [ $dryrun_set -eq 1 ]; }; then
    echo -e "\e[1;31mpersist/dryrun flag is not supported while running all tests!\e[1;0m"
    exit 2
fi

if [ $unconfigure_set -eq 1 ] && [ $focused_test -eq 0 ]; then
    echo -e "\e[1;31ma single test has to be specified when unconfigure is set\e[1;0m"
    exit 2
fi

if [ $persist_set -eq 1 ] && [ $unconfigure_set -eq 1 ]; then
    echo -e "\e[1;31msetting persist flag and unconfigure flag is not allowed\e[1;0m"
    exit 2
fi

if [ $focused_test -eq 0 ] && [ $debug_set -eq 1 ]; then
    echo -e "\e[1;31mVPP debug flag is not supported while running all tests!\e[1;0m"
    exit 2
fi

if [ $leak_check_set -eq 1 ]; then
  if [ $focused_test -eq 0 ]; then
    echo -e "\e[1;31ma single test has to be specified when leak_check is set\e[1;0m"
    exit 2
  fi
  ginkgo_args="--focus ${tc_names[0]}"
  sudo -E go run github.com/onsi/ginkgo/v2/ginkgo $ginkgo_args -- $args
  exit 0
fi

if [ -n "${BUILD_NUMBER}" ]; then
       ginkgo_args="$ginkgo_args --no-color"
fi

mkdir -p summary
# shellcheck disable=SC2086
sudo -E go run github.com/onsi/ginkgo/v2/ginkgo --json-report=summary/report.json $ginkgo_args -- $args
exit_status=$?

if [ -e "summary/failed-summary.log" ]; then
        rm summary/failed-summary.log
fi

if [ $exit_status != 0 ]; then
    jq -r '.[0] | .SpecReports[] | select((.State == "failed") or (.State == "timedout") or (.State == "panicked")) | select(.Failure != null) |
"TestName:
    \(.LeafNodeText)
Suite:
    \(.Failure.FailureNodeLocation.FileName)
Message:\n"
+ (
    if .ReportEntries? then
        (.ReportEntries[] | select(.Name == "VPP Backtrace") |
        "\tVPP crashed
Full Back Trace:
\(.Value.Representation | ltrimstr("{{red}}") | rtrimstr("{{/}}"))"
        ) // "\(.Failure.Message)"
    else
        "parse error"
    end
)
+ (
    if .Failure.Message == "A spec timeout occurred" then
        "\n"
    else
        "\nFull Stack Trace:
\(.Failure.Location.FullStackTrace)\n"
    end
)' summary/report.json > summary/failed-summary.log \
&& echo "Summary generated -> summary/failed-summary.log"
    exit $exit_status
else
    exit $exit_status
fi
