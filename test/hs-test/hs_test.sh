#!/usr/bin/env bash

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
hs_root=
label=
verbose=0

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
    --vpp_cpus=*)
        args="$args -vpp_cpus ${i#*=}"
        ;;
    --vppsrc=*)
        args="$args -vppsrc ${i#*=}"
        ;;
    --test=*)
        tc_list="${i#*=}"
        if [ "$tc_list" != "all" ]; then
            focused_test=1
            IFS=',' read -r -a tc_names <<< "$tc_list"
        fi
        ;;
    --skip=*)
        skip_list="${i#*=}"
        IFS=',' read -r -a skip_names <<< "$skip_list"
        ;;
    --parallel=*)
        ginkgo_args="$ginkgo_args -procs=${i#*=}"
        ;;
    --ginkgo_timeout=*)
        ginkgo_args="$ginkgo_args --timeout=${i#*=}"
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
    --timeout=*)
        args="$args -timeout ${i#*=}"
        ;;
    --hs_root=*)
        hs_root="${i#*=}"
        cd $hs_root
        ;;
    --label=*)
        label="${i#*=}"
        focused_test=1
        ginkgo_args="$ginkgo_args --label-filter="$label""
        ;;
    --host_ppid=*)
        args="$args -host_ppid ${i#*=}"
        ;;
    --seed=*)
        seed="${i#*=}"
        ginkgo_args="$ginkgo_args --seed=$seed"
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

if [ "$verbose" == "true" ]; then
    echo -e "\e[1;33mPlease use V=[0|1|2] or VERBOSE=[0|1|2]\e[1;0m"
    verbose=1
fi

if { [ $focused_test -eq 1 ] && [ $verbose -eq 0 ]; } || [ $verbose -eq 1 ]; then
    args="$args -verbose"
    ginkgo_args="$ginkgo_args -v"
elif [ $verbose -eq 2 ]; then
    args="$args -verbose"
    ginkgo_args="$ginkgo_args -vv"
fi

args="$args -whoami $(whoami)"

if [ $leak_check_set -eq 1 ]; then
  if [ $focused_test -eq 0 ]; then
    echo -e "\e[1;31ma single test has to be specified via TEST var when leak_check is set\e[1;0m"
    exit 2
  else
    if [[ $tc_list != *"MemLeak"* ]]; then
        echo -e "\e[1;31mnone of the selected tests are memleak tests\e[1;0m"
        exit 2
    fi
  fi
fi

if [ -n "${BUILD_NUMBER}" ]; then
        ginkgo_args="$ginkgo_args --no-color"
fi

mkdir -p .go_cache

mkdir -p summary
rm -f summary/*
# shellcheck disable=SC2086
CMD="go run github.com/onsi/ginkgo/v2/ginkgo --json-report=summary/report.json $ginkgo_args -- $args"
echo "$CMD"
$CMD
exit_status=$?

if [ $exit_status != 0 ]; then
    jq -r '.[0] | .SpecReports[] | select((.State == "failed") or (.State == "timedout") or (.State == "panicked")) | select(.Failure != null) |
"TestName:
    \(.LeafNodeText)
Suite:
    \(.Failure.FailureNodeLocation.FileName)
Message:\n"
+ (
    if .ReportEntries? then
        (.ReportEntries[] | select(.Name | contains("Backtrace")) |
        "\tFull Back Trace:
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
