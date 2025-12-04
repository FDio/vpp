#!/usr/bin/env bash

args=
focused_test=0
persist_set=0
debug_set=0
debug_build=
ginkgo_args=
tc_names=()
skip_names=()
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
    --verbose=*)
        verbose="${i#*=}"
        if [ "$verbose" = "true" ]; then
            args="$args -verbose"
        fi
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
    --ginkgo_timeout=*)
        ginkgo_args="$ginkgo_args --timeout=${i#*=}"
        ;;
    --repeat=*)
        ginkgo_args="$ginkgo_args --repeat=${i#*=}"
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

if [ $focused_test -eq 0 ] && { [ $persist_set -eq 1 ]; }; then
    echo -e "\e[1;31mpersist flag is not supported while running all tests!\e[1;0m"
    exit 2
fi

if [ -n "${BUILD_NUMBER}" ]; then
        ginkgo_args="$ginkgo_args --no-color"
fi

mkdir -p summary
rm -f summary/*
# shellcheck disable=SC2086
CMD="go run github.com/onsi/ginkgo/v2/ginkgo --json-report=summary/report.json $ginkgo_args -- $args"
echo "$CMD"
$CMD
exit_status=$?

if [ $exit_status -ne 0 ]; then
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
