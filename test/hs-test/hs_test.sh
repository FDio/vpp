#!/usr/bin/env bash

args=
focused_test=0
persist_set=0
dryrun_set=0
coverage_set=0
debug_set=0
leak_check_set=0
debug_build=
ginkgo_args="--trace"
tc_names=()
skip_names=()
dryrun=
no_color=
hs_root=
label=
verbose=0
hyperthread=false
parallel=
use_cpu0=false
mw_parallel=false
mw_slots_per_numa=auto
mw_slots_per_numa_set=0

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
        parallel="${i#*=}"
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
            use_cpu0=true
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
    --hyperthread=*)
        args="$args -hyperthread=${i#*=}"
        hyperthread=${i#*=}
        ;;
    --mw_parallel=*)
        mw_parallel="${i#*=}"
        ;;
    --mw_slots_per_numa=*)
        mw_slots_per_numa="${i#*=}"
        mw_slots_per_numa_set=1
        ;;
esac
done

if [ "$mw_slots_per_numa_set" -eq 1 ] && [ "$mw_parallel" != "true" ]; then
    echo -e "\e[1;31mMW_SLOTS_PER_NUMA requires MW_PARALLEL=true\e[1;0m"
    exit 2
fi

if [ "$mw_slots_per_numa" != "auto" ] && ! [[ "$mw_slots_per_numa" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "\e[1;31mMW_SLOTS_PER_NUMA must be 'auto' or a positive integer\e[1;0m"
    exit 2
fi

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

if [ -n "${GITHUB_REPO_URL}" ]; then
        ginkgo_args="$ginkgo_args --no-color --github-output"
fi

mkdir -p .go_cache

mkdir -p /tmp/hs-test
rm -f /tmp/hs-test/cpu-claims /tmp/hs-test/cpu-claims.lock

mkdir -p summary
rm -f summary/*
# shellcheck disable=SC2086

CPUS_PER_SLOT=4
MW_AUTO_MAX_SLOTS_PER_NUMA=2
REQUIRED_PHYSICAL_CORES=20
CORES_TO_USE=10

# Get physical (or all, if HT enabled) core IDs for a given NUMA node.
# Falls back to non-NUMA-aware listing if NODE field is unavailable.
get_cores_on_node() {
    local node_id=$1

    # Check if lscpu reports NODE field
    local has_node
    has_node=$(lscpu -p=NODE,CORE,CPU 2>/dev/null | grep -v '^#' | head -1 | cut -d, -f1)

    if [ -z "$has_node" ]; then
        # NODE field is empty — get all cores without node filtering
        if [ "$hyperthread" = true ]; then
            lscpu -p=CORE,CPU | grep -v '^#' | sort -t, -k2,2n | cut -d, -f2
        else
            lscpu -p=CORE,CPU | grep -v '^#' | sort -t, -k2,2n | sort -u -t, -k1,1n | cut -d, -f2
        fi
    else
        if [ "$hyperthread" = true ]; then
            lscpu -p=NODE,CORE,CPU | \
            grep "^$node_id," | \
            sort -t, -k3,3n | \
            cut -d, -f3
        else
            lscpu -p=NODE,CORE,CPU | \
            grep "^$node_id," | \
            sort -t, -k3,3n | \
            sort -u -n -t, -k2,2 | \
            cut -d, -f3
        fi
    fi
}

# Get list of NUMA node IDs, falling back to "0" if NUMA is not available
get_numa_nodes() {
    if [ -d /sys/devices/system/node ] && ls /sys/devices/system/node/node* &>/dev/null; then
        for node in /sys/devices/system/node/node*; do
            basename "$node" | sed 's/node//'
        done
    else
        # No NUMA topology exposed — treat as single node 0
        echo "0"
    fi
}

# Determine available cores and set up taskset
taskset_cmd=""
total_usable_cores=0

mapfile -t numa_nodes < <(get_numa_nodes)

numa_process_count() {
    local count=${#numa_nodes[@]}
    if [ "$count" -lt 1 ]; then
        count=1
    fi
    echo "$count"
}

mw_usable_cores_on_node() {
    local node_id=$1

    mapfile -t node_cores < <(get_cores_on_node "$node_id")
    local usable=${#node_cores[@]}

    if [ "$usable" -gt 0 ] && [ "${node_cores[0]}" = "0" ] && [ "$use_cpu0" != true ]; then
        usable=$((usable - 1))
    fi

    if [ -n "$taskset_cmd" ] && [ "$node_id" = "0" ] && [ "$usable" -gt "$CORES_TO_USE" ]; then
        usable=$((usable - CORES_TO_USE))
    fi

    if [ "$usable" -lt 0 ]; then
        usable=0
    fi

    echo "$usable"
}

resolve_mw_slots_per_numa() {
    if [ "$mw_slots_per_numa" != "auto" ]; then
        return
    fi

    if [ "$mw_parallel" != "true" ] || [ "$parallel" != "auto" ]; then
        mw_slots_per_numa=1
        return
    fi

    local min_usable=
    local node_id
    local usable
    for node_id in "${numa_nodes[@]}"; do
        usable=$(mw_usable_cores_on_node "$node_id")
        if [ -z "$min_usable" ] || [ "$usable" -lt "$min_usable" ]; then
            min_usable=$usable
        fi
    done

    mw_slots_per_numa=$((min_usable / CPUS_PER_SLOT))
    if [ "$mw_slots_per_numa" -lt 1 ]; then
        mw_slots_per_numa=1
    elif [ "$mw_slots_per_numa" -gt "$MW_AUTO_MAX_SLOTS_PER_NUMA" ]; then
        mw_slots_per_numa=$MW_AUTO_MAX_SLOTS_PER_NUMA
    fi

    echo "* MW_SLOTS_PER_NUMA=auto resolved to $mw_slots_per_numa slot(s) per NUMA node (smallest NUMA node has $min_usable usable cores, cap $MW_AUTO_MAX_SLOTS_PER_NUMA)"
}

for node_id in "${numa_nodes[@]}"; do
    mapfile -t phys_cores < <(get_cores_on_node "$node_id")
    count=${#phys_cores[@]}

    if [ "$count" -ge "$REQUIRED_PHYSICAL_CORES" ]; then
        if [ "$use_cpu0" = true ]; then
            # Include core 0: take CORES_TO_USE starting from index 0
            selected_cores=("${phys_cores[@]:0:$CORES_TO_USE}")
            node_usable=$((count - CORES_TO_USE))
        else
            # Skip core 0: take CORES_TO_USE starting from index 1
            selected_cores=("${phys_cores[@]:1:$CORES_TO_USE}")
            node_usable=$((count - 1 - CORES_TO_USE))
        fi

        cpu_list=$(IFS=,; echo "${selected_cores[*]}")
        taskset_cmd="taskset -c $cpu_list"
        args="$args -cpu_offset=$CORES_TO_USE"

        total_usable_cores=$((total_usable_cores + node_usable))
        echo "* Node $node_id: $count cores, $node_usable usable for tests"

        # Add all other NUMA nodes entirely
        for other_id in "${numa_nodes[@]}"; do
            if [ "$other_id" != "$node_id" ]; then
                mapfile -t other_cores < <(get_cores_on_node "$other_id")
                other_count=${#other_cores[@]}
                total_usable_cores=$((total_usable_cores + other_count))
                echo "* Node $other_id: $other_count cores, all usable for tests"
            fi
        done

        echo "* System has enough CPUs to run Ginkgo with taskset!"
        echo "* Total usable cores for tests: $total_usable_cores"
        break
    fi
done

resolve_auto_process_count() {
    if [ "$total_usable_cores" -le 0 ]; then
        # No taskset / small system fallback: count all physical cores,
        # no offset reservation since taskset is not used.
        if [ "$hyperthread" = true ]; then
            total_cores=$(lscpu -p=CPU | grep -vc '^#')
        else
            total_cores=$(lscpu -p=CORE,CPU | grep -v '^#' | sort -u -t, -k1,1 | wc -l)
        fi

        if [ "$use_cpu0" = true ]; then
            total_usable_cores=$total_cores
        else
            total_usable_cores=$((total_cores - 1))
        fi
    fi

    auto_procs=$((total_usable_cores / CPUS_PER_SLOT))
    if [ "$auto_procs" -lt 1 ]; then
        auto_procs=1
    fi
}

auto_procs=1
numa_procs=$(numa_process_count)
resolve_mw_slots_per_numa
mw_procs=$((numa_procs * mw_slots_per_numa))
parallel_ginkgo_args=
parallel_test_args=

case "$parallel" in
    auto)
        resolve_auto_process_count
        echo "* PARALLEL=auto resolved to $auto_procs processes ($total_usable_cores usable cores / $CPUS_PER_SLOT CPUs per slot)"
        parallel_ginkgo_args="-procs=$auto_procs"
        ;;
    per-numa)
        echo "* PARALLEL=per-numa resolved to $numa_procs processes (${#numa_nodes[@]} NUMA node(s))"
        parallel_ginkgo_args="-procs=$numa_procs"
        parallel_test_args="-numa_per_process"
        ;;
    "")
        ;;
    *)
        parallel_ginkgo_args="-procs=$parallel"
        ;;
esac

run_ginkgo() {
    local report_path=$1
    local extra_ginkgo_args=$2
    local extra_test_args=$3

    local cmd="go run github.com/onsi/ginkgo/v2/ginkgo --json-report=$report_path $ginkgo_args $extra_ginkgo_args -- $args $extra_test_args"

    if [ -n "$taskset_cmd" ]; then
        cmd="$taskset_cmd $cmd"
    fi

    echo "$cmd"
    $cmd
}

combine_ginkgo_reports() {
    local reports=()

    if [ -f summary/report-non-mw.json ]; then
        reports+=("summary/report-non-mw.json")
    fi
    if [ -f summary/report-mw-wide.json ]; then
        reports+=("summary/report-mw-wide.json")
    fi
    if [ -f summary/report-mw-narrow.json ]; then
        reports+=("summary/report-mw-narrow.json")
    fi
    if [ -f summary/report-mw.json ]; then
        reports+=("summary/report-mw.json")
    fi

    if [ ${#reports[@]} -eq 1 ]; then
        cp "${reports[0]}" summary/report.json
    elif [ ${#reports[@]} -gt 1 ]; then
        jq -s 'add' "${reports[@]}" > summary/report.json
    fi
}

should_split_auto_mw_run() {
    [ "$parallel" = "auto" ] && [ "$mw_parallel" = "true" ] && [ "${tc_list:-all}" = "all" ] && [ -z "$label" ]
}

should_run_mw_only_numa() {
    [ "$parallel" = "auto" ] && [ "$mw_parallel" = "true" ] && [ "$label" = "MW" ]
}

run_mw_numa_ginkgo() {
    local report_path=$1
    local label_filter=$2
    local slots_per_numa=$3
    local filter_arg=
    local procs=$((numa_procs * slots_per_numa))

    if [ -n "$label_filter" ]; then
        filter_arg="--label-filter=$label_filter"
    fi

    export HST_MW_PARALLEL=true
    run_ginkgo "$report_path" "-procs=$procs $filter_arg" "-numa_per_process -numa_slots_per_node=$slots_per_numa"
}

run_mw_ginkgo_phases() {
    if [ "$mw_slots_per_numa" -eq 1 ]; then
        echo "* MW phase: $numa_procs NUMA-aware process(es) (${#numa_nodes[@]} NUMA node(s), 1 slot per NUMA node)"
        run_mw_numa_ginkgo "summary/report-mw.json" "MW" 1
        return $?
    fi

    local wide_procs=$numa_procs
    local narrow_procs=$mw_procs
    echo "* MW wide phase: $wide_procs NUMA-aware process(es) (${#numa_nodes[@]} NUMA node(s), 1 slot per NUMA node)"
    run_mw_numa_ginkgo "summary/report-mw-wide.json" "MW&&MWWide" 1
    wide_status=$?

    echo "* MW narrow phase: $narrow_procs NUMA-aware process(es) (${#numa_nodes[@]} NUMA node(s), $mw_slots_per_numa slot(s) per NUMA node)"
    run_mw_numa_ginkgo "summary/report-mw-narrow.json" "MW&&!MWWide" "$mw_slots_per_numa"
    narrow_status=$?

    if [ $wide_status -ne 0 ]; then
        return $wide_status
    fi
    return $narrow_status
}

exit_status=0

if should_split_auto_mw_run; then
    echo "* PARALLEL=auto with MW_PARALLEL=true: running non-MW specs with auto parallelism, then MW specs with NUMA-aware parallelism"
    echo "* non-MW phase: $auto_procs process(es)"

    export HST_MW_PARALLEL=false
    run_ginkgo "summary/report-non-mw.json" "$parallel_ginkgo_args --label-filter=!MW" "$parallel_test_args"
    non_mw_status=$?

    run_mw_ginkgo_phases
    mw_status=$?

    combine_ginkgo_reports

    if [ $non_mw_status -ne 0 ]; then
        exit_status=$non_mw_status
    else
        exit_status=$mw_status
    fi
elif should_run_mw_only_numa; then
    echo "* PARALLEL=auto with MW_PARALLEL=true and LABEL=MW: running MW specs with NUMA-aware parallelism"
    run_mw_ginkgo_phases
    exit_status=$?
    combine_ginkgo_reports
else
    export HST_MW_PARALLEL="$mw_parallel"
    run_ginkgo "summary/report.json" "$parallel_ginkgo_args" "$parallel_test_args"
    exit_status=$?
fi

# Ginkgo container stops and is removed when this script finishes.
# Some tests use network namespaces, and to access them when debugging,
# we need to keep the Ginkgo container running.
if [ "$dryrun_set" = "1" ] || [ "$persist_set" = "1" ]; then
    trap 'exit 0' SIGINT
    echo -e "\e[1;33mDRYRUN=true or PERSIST=true, sleeping to keep Ginkgo container alive.\nPress 'Ctrl+C' to exit\e[1;0m"
    sleep infinity
fi

if [ $exit_status != 0 ]; then
    jq -r '.[] | .SpecReports[] | select((.State == "failed") or (.State == "timedout") or (.State == "panicked")) | select(.Failure != null) |
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
    chmod 666 summary/report.json
    chmod 666 summary/failed-summary.log
    exit $exit_status
else
    chmod 666 summary/report.json
    exit $exit_status
fi
