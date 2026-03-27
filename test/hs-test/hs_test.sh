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
hyperthread=false
parallel=
use_cpu0=false

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

if [ -n "${GITHUB_REPO_URL}" ]; then
        ginkgo_args="$ginkgo_args --no-color"
fi

mkdir -p .go_cache

mkdir -p summary
rm -f summary/*
# shellcheck disable=SC2086

CPUS_PER_SLOT=4
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

# Resolve parallel process count
if [ "$parallel" = "auto" ]; then
    if [ "$total_usable_cores" -gt 0 ]; then
        auto_procs=$((total_usable_cores / CPUS_PER_SLOT))
    else
        # No taskset / small system fallback: count all physical cores,
        # no offset reservation since taskset is not used
        if [ "$hyperthread" = true ]; then
            total_cores=$(lscpu -p=CPU | grep -vc '^#')
        else
            total_cores=$(lscpu -p=CORE,CPU | grep -v '^#' | sort -u -t, -k1,1 | wc -l)
        fi
        if [ "$use_cpu0" = true ]; then
            usable_cores=$total_cores
        else
            usable_cores=$((total_cores - 1))
        fi
        auto_procs=$((usable_cores / CPUS_PER_SLOT))
        total_usable_cores=$usable_cores
    fi
    if [ "$auto_procs" -lt 1 ]; then
        auto_procs=1
    fi
    echo "* PARALLEL=auto resolved to $auto_procs processes ($total_usable_cores usable cores / $CPUS_PER_SLOT CPUs per slot)"
    ginkgo_args="$ginkgo_args -procs=$auto_procs"
elif [ -n "$parallel" ]; then
    ginkgo_args="$ginkgo_args -procs=$parallel"
fi

CMD="go run github.com/onsi/ginkgo/v2/ginkgo --json-report=summary/report.json $ginkgo_args -- $args"

if [ -n "$taskset_cmd" ]; then
    CMD="$taskset_cmd $CMD"
fi

echo $CMD
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
    chmod 666 summary/report.json
    chmod 666 summary/failed-summary.log
    exit $exit_status
else
    chmod 666 summary/report.json
    exit $exit_status
fi
