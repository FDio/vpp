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
mw_workers_per_numa=auto
mw_workers_per_numa_set=0
repeat=0
run_id=
cpu_budget=0
rebalance_pid=

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
        repeat="${i#*=}"
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
        ;;
    --host_ppid=*)
        args="$args -host_ppid ${i#*=}"
        ;;
    --cpu_budget=*)
        cpu_budget="${i#*=}"
        ;;
    --run_id=*)
        run_id="${i#*=}"
        args="$args -run_id ${i#*=}"
        ;;
    --image_tag=*)
        args="$args -image_tag ${i#*=}"
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
    --mw_workers_per_numa=*)
        mw_workers_per_numa="${i#*=}"
        mw_workers_per_numa_set=1
        ;;
esac
done

if [ "$mw_parallel" != "true" ] && [ "$mw_parallel" != "false" ]; then
    echo -e "\e[1;31mMW_PARALLEL must be true or false\e[1;0m"
    exit 2
fi

if [ "$mw_workers_per_numa_set" -eq 1 ] && [ "$mw_parallel" != "true" ]; then
    echo -e "\e[1;31mMW_WORKERS_PER_NUMA requires MW_PARALLEL=true\e[1;0m"
    exit 2
fi

if [ "$mw_workers_per_numa" != "auto" ] && ! [[ "$mw_workers_per_numa" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "\e[1;31mMW_WORKERS_PER_NUMA must be 'auto' or a positive integer\e[1;0m"
    exit 2
fi

if ! [[ "$cpu_budget" =~ ^[0-9]+$ ]]; then
    echo -e "\e[1;31mCPU_BUDGET must be a non-negative integer\e[1;0m"
    exit 2
fi

if ! [[ "$repeat" =~ ^[0-9]+$ ]]; then
    echo -e "\e[1;31mREPEAT must be a non-negative integer\e[1;0m"
    exit 2
fi

if [ -n "$parallel" ] && [ "$parallel" != "auto" ] && ! [[ "$parallel" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "\e[1;31mPARALLEL must be 'auto' or a positive integer\e[1;0m"
    exit 2
fi

if [ "$mw_parallel" = "true" ] && [ "$parallel" != "auto" ]; then
    echo -e "\e[1;31mMW_PARALLEL=true requires PARALLEL=auto\e[1;0m"
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

if [ "$mw_parallel" = "true" ]; then
    mkdir -p /tmp/hst
    # Drop only claims left behind by an earlier run with this id. Removing the
    # whole file would discard the claims of a run happening right now.
    if [ -f /tmp/hst/cpu-claims ] && [ -n "$run_id" ]; then
        awk -v prefix="run=$run_id " 'index($0, prefix) != 1' /tmp/hst/cpu-claims \
            > /tmp/hst/cpu-claims.$$ 2>/dev/null || true
        mv /tmp/hst/cpu-claims.$$ /tmp/hst/cpu-claims
    fi
fi

mkdir -p summary
rm -f summary/*
# shellcheck disable=SC2086

CPUS_PER_WORKER=4
MW_AUTO_MAX_WORKERS_PER_NUMA=2
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
taskset_node_id=""
taskset_cores=""
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

    if [ -n "$taskset_cmd" ] && [ "$node_id" = "$taskset_node_id" ] && [ "$usable" -gt "$CORES_TO_USE" ]; then
        usable=$((usable - CORES_TO_USE))
    fi

    if [ "$usable" -lt 0 ]; then
        usable=0
    fi

    echo "$usable"
}

resolve_mw_workers_per_numa() {
    if [ "$mw_workers_per_numa" != "auto" ]; then
        return
    fi

    if [ "$mw_parallel" != "true" ] || [ "$parallel" != "auto" ]; then
        mw_workers_per_numa=1
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

    mw_workers_per_numa=$((min_usable / CPUS_PER_WORKER))
    if [ "$mw_workers_per_numa" -lt 1 ]; then
        mw_workers_per_numa=1
    elif [ "$mw_workers_per_numa" -gt "$MW_AUTO_MAX_WORKERS_PER_NUMA" ]; then
        mw_workers_per_numa=$MW_AUTO_MAX_WORKERS_PER_NUMA
    fi

    echo "* MW_WORKERS_PER_NUMA=auto resolved to $mw_workers_per_numa worker(s) per NUMA node (smallest NUMA node has $min_usable usable cores, cap $MW_AUTO_MAX_WORKERS_PER_NUMA)"
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
        taskset_cores=$cpu_list
        taskset_cmd="taskset -c $cpu_list"
        taskset_node_id=$node_id
        args="$args -cpu_offset=$CORES_TO_USE"
        if [ "$mw_parallel" = "true" ]; then
            args="$args -cpu_offset_numa_node=$node_id"
        fi

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

    auto_procs=$((total_usable_cores / CPUS_PER_WORKER))
    if [ "$auto_procs" -lt 1 ]; then
        auto_procs=1
    fi
}

# ---------------------------------------------------------------------------
# CPU reservation
#
# Container CPUs are pinned by index from the start of the allocator's list, so
# two runs left to themselves pin to the same cores while the rest of the machine
# sits idle. Each run therefore reserves the cores it may use before Ginkgo
# starts, and passes them on with -cpu_list.
#
# With no other run present a run reserves everything free, which is what it
# would have used anyway. CPU_BUDGET caps that, so two runs can be given a share
# each; the reservation is what makes the shares disjoint rather than advisory.
# ---------------------------------------------------------------------------
CPU_RESERVATIONS=/tmp/hst/cpu-reservations
CPU_RESERVATIONS_LOCK=/tmp/hst/cpu-reservations.lock
reserved_cpus=

# Cores tests may use: physical cores (or every thread with HT), less core 0
# unless CPU0=true, less the block handed to taskset for the Ginkgo process.
usable_core_list() {
    local node_id core
    local -a cores
    for node_id in "${numa_nodes[@]}"; do
        mapfile -t cores < <(get_cores_on_node "$node_id")
        for core in "${cores[@]}"; do
            if [ "$core" = "0" ] && [ "$use_cpu0" != true ]; then
                continue
            fi
            case ",$taskset_cores," in *",$core,"*) continue ;; esac
            echo "$core"
        done
    done
}

# A reservation whose Ginkgo container is gone belongs to a run that died; the
# cores are free again. This is what keeps a crashed run from leaking its share.
reservation_is_live() {
    # by label, not by name: the name filter is a regex and RUN_ID may contain
    # '.', which would match another run and treat it as this one
    [ -n "$(docker ps -q -f "label=io.fd.hs-test.run=$1" 2>/dev/null)" ]
}

# Any live run other than this one holding cores.
other_runs_hold_cpus() {
    local id cpus mode
    [ -f "$CPU_RESERVATIONS" ] || return 1
    while IFS="	" read -r id cpus mode; do
        [ -z "$id" ] && continue
        [ "$id" = "$run_id" ] && continue
        reservation_is_live "$id" && return 0
    done < "$CPU_RESERVATIONS"
    return 1
}

# An MW_PARALLEL run has the machine; plain runs must not start alongside it.
mw_run_is_live() {
    local id cpus mode
    [ -f "$CPU_RESERVATIONS" ] || return 1
    while IFS="	" read -r id cpus mode; do
        [ -z "$id" ] && continue
        [ "$id" = "$run_id" ] && continue
        [ "$mode" = "mw" ] || continue
        reservation_is_live "$id" && return 0
    done < "$CPU_RESERVATIONS"
    return 1
}

# Claim everything, so a plain run starting later sees the machine is taken. No
# -cpu_list is passed: an MW run keeps the NUMA-aware allocation it has always had.
record_whole_machine_reservation() {
    local usable
    mkdir -p /tmp/hst 2>/dev/null || true
    (
        flock 9
        touch "$CPU_RESERVATIONS"
        usable=$(usable_core_list | paste -sd, -)
        printf '%s	%s	mw\n' "$run_id" "$usable" > "$CPU_RESERVATIONS.tmp.$$"
        chmod 666 "$CPU_RESERVATIONS.tmp.$$" 2>/dev/null || true
        mv "$CPU_RESERVATIONS.tmp.$$" "$CPU_RESERVATIONS"
    ) 9>"$CPU_RESERVATIONS_LOCK"
    echo "* MW_PARALLEL run '$run_id' has taken the whole machine"
}

release_cpu_reservation() {
    [ -n "$run_id" ] || return 0
    [ -f "$CPU_RESERVATIONS" ] || return 0
    (
        flock 9
        awk -F'\t' -v id="$run_id" '$1 != id' "$CPU_RESERVATIONS" \
            > "$CPU_RESERVATIONS.$$" 2>/dev/null || true
        mv "$CPU_RESERVATIONS.$$" "$CPU_RESERVATIONS" 2>/dev/null || true
    ) 9>"$CPU_RESERVATIONS_LOCK"
}

# Reserve this run's share of the machine.
#
# The share is the usable cores divided by the number of runs, this one included,
# so nothing has to be passed on the command line. A run that already holds more
# than its share is trimmed down to it and the surplus taken; holders notice at
# their next test and carry on with fewer cores. CPU_BUDGET, when set, caps this
# run's share but never raises it.
reserve_cpus() {
    local id cpus kept core fair keep n_live want held_now
    local -a usable free mine

    mkdir -p /tmp/hst 2>/dev/null || true
    : > "$CPU_RESERVATIONS.new.$$"

    (
        flock 9
        touch "$CPU_RESERVATIONS"
        # runs may belong to different users; all of them have to be able to
        # rewrite the shares
        chmod 666 "$CPU_RESERVATIONS" "$CPU_RESERVATIONS_LOCK" 2>/dev/null || true

        mapfile -t usable < <(usable_core_list)

        n_live=0
        while IFS="	" read -r id cpus mode; do
            [ -z "$id" ] && continue
            [ "$id" = "$run_id" ] && continue
            reservation_is_live "$id" && n_live=$((n_live + 1))
        done < "$CPU_RESERVATIONS"

        fair=$(( ${#usable[@]} / (n_live + 1) ))
        [ "$fair" -lt 1 ] && fair=1
        want=$fair
        if [ "$cpu_budget" -gt 0 ] && [ "$cpu_budget" -lt "$want" ]; then
            want=$cpu_budget
        fi

        # Trim every live holder to the fair share. What they give up needs no
        # bookkeeping: the free list below is whatever no holder kept.
        kept=""
        while IFS="	" read -r id cpus mode; do
            [ -z "$id" ] && continue
            [ "$id" = "$run_id" ] && continue
            if ! reservation_is_live "$id"; then
                continue
            fi
            keep=$(echo "$cpus" | tr ',' '\n' | head -n "$fair" | paste -sd,)
            kept="$kept$id	$keep	${mode:-plain}
"
        done < "$CPU_RESERVATIONS"

        # Free cores are those no live holder kept. The held set is built once:
        # this runs on a timer for every live run, so a subshell per core adds up.
        held_now=",$(printf '%s' "$kept" | cut -f2 | paste -sd, -),"
        free=()
        for core in "${usable[@]}"; do
            case "$held_now" in *",$core,"*) continue ;; esac
            free+=("$core")
        done

        mine=("${free[@]:0:$want}")
        if [ "${#mine[@]}" -lt 1 ]; then
            printf 'NONE\n' > "$CPU_RESERVATIONS.new.$$"
            printf '%s' "$kept" > "$CPU_RESERVATIONS.tmp.$$"
            mv "$CPU_RESERVATIONS.tmp.$$" "$CPU_RESERVATIONS"
            exit 0
        fi

        printf '%s%s	%s	plain\n' "$kept" "$run_id" "$(IFS=,; echo "${mine[*]}")" \
            > "$CPU_RESERVATIONS.tmp.$$"
        chmod 666 "$CPU_RESERVATIONS.tmp.$$" 2>/dev/null || true
        mv "$CPU_RESERVATIONS.tmp.$$" "$CPU_RESERVATIONS"
        (IFS=,; echo "${mine[*]}") > "$CPU_RESERVATIONS.new.$$"
    ) 9>"$CPU_RESERVATIONS_LOCK"

    reserved_cpus=$(head -1 "$CPU_RESERVATIONS.new.$$" 2>/dev/null)
    rm -f "$CPU_RESERVATIONS.new.$$"

    if [ "$reserved_cpus" = "NONE" ] || [ -z "$reserved_cpus" ]; then
        echo -e "\e[1;31mNo CPUs are free for this run.\e[1;0m"
        echo "Cores are held by:"
        sed 's/^/    /' "$CPU_RESERVATIONS" 2>/dev/null
        return 1
    fi
    return 0
}

# Re-balancing is just reserve_cpus run again: it recomputes the fair share from
# the runs that are live at that moment and re-takes this run's part of it. Doing
# it periodically is what lets a share grow back once another run has finished,
# not only shrink when one starts. Ginkgo is running by then, so it has to happen
# in the background; the test binary picks the change up at its next test.
rebalance_cpus_periodically() {
    while sleep 30; do
        reserve_cpus "$cpu_budget" > /dev/null 2>&1 || true
    done
}

stop_cpu_rebalance() {
    [ -n "$rebalance_pid" ] && kill "$rebalance_pid" 2>/dev/null
    release_cpu_reservation
}

# Sharing is for plain runs. An MW_PARALLEL run allocates per NUMA node and needs
# whole nodes, so it takes the machine and is never trimmed; other runs stay out of
# its way, and it will not start while somebody else is holding cores.
if [ "$mw_parallel" = "true" ] && [ -n "$run_id" ]; then
    if other_runs_hold_cpus; then
        echo -e "\e[1;31mMW_PARALLEL needs the whole machine, but other runs hold cores:\e[1;0m"
        sed 's/^/    /' "$CPU_RESERVATIONS" 2>/dev/null
        exit 2
    fi
    record_whole_machine_reservation
    trap release_cpu_reservation EXIT
elif [ -n "$run_id" ]; then
    if mw_run_is_live; then
        echo -e "\e[1;31mAn MW_PARALLEL run is using the whole machine; wait for it to finish.\e[1;0m"
        exit 2
    fi
    trap stop_cpu_rebalance EXIT
    reserve_cpus "$cpu_budget" || exit 2
    reserved_count=$(echo "$reserved_cpus" | tr ',' '\n' | grep -c .)
    args="$args -cpu_list=$reserved_cpus"
    total_usable_cores=$reserved_count
    echo "* Reserved $reserved_count core(s) for run '$run_id': $reserved_cpus"
    rebalance_cpus_periodically &
    rebalance_pid=$!
fi

auto_procs=1
numa_procs=1
mw_procs=1
if [ "$mw_parallel" = "true" ]; then
    numa_procs=$(numa_process_count)
    resolve_mw_workers_per_numa
    mw_procs=$((numa_procs * mw_workers_per_numa))
fi
parallel_ginkgo_args=
label_ginkgo_arg=

if [ -n "$label" ]; then
    label_ginkgo_arg="--label-filter=$label"
fi

case "$parallel" in
    auto)
        resolve_auto_process_count
        echo "* PARALLEL=auto resolved to $auto_procs processes ($total_usable_cores usable cores / $CPUS_PER_WORKER CPUs per worker)"
        parallel_ginkgo_args="-procs=$auto_procs"
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
    local status=$?
    if [ -f "$report_path" ]; then
        generated_reports+=("$report_path")
    fi
    return $status
}

combine_ginkgo_reports() {
    local reports=()
    local report

    for report in "${generated_reports[@]}"; do
        if [ -f "$report" ]; then
            reports+=("$report")
        fi
    done

    if [ ${#reports[@]} -eq 1 ]; then
        cp "${reports[0]}" summary/report.json
    elif [ ${#reports[@]} -gt 1 ]; then
        jq -s 'add' "${reports[@]}" > summary/report.json.tmp &&
            mv summary/report.json.tmp summary/report.json
    fi
}

format_elapsed_time() {
    local elapsed=$1
    printf '%02d:%02d:%02d' "$((elapsed / 3600))" "$(((elapsed % 3600) / 60))" "$((elapsed % 60))"
}

print_aggregate_summary() {
    local elapsed=$1
    local passed
    local failed
    local skipped
    local executed
    local selected

    read -r passed failed skipped < <(jq -r '
        [.[].SpecReports[] |
            select(.LeafNodeType == "It" and .NumAttempts > 0) |
            .State] as $states |
        [
            ($states | map(select(. == "passed")) | length),
            ($states | map(select(
                . == "failed" or . == "timedout" or . == "panicked" or
                . == "aborted" or . == "interrupted"
            )) | length),
            ($states | map(select(. == "skipped")) | length)
        ] | @tsv
    ' summary/report.json)
    executed=$((passed + failed))
    selected=$((executed + skipped))

    echo "*************************** AGGREGATE SUMMARY ***************************"
    echo "Selected: $selected | Executed: $executed | Passed: $passed | Failed: $failed | Skipped: $skipped"
    echo "Total time: $(format_elapsed_time "$elapsed")"
}

should_split_auto_mw_run() {
    [ "$parallel" = "auto" ] && [ "$mw_parallel" = "true" ] && [ "${tc_list:-all}" = "all" ] && [ -z "$label" ]
}

should_run_mw_only_numa() {
    [ "$parallel" = "auto" ] && [ "$mw_parallel" = "true" ] && \
        { [ "$label" = "MW" ] || [ "${tc_list:-all}" = "MW" ]; }
}

validate_auto_mw_run() {
    if [ "$parallel" = "auto" ] && [ "$mw_parallel" = "true" ] &&
        ! should_split_auto_mw_run && ! should_run_mw_only_numa; then
        echo -e "\e[1;31mMW_PARALLEL=true with PARALLEL=auto supports a full run, LABEL=MW, or TEST=MW\e[1;0m"
        return 2
    fi
}

run_mw_numa_ginkgo() {
    local report_path=$1
    local label_filter=$2
    local workers_per_numa=$3
    local filter_arg=
    local procs=$((numa_procs * workers_per_numa))

    if [ -n "$label_filter" ]; then
        filter_arg="--label-filter=$label_filter"
    fi

    export HST_MW_PARALLEL=true
    run_ginkgo "$report_path" "-procs=$procs $filter_arg" "-numa_per_process -numa_workers_per_node=$workers_per_numa"
}

run_mw_ginkgo_phases() {
    local report_suffix=$1
    local wide_status
    local narrow_status

    if [ "$mw_workers_per_numa" -eq 1 ]; then
        echo "* MW phase: $numa_procs NUMA-aware process(es) (${#numa_nodes[@]} NUMA node(s), 1 worker per NUMA node)"
        run_mw_numa_ginkgo "summary/report-mw${report_suffix}.json" "MW" 1
        return $?
    fi

    local wide_procs=$numa_procs
    local narrow_procs=$mw_procs
    echo "* MW wide phase: $wide_procs NUMA-aware process(es) (${#numa_nodes[@]} NUMA node(s), 1 worker per NUMA node)"
    run_mw_numa_ginkgo "summary/report-mw-wide${report_suffix}.json" "MW&&MWWide" 1
    wide_status=$?
    if [ $wide_status -ne 0 ]; then
        return $wide_status
    fi

    echo "* MW narrow phase: $narrow_procs NUMA-aware process(es) (${#numa_nodes[@]} NUMA node(s), $mw_workers_per_numa worker(s) per NUMA node)"
    run_mw_numa_ginkgo "summary/report-mw-narrow${report_suffix}.json" "MW&&!MWWide" "$mw_workers_per_numa"
    narrow_status=$?

    return $narrow_status
}

run_repeated_split_ginkgo() {
    local run_non_mw=$1
    local attempts=$((repeat + 1))
    local attempt
    local report_suffix
    local phase_status

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        report_suffix=
        if [ "$attempts" -gt 1 ]; then
            report_suffix="-attempt-$attempt"
            echo "* Split run attempt $attempt of $attempts"
        fi

        if [ "$run_non_mw" = "true" ]; then
            export HST_MW_PARALLEL=false
            run_ginkgo "summary/report-non-mw${report_suffix}.json" "$parallel_ginkgo_args --label-filter=!MW" ""
            phase_status=$?
            if [ $phase_status -ne 0 ]; then
                return $phase_status
            fi
        fi

        run_mw_ginkgo_phases "$report_suffix"
        phase_status=$?
        if [ $phase_status -ne 0 ]; then
            return $phase_status
        fi
    done
}

exit_status=0
run_start_seconds=$SECONDS
generated_reports=()

validate_auto_mw_run || exit $?

if should_split_auto_mw_run; then
    echo "* PARALLEL=auto with MW_PARALLEL=true: running non-MW specs with auto parallelism, then MW specs with NUMA-aware parallelism"
    echo "* non-MW phase: $auto_procs process(es)"

    run_repeated_split_ginkgo true
    exit_status=$?
    combine_ginkgo_reports
    if [ -f summary/report.json ]; then
        print_aggregate_summary "$((SECONDS - run_start_seconds))"
    fi
elif should_run_mw_only_numa; then
    echo "* PARALLEL=auto with MW_PARALLEL=true: running the MW-only selection with NUMA-aware parallelism"
    run_repeated_split_ginkgo false
    exit_status=$?
    combine_ginkgo_reports
    if [ -f summary/report.json ]; then
        print_aggregate_summary "$((SECONDS - run_start_seconds))"
    fi
else
    export HST_MW_PARALLEL="$mw_parallel"
    run_ginkgo "summary/report.json" "$parallel_ginkgo_args $label_ginkgo_arg --repeat=$repeat" ""
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
    jq -r '.[] | .SpecReports[] | select((.State == "failed") or (.State == "timedout") or (.State == "panicked") or (.State == "aborted") or (.State == "interrupted")) | select(.Failure != null) |
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
