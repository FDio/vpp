#!/bin/bash -e

# WARNING this code is (was) in the process of being transitioned to Python
# for better extensibility and functionality. Some functions below already
# have better alternatives which should be used (but they remain here because
# of dependencies).


# Set these 3 variables
aflpath=~/fuzz/afl
ijonpath=~/fuzz/ijon
vpppath=~/fuzz/vpp

fuzzdir=$vpppath/extras/fuzzing
# Name of the generated startup file that will be used for each
# fuzzing or replay job
startupfile=startup.conf
ASANFLAG="VPP_EXTRA_CMAKE_ARGS=-DVPP_ENABLE_SANITIZE_ADDR=ON"

# Echo the path corresponding to the given fuzzer name
pathfromfuzzer() {
    fuzzer=$1
    shift
    case $fuzzer in
        afl) echo $aflpath;;
        ijon) echo $ijonpath;;
        *) >&2 echo "Wrong fuzzer name"; exit 1;;
    esac
}

getvppbin() {
    if [ $# != 1 ]; then
        echo "Usage: ./run.sh getvppbin <tag>"
        exit 1
    fi
    tag=$1
    shift
    echo "$vpppath/build-root/build-vpp_${tag}-native/vpp/bin/vpp"
}

# These settings are required by AFL
aflsetup() {
    sudo sh -c "echo core.%t > /proc/sys/kernel/core_pattern"
    pushd /sys/devices/system/cpu || exit 1
    sudo sh -c "echo performance | tee cpu*/cpufreq/scaling_governor"
    popd || exit 1
}

# Build the patch to be applied to a freshly cloned
# version of the fuzzer
buildfuzzerpatch() {
    if [ $# != 1 ]; then
        echo "Usage: ./run.sh buildfuzzerpatch <fuzzer>"
        exit 1
    fi
    fuzzer=$1
    shift
    path=$(pathfromfuzzer $fuzzer)
    pushd $path || exit 1
    git diff origin/master master | tee $fuzzdir/$fuzzer.patch
    popd || exit 1
}

# Build the startup file supplied to VPP (vpp -c ...) with the given options
buildstartupfile() {
    if [ $# != 2 ]; then
        echo "Usage: ./run.sh buildstartupfile <mode> <config>"
        exit 1
    fi
    # mode: (fuzz|replay)
    mode=$1
    shift
    # name of the config (e.g. ip4 for full_ip4.conf)
    config=$1
    shift

    configfile=full_"$config".conf
    if [ ! -f "$configfile" ]; then
        echo "$configfile doesn't exist"
        exit 1
    fi
    case $mode in
        fuzz) maybe_cli="";;
        replay) maybe_cli="cli-listen localhost:5002";;
    esac
    echo \
"unix {
    nodaemon
    coredump-size unlimited
    full-coredump
    $maybe_cli
    exec $fuzzdir/$configfile
}

plugins {
    plugin pfuzz_plugin.so { enable }
    plugin dpdk_plugin.so { disable }
}" > $startupfile

    echo "Built startup file $startupfile in $mode mode"
}

buildmaketeststartupfiles() {
    if [ $# != 3 ]; then
        echo "Usage: ./run.sh buildmaketeststartupfiles <mode> <API trace file> <PG capture file>"
        exit 1
    fi
    mode=$1
    shift
    apitrace=$1
    shift
    pgcapture=$1
    shift

    # Both $apitrace and $pgcapture are (or should be) in the format:
    # latest_(trace|pcap).testname.sw_if_index
    # So we retrieve the sw_if_index like so:
    sw_if_index=${apitrace##*.}

    configfile=full_maketest.conf
    # build config file
    rm -f $configfile
    # Create a large number of loops to be sure the one
    # used in the test is here
    for _ in {1..20}; do
        echo "loop create" >> $configfile
    done
    n=$((sw_if_index - 1))
    echo \
"api trace replay $apitrace
packet-generator new {
    pcap $pgcapture
    interface loop$n
    limit -1
}" >> $configfile
    if [ "$mode" = "replay" ]; then
        echo "pfuzz enable loop$n mode-replay" >> $configfile
    else
        echo "pfuzz enable loop$n" >> $configfile
    fi
    echo "packet-generator enable" >> $configfile
    # TODO differentiate according to mode (fuzz or replay).

    # Build startup file
    buildstartupfile "$mode" maketest
}

# Join a config (prefix) with commands specific to replay / fuzzing (suffix)
joinfiles() {
    if [ $# != 2 ]; then
        echo "Usage: ./run.sh joinfiles <mode> <config>"
        exit 1
    fi
    # mode: (fuzz|replay)
    mode=$1
    shift
    # name of the config
    config=$1
    shift

    prefixname=prefix_"$config"
    suffixname=suffix_"$mode"

    if [ ! -f $fuzzdir/"$prefixname" ]; then
        echo "$prefixname doesn't exist"
        exit 1
    fi

    if [ ! -f "$suffixname" ]; then
        echo "$suffixname doesn't exist"
        exit 1
    fi
    cat "$prefixname" "$suffixname" > full_"$config"_"$mode".conf
    echo "Joined $prefixname and $suffixname into full_${config}_$mode.conf"
}

# Run fuzzing
fuzz() {
    if [ $# -lt 3 ]; then
        echo "Usage: ./run.sh fuzz <tag> <fuzzer> <config> [<fuzzer args>]"
        exit 1
    fi
    # tag (e.g. debug)
    tag=$1
    shift
    # name of the fuzzer
    fuzzer=$1
    shift
    # name of the config (e.g. ip4 / maketest)
    config=$1
    shift

    path=$(pathfromfuzzer "$fuzzer")

    if [ "$config" = "maketest" ]; then
        if [ ! -f "full_maketest.conf" ]; then
            echo "Run ./run.sh buildmaketeststartupfiles first"
            exit 1
        fi
    else
        joinfiles fuzz "$config"
        buildstartupfile fuzz "$config"
    fi

    vppbin=$(getvppbin "$tag")
    set -x
    sudo $path/afl-fuzz -t 30000 -m none "$@" -i fuzz_in_dir -o fuzz_out_dir "$vppbin" -c $fuzzdir/$startupfile
    set +x
}

# Run VPP in replay mode. Inputs are then replayed from the CLI or via ./replay.py
replay() {
    if [ $# != 2 ]; then
        echo "Usage: ./run.sh replay <tag> <config>"
        exit 1
    fi
    tag=$1
    shift
    config=$1
    shift

    if [ "$config" = "maketest" ]; then
        if [ ! -f "full_maketest.conf" ]; then
            echo "Run ./run.sh buildmaketeststartupfiles first"
            exit 1
        fi
    else
        joinfiles replay "$config"
        buildstartupfile replay "$config"
    fi

    vppbin=$(getvppbin "$tag")
    sudo $vppbin -c $fuzzdir/$startupfile
}

# Compile the fuzzers
fuzzmake() {
    if [ $# != 1 ]; then
        echo "Usage: ./run.sh fuzzmake <fuzzer>"
        exit 1
    fi

    fuzzer=$1
    shift

    path=$(pathfromfuzzer "$fuzzer")

    export CC=clang-9
    export LLVM_CONFIG=llvm-config-9
    make -C $path
    make -C $path/llvm_mode
}

# Compile VPP with the compiler of a fuzzer, and a specific tag
vppmake() {
    if [ $# != 3 ]; then
        echo "Usage: ./run.sh vppmake <fuzzer> <tag (e.g. debug)> (asan|noasan)"
        exit 1
    fi
    fuzzer=$1
    shift
    tag=$1
    shift
    useASAN=$1
    shift
    if [ "$useASAN" = "asan" ]; then
        maybeASAN=$ASANFLAG
    else
        maybeASAN=
    fi

    # Before building, we want to make sure the tag
    # is associated to a build type. If it's not, we
    # associate it with debug.
    buildtype="vpp_${tag}_TAG_BUILD_TYPE"
    file=$vpppath/build-data/platforms/vpp.mk
    if ! grep "$buildtype" $file; then
        line="$buildtype = debug"
        echo "Adding '$line' to $file"
        echo "$line" >> $file
    fi

    path=$(pathfromfuzzer "$fuzzer")
    export AFL_DONT_OPTIMIZE=1  # for debugging
    pushd $vpppath || exit 1
    CC=$path/afl-clang-fast make -C build-root PLATFORM=vpp TAG=vpp_"$tag" vpp-install $maybeASAN
    popd || exit 1
}

# Steps to perform before running inputs for coverage
precoverage() {
    if [ $# != 1 ]; then
        echo "Usage: ./run.sh precoverage <config>"
        exit 1
    fi
    config=$1
    shift

    # Build $startupfile
    joinfiles fuzz "$config"
    buildstartupfile fuzz "$config"

    pushd $vpppath/build-root || exit 1
    # Start with some cleanup
    rm -f -- *.info
    lcov --zerocounters --directory .

    # Produce .gcda files with zero coverage, to ensure percentages are
    # correct even if not all source code files are loaded during tests
    lcov --capture --initial --directory . --output-file zero.info
    popd || exit 1
}

# Get the code coverage of null inputs corresponding to some inputs
getbaseline() {
    if [ $# -lt 1 ]; then
        echo "Usage: ./run.sh getbaseline <future inputs (absolute paths)>"
        exit 1
    fi
    inputs=("$@")

    pushd $vpppath/build-root || exit 1
    # Zero out counters (remove all .gcda files)
    lcov --zerocounters --directory .

    # Run as many empty inputs as there are inputs supplied
    for _ in "${inputs[@]}"; do
        sudo $vppcov -c $fuzzdir/$startupfile < /dev/null
    done
    # Get the coverage
    lcov --no-checksum --directory . --capture --gcov-tool $fuzzdir/gcov_for_clang.sh -o baseline.info
    # Remove unwanted stuff from the coverage
    lcov --remove baseline.info \
       "/usr/include/*" "*/build-root/*" "/opt/*" "/usr/lib/*" \
       -o baseline_filtered.info
    # Zero out counters again
    lcov --zerocounters --directory .
    popd || exit 1
}

# Get the code coverage for some inputs
getcoverage() {
    if [ $# -lt 1 ]; then
        echo "Usage: ./run.sh getcoverage <inputs (absolute paths)>"
        exit 1
    fi
    inputs=("$@")

    pushd $vpppath/build-root || exit 1
    # Run the inputs
    for input in "${inputs[@]}"; do
        sudo $vppcov -c $fuzzdir/$startupfile < "$input"
    done
    # Retrieve the coverage
    lcov --no-checksum --directory . --capture --gcov-tool $fuzzdir/gcov_for_clang.sh -o out.info
    # Combine with zero.info, in case some files haven't
    # been loaded and would otherwise skew percentages
    lcov --add-tracefile zero.info --add-tracefile out.info -o total.info
    # Remove unwanted stuff from the coverage
    lcov --remove total.info \
       "/usr/include/*" "*/build-root/*" "/opt/*" "/usr/lib/*" \
       -o total_filtered.info
    genhtml baseline_filtered.info -o html_base
    genhtml total_filtered.info -o html_full
    genhtml --baseline-file baseline_filtered.info total_filtered.info -o html_diff
    genhtml --baseline-file total_filtered.info baseline_filtered.info -o html_diff_rev
    echo "All done, see:"
    echo "  - build-root/html_base/index.html for the baseline"
    echo "  - build-root/html_full/index.html for the full coverage"
    echo "  - build-root/html_diff/index.html for the diff with baseline"
    echo "  - build-root/html_diff_rev/index.html for the reverse diff"
    popd || exit 1
}

# A shortcut for all the steps necessary for coverage
coverage() {
    if [ $# -lt 2 ]; then
        echo "Usage: ./run.sh coverage <config> <inputs>"
        exit 1
    fi
    config=$1
    shift

    vppcovmake
    precoverage "$config"
    getbaseline "$@"
    getcoverage "$@"
}

# Find the sources of the low stability, going through the graph
# 1 time and 1,000 times.
teststability() {
    if [ $# != 2 ]; then
        echo "Usage: ./run.sh teststability <config> <findings directory (full path)>"
        exit 1
    fi
    config=$1
    shift
    outdir=$1
    shift

    for iter in 1 1000; do
        mkdir -p "$outdir/$iter"
        sed -ir "s/#define TEST_STABILITY_ITERATIONS .*/#define TEST_STABILITY_ITERATIONS $iter/" $vpppath/src/plugins/pfuzz/node.c
        # Checking
        awk '/#define TEST_STABILITY_ITERATIONS/' $vpppath/src/plugins/pfuzz/node.c
        coverage "$config" /dev/null
        pushd $vpppath/build-root || exit 1
        mv *.info html_* "$outdir/$iter"
        popd || exit 1
    done
    echo "All done, see $outdir"
}

# Classify the traces produced by ./replay.py into unique traces
classify() {
    if [ $# != 1 ]; then
        echo "Usage: ./run.sh classify <directory with .trace files>"
        exit 1
    fi
    # a directory containing traces produced by ./replay.py
    path=$1
    shift

    # Output: one line for each unique trace
    grep -P "^[\d:]+\s" "$path"/*.trace | \
        awk '{print $2;}' | \
        sed 's/pg-input/#pg-input/' | \
        tr -s '\r\n' ' ' | \
        tr '#' '\n' | \
        sort | uniq
}

# Test stability and execution speed with different bitmap sizes
testbitmapsize() {
    if [ $# != 5 ]; then
        echo "Usage: sudo ./run.sh testbitmapsize <fuzzer> <config> <start> <end> <number of paths>"
        echo "The range [2^start, 2^end] (included) will be tested."
        exit 1
    fi
    fuzzer=$1
    shift
    config=$1
    shift
    start=$1
    shift
    end=$1
    shift
    npaths=$1
    shift

    if [ $start -lt 16 ]; then
        echo "AFL doesn't work with values below 16"
        exit 1
    fi

    out=$fuzzdir/testbitmapsize.out
    rm -f $out
    stabfile=$fuzzdir/fuzz_out_dir/stabilities
    statsfile=$fuzzdir/fuzz_out_dir/fuzzer_stats
    path=$(pathfromfuzzer "$fuzzer")
    saved=$(grep '#define MAP_SIZE_POW2' $path/config.h | awk '{ print $3; }')
    echo "Saved value: $saved"
    for size in $(seq "$start" "$end"); do
        sed -ir "s/#define MAP_SIZE_POW2.*/#define MAP_SIZE_POW2       $size/" $path/config.h
        grep '#define MAP_SIZE_POW2' $path/config.h | tee -a $out
        # Recompile the fuzzer, then VPP
        fuzzmake $fuzzer
        vppmake $fuzzer rebuild
        # Run fuzzing, capped at $npaths new paths
        fuzz $fuzzer "$config" -s "$npaths"
        sudo chown -R $USER:$USER fuzz_out_dir
        # Now look at stabilities
        {
            echo -n "Stability: "
            tail -n 1 $stabfile
            echo -n "Bitmap coverage: "
            awk '/bitmap_cvg/ { print $3; }' $statsfile
            echo -n "Exec speed: "
            start_time=$(awk '/start_time/ { print $3; }' $statsfile)
            stop_time=$(awk '/last_update/ { print $3; }' $statsfile)
            execs=$(awk '/execs_done/ { print $3; }' $statsfile)
            execspeed=$(( execs / (stop_time - start_time) ))
            echo "$execspeed execs/s"
        } | tee -a $out
    done
    # Restore the bitmap size to its previous value
    sed -ir "s/#define MAP_SIZE_POW2.*/#define MAP_SIZE_POW2       $saved/" $path/config.h
    grep '#define MAP_SIZE_POW2' $path/config.h
    fuzzmake $fuzzer
    vppmake $fuzzer rebuild
}

# Test stability and bitmap coverage with different vector sizes
testvectorsize() {
    if [ $# != 6 ]; then
        echo "Usage: sudo ./run.sh testvectorsize <fuzzer> <config> <start (included)> <end (included)> <number of paths> <number of measures per point>"
        exit 1
    fi
    fuzzer=$1
    shift
    config=$1
    shift
    start=$1
    shift
    end=$1
    shift
    npaths=$1
    shift
    nmeasures=$1
    shift

    out=$fuzzdir/testvectorsize.out
    rm -f $out
    stabfile=$fuzzdir/fuzz_out_dir/stabilities
    cvgfile=$fuzzdir/fuzz_out_dir/bitmap_coverages
    path=$(pathfromfuzzer "$fuzzer")
    # Initialization
    fuzzmake $fuzzer
    vppmake $fuzzer build
    # Explain the structure of $out
    echo "# <vector size> <n (nth measure)>: <stability> <bitmap coverage>" > $out
    for vecsize in $(seq "$start" "$end"); do
        sed -ir "s/    maxframe.*/    maxframe $vecsize/" $fuzzdir/prefix_"$config".conf
        for i in $(seq 1 "$nmeasures"); do
            sudo rm -rf fuzz_out_dir
            # Run fuzzing, capped at $npaths new paths
            fuzz $fuzzer "$config" -s "$npaths" > /dev/null
            sudo pkill -KILL vpp
            sudo chown -R $USER:$USER fuzz_out_dir
            stability=$(tail -n 1 $stabfile | awk '{ print $2; }')
            coverage=$(tail -n 1 $cvgfile | awk '{ print $2; }')
            echo "$vecsize $i: $stability $coverage" | tee -a $out
        done
    done
}

# Create a range of Docker containers
containerbuild() {
    if [ $# != 2 ]; then
        echo "Usage: ./run.sh containerbuild <n0> <n1>"
        echo "Builds containers named container<n0> to container<n1>"
        echo "The containers will be bound to CPUs <n0> to <n1>"
        echo "(CPU count starts at 0)"
        exit 1
    fi
    n0=$1
    shift
    n1=$1
    shift
    for i in $(seq "$n0" "$n1"); do
        name="container$i"
        echo "Building $name..."
        docker run --name $name --privileged -v $HOME:$HOME -v /dev:/dev \
            -v /usr:/usr:ro -v /lib:/lib:ro --cpuset-cpus=$i \
            -td ubuntu:18.04 /bin/bash
        echo "Done"
    done
}

# Run fuzzing on a range of containers
containerfuzz() {
    if [ $# -lt 5 ]; then
        echo "Usage: ./run.sh containerfuzz <n0> <n1> <tag> <fuzzer> <config> [<fuzzer args>]"
        exit 1
    fi
    n0=$1
    shift
    n1=$1
    shift
    tag=$1
    shift
    fuzzer=$1
    shift
    config=$1
    shift

    path=$(pathfromfuzzer "$fuzzer")
    vppbin=$(getvppbin "$tag")
    joinfiles fuzz "$config"
    buildstartupfile fuzz "$config"
    # The first container is the master process
    docker container exec -dt -w $fuzzdir "container$n0" bash -c "AFL_NO_AFFINITY=1 $path/afl-fuzz -t 60000 -m none $@ -i fuzz_in_dir -o fuzz_sync_dir -M fuzzer$n0 $vppbin -c $fuzzdir/$startupfile"
    echo "Started container$n0"

    # The other containers are secondary processes
    for i in $(seq $((n0+1)) "$n1"); do
        docker container exec -dt -w $fuzzdir "container$i" bash -c "AFL_NO_AFFINITY=1 $path/afl-fuzz -t 60000 -m none $@ -i fuzz_in_dir -o fuzz_sync_dir -S fuzzer$i $vppbin -c $fuzzdir/$startupfile"
        echo "Started container$i"
    done
}

# Run a docker command on each container in a range
containerrun() {
    if [ $# != 3 ]; then
        echo "Usage: ./run.sh containerrun <n0> <n1> <docker command>"
        echo "sudo docker <docker command> container\$i will then be run"
        echo "for each i between n0 and n1."
        exit 1
    fi
    n0=$1
    shift
    n1=$1
    shift
    command=$1
    shift

    for i in $(seq "$n0" "$n1"); do
        sudo docker "$command" "container$i"
    done
}

if [ $# = 0 ]; then
    echo "Usage: ./run.sh <function> <args>"
    exit 1
fi

# Global variables that need to be generated by functions
vppcov=$(getvppbin gcov)

# Execute the given function
"$@"
