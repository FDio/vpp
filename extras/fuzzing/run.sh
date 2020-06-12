#!/bin/bash -e

# Convenience functions

# Set these 3 variables
aflpath=~/fuzz/afl
ijonpath=~/fuzz/ijon
vpppath=~/fuzz/vpp

vpp=$vpppath/build-root/build-vpp_debug-native/vpp/bin/vpp
fuzzdir=$vpppath/extras/fuzzing
# Name of the generated startup file that will be used for each
# fuzzing or replay job
startupfile=startup.conf

clean() {
    pushd $fuzzdir || exit
    rm -fv full_*.conf
    rm -fv $startupfile
    rm -fv target.log.*
    rm -fv testbitmapsize.out
    popd || exit
}

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

# These settings are required by AFL
aflsetup() {
    sudo sh -c "echo core > /proc/sys/kernel/core_pattern"
    pushd /sys/devices/system/cpu || exit
    sudo sh -c "echo performance | tee cpu*/cpufreq/scaling_governor"
    popd || exit
}

# Build the patch to be applied to a freshly cloned
# version of the fuzzer
buildfuzzerpatch() {
    if [ $# != 1 ]; then
        echo "Usage: ./run.sh <fuzzer>"
        exit 1
    fi
    fuzzer=$1
    shift
    path=$(pathfromfuzzer "$fuzzer")
    pushd $path || exit
    git diff origin/master master | tee $fuzzdir/$fuzzer.patch
    popd || exit
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
}" > $startupfile

    echo "Built startup file $startupfile in $mode mode"
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

    prefixname=prefix_"$config".conf
    suffixname=suffix_"$mode"

    if [ ! -f $fuzzdir/"$prefixname" ]; then
        echo "$prefixname doesn't exist"
        exit 1
    fi

    if [ ! -f "$suffixname" ]; then
        echo "$suffixname doesn't exist"
        exit 1
    fi
    cat "$prefixname" "$suffixname" > full_"$config".conf
    echo "Joined $prefixname and $suffixname into full_$config.conf"
}

# Run fuzzing
fuzz() {
    if [ $# -lt 2 ]; then
        echo "Usage: ./run.sh fuzz <fuzzer> <config> [<fuzzer args>]"
        exit 1
    fi
    # name of the fuzzer
    fuzzer=$1
    shift
    # name of the config (e.g. ip4)
    config=$1
    shift

    path=$(pathfromfuzzer "$fuzzer")

    joinfiles fuzz "$config"
    buildstartupfile fuzz "$config"

    set -x
    sudo $path/afl-fuzz -t 30000 -m none "$@" -i fuzz_in_dir -o fuzz_out_dir $vpp -c $fuzzdir/$startupfile
    set +x
}

# Run VPP in replay mode. Inputs are then replayed from the CLI or via ./replay.py
replay() {
    if [ $# != 1 ]; then
        echo "Usage: ./run.sh replay <config>"
        exit 1
    fi
    # config name (e.g. ip4)
    config=$1
    shift

    joinfiles replay "$config"
    buildstartupfile replay "$config"

    sudo $vpp -c $fuzzdir/$startupfile
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

    pushd $path || exit
    make
    pushd llvm_mode || exit
    CC=clang-6.0 LLVM_CONFIG=llvm-config-6.0 make
    popd || exit
    popd || exit
}

# Compile VPP with the compiler of a fuzzer
vppmake() {
    if [ $# -lt 2 ]; then
        echo "Usage: ./run.sh vppmake <fuzzer> <arguments for make>"
        exit 1
    fi

    fuzzer=$1
    shift

    path=$(pathfromfuzzer "$fuzzer")
    export AFL_DONT_OPTIMIZE=1  # for debugging
    pushd $vpppath || exit
    CC=$path/afl-clang-fast make "$@"
    popd || exit
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

if [ $# = 0 ]; then
    echo "Usage: ./run.sh <function> <args>"
    exit 1
fi

"$@"
