# Convenience functions

# Set these 2 variables
aflpath=~/fuzz/afl
vpppath=~/fuzz/vpp

vpp=$vpppath/build-root/build-vpp_debug-native/vpp/bin/vpp
fuzzdir=$vpppath/extras/fuzzing

# These settings are required by AFL
afl-setup() {
    sudo sh -c "echo core > /proc/sys/kernel/core_pattern"
    pushd /sys/devices/system/cpu
    sudo sh -c "echo performance | tee cpu*/cpufreq/scaling_governor"
    popd
}

fuzz() {
    sudo $aflpath/afl-fuzz -t 10000 -m none -i fuzz_in_dir -o fuzz_out_dir $vpp -c $fuzzdir/startup_fuzz.conf
}

fuzz-resume() {
    sudo $aflpath/afl-fuzz -t 10000 -m none -i- -o fuzz_out_dir $vpp -c $fuzzdir/startup_fuzz.conf
}

replay() {
    sudo $vpp -c $fuzzdir/startup_replay.conf
}

fuzz-make() {
    # Argument 1: argument for make (build / rebuild...)
    export AFL_DONT_OPTIMIZE=1  # for debugging
    pushd $vpppath
    CC=$aflpath/afl-clang-fast make $1
    popd
}

case $1 in
    afl-setup) afl-setup;;
    fuzz) fuzz;;
    fuzz-resume) fuzz-resume;;
    replay) replay;;
    fuzz-make) fuzz-make $2;;
esac
