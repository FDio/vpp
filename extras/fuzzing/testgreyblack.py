#!/usr/bin/env -S python3 -u

"""
Compare blackbox and greybox fuzzing

Metrics:
- code coverage
- bugs found

Known issues:
- if a crash is found, blackbox fuzzing won't resume by itself

Checklist before running:
- review testgreyblack_params.py
- modify the C flags of GCOV compiling to make GCOV binaries look like debug
binaries, except with a few more coverage flags: add
"-fstack-protector", "-DFORTIFY_SOURCE=2" and "-fno-common" to
CMAKE_C_FLAGS_GCOV in src/CMakeLists.txt
- git clean -dfx build-root src test
- have enough containers ready and correctly named (./run.sh containerbuild...)
- echo core.%t > /proc/sys/kernel/core_pattern
- make sure pfuzz is not using the XOR approach
- make sure fuzz_in_dir is populated with a single file named "init" and
containing a packet corresponding to the packet produced by the config file
used (as blackbox fuzzing won't know about this file but will directly use
the packet produced by pg).
- make sure nothing's heavy in extras/fuzzing (it will be copied many times)
- make sure VPP is reverted to a state prior to the bug fixes
- make sure AFL_LOOP_ITERATIONS is set to e.g. 1 billion so that VPP never
restarts during fuzzing (which would produce a core dump per restart with ASAN
at the moment).
- make sure nothing's important in the container<n>_vpp directories
"""

import os
import sys
import time

from coverage import Coverage
from global_values import *
from testgreyblack_params import *
from util import *


n_used_cores = ncores // 2 if only_blackbox else ncores


def step_duplicate():
    """trim the VPP directory and duplicate it for each container;
    compile.
    This is not necessary for step_fuzz but it is for step_coverage
    as lcov updates .gcda files in-place.
    We need to compile individually in each new directory because
    gcov uses full paths (also safer for VPP)"""
    for i in range(n_used_cores):
        vpp_dir = f"{project_dir}/container{i}_vpp"
        system_wrapper(f"rm -rf {vpp_dir}")
        system_wrapper(f"cp -r {default_vpp_path} {vpp_dir}")
        if i < ncores // 2:  # blackbox
            # We only need one binary: gcov (+ ASAN)
            vpp_make(fuzzer=None, tag="gcov", build_type="gcov",
                     use_ASAN=use_ASAN, custom_vpp_path=vpp_dir)
            # Produce a zero.info file now because we won't be able to execute
            # pre_coverage() after fuzzing.
            cov = Coverage(config, custom_vpp_path=vpp_dir)
            cov.pre_coverage()
        else:  # greybox
            # We need 2 binaries: one for fuzzing (debug (+ ASAN)) and one for
            # coverage (gcov without ASAN, because with ASAN each input
            # produces a core dump on exit).
            vpp_make(fuzzer, tag="debug", build_type="debug",
                     use_ASAN=use_ASAN, custom_vpp_path=vpp_dir)
            vpp_make(fuzzer, tag="gcov", build_type="gcov",
                     use_ASAN=False, custom_vpp_path=vpp_dir)


def step_fuzz():
    """Start fuzzing on each container"""
    for i in range(n_used_cores):
        vpp_dir = f"{project_dir}/container{i}_vpp"
        build_exec_file("fuzz", config, custom_vpp_path=vpp_dir)
        startup_file = f"{vpp_dir}/extras/fuzzing/startup.conf"
        if i < ncores // 2:  # blackbox
            # We need coredumps for blackbox fuzzing, otherwise we would
            # never know about the crashes.
            build_startup_file("fuzz", config, custom_vpp_path=vpp_dir,
                               coredumps=True)
            vpp_bin = get_vpp_bin("gcov", custom_vpp_path=vpp_dir)
            fuzz_command = (
                f"PFUZZ_USE_BLACKBOX=1"
                f" {vpp_bin} -c {startup_file}"
            )
        else:  # greybox
            build_startup_file("fuzz", config, custom_vpp_path=vpp_dir,
                               coredumps=False)
            vpp_bin = get_vpp_bin("debug", custom_vpp_path=vpp_dir)
            fuzzer_path = path_from_fuzzer(fuzzer)
            fuzz_command = (
                "AFL_NO_AFFINITY=1"  # Tell AFL not to be clever with CPUs
                f" {fuzzer_path}/afl-fuzz -t 30000 -m none"
                f" -i fuzz_in_dir -o fuzz_out_dir"
                f" {vpp_bin} -c {startup_file}"
            )
        system_wrapper(
            f"docker container exec -dt -w {vpp_dir}/extras/fuzzing container{i}"
            f" bash -c '{fuzz_command}'"
        )


def step_wait():
    """Wait, then interrupt all fuzzers"""
    time.sleep(duration)
    for i in range(n_used_cores):
        system_wrapper(f"docker restart container{i}")


def step_coverage():
    """Analyze the code coverage of each instance"""
    # As this step is quite time-consuming, we also use the containers here.
    # This means we need to have the logic in a separate file: aux_file
    for i in range(n_used_cores):
        vpp_dir = f"{project_dir}/container{i}_vpp"
        aux_file = f"{vpp_dir}/extras/fuzzing/testgreyblack_cov_step.py"
        aux_file_out = f"{vpp_dir}/extras/fuzzing/testgreyblack_cov_step.out"
        condition = "blackbox" if i < ncores // 2 else "greybox"
        system_wrapper(
            f"docker container exec -dt container{i}"
            f" bash -c 'exec &> {aux_file_out} && {aux_file} {vpp_dir} {condition}'"
        )
    # Now manual step: inspect the results of all the
    # {vpp_dir}/build-root/html_cmp[_filt]


def step_bugs():
    """Find out the number of unique bugs found by each instance"""
    # We can't rely on AFL's classification of unique bugs, so we need
    # to replay each input classified as crashing, determine whether it
    # is still crashing, and if so inspect the core dump.
    # We don't perform these steps in parallel, as it would fill the
    # disk with core dumps.
    for i in range(n_used_cores):
        vpp_dir = f"{project_dir}/container{i}_vpp"
        fuzz_dir = f"{vpp_dir}/extras/fuzzing"
        # The blackbox condition only has a gcov binary, so for simplicity
        # use it in both cases. We won't look at the coverage output anymore.
        vpp_bin = get_vpp_bin("gcov", custom_vpp_path=vpp_dir)
        startup_file = f"{fuzz_dir}/startup.conf"
        out_file = f"{fuzz_dir}/bugs.out"

        # How many core dumps are there?
        cores = [f for f in os.listdir(fuzz_dir) if f.startswith("core.")]
        if i < ncores // 2:
            with open(out_file, "w") as f:
                f.write(f"blackbox: {len(cores)} crashes\n")
        else:  # greybox
            crashing_inputs_dir = f"{fuzz_dir}/fuzz_out_dir/crashes"
            # Replay all crashing inputs
            system_wrapper(
                f"cd {fuzz_dir}"
                f" && for input in {crashing_inputs_dir}/id*; do"  # don't replay the README
                f" [ -f \"$input\" ] || continue;"  # there may not be any files
                f" {vpp_bin} -c {startup_file} < $input;"
                " done",
                skip_failure=True  # the commands are expected to fail
            )
            # How many inputs were previously classified as crashing?
            crashing_inputs = [
                f for f in os.listdir(crashing_inputs_dir) if f.startswith("id")
            ]
            with open(out_file, "w") as f:
                f.write(f"greybox: {len(cores)} replicated out of"
                    f" {len(crashing_inputs)}\n")

        # Now analyze the coredumps superficially (look only at the backtrace)
        system_wrapper(
            f"cd {fuzz_dir}"
            f" && for core in core.*; do"
            f" [ -f \"$core\" ] || continue;"  # there may not be any core dumps
            f" gdb -q -nh -batch -ex 'set logging file {out_file}'"
            f" -ex 'set logging on' -ex bt -c $core {vpp_bin};"
            " done",
            skip_failure=True  # who knows. Will see the reason in out_file
        )
        system_wrapper(f"rm -f {fuzz_dir}/core.*")
        # Now manual step: inspect the produced out files to count the
        # number of unique bugs found by each fuzzer.


def main():
    if os.getuid() != 0:
        fatal("Must be run as root")

    step_duplicate()
    step_fuzz()
    step_wait()
    step_bugs()
    step_coverage()


if __name__ == "__main__":
    main()
