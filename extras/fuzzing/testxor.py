#!/usr/bin/env -S python3 -u

"""
Compare the results of:
- the XOR approach, where the initial input is only zeroes
and AFL's input is XORed with the current packet
- the "no XOR" approach, where the initial input is a valid
packet and AFL's input overwrites the current packet

Metrics:
- code coverage
- bugs found

Checklist before running:
- have enough containers ready and correctly named (./run.sh containerbuild...)
- echo core.%t > /proc/sys/kernel/core_pattern
- make sure fuzz_in_dir is populated with a single file named "init" and
containing a packet corresponding to the "no XOR" condition
- git clean -dfx build-root src test
- make sure nothing's heavy in extras/fuzzing (it will be copied many times)
- make sure VPP is reverted to a state prior to the bug fixes
- make sure "#define USE_XOR ..." is still used in src/plugins/pfuzz/node.c
- make sure AFL_LOOP_ITERATIONS is set to e.g. 1 billion so that VPP never
restarts during fuzzing (which would produce a core dump per restart with ASAN
at the moment).
- make sure nothing's important in the container<n>_vpp directories
"""

import os
import sys
import time

from global_values import *
from testxor_params import *
from util import *


def step_duplicate():
    """trim the VPP directory and duplicate it for each container;
    make the necessary changes; compile.
    This is not necessary for step_fuzz but it is for step_coverage
    as lcov updates .gcda files in-place.
    We need to compile individually in each new directory because
    gcov uses full paths (also safer for VPP)"""
    template_paths = {
        "xor": f"{project_dir}/vpp_xor_template",
        "noxor": f"{project_dir}/vpp_noxor_template",
    }
    for tag, use_xor in zip(("xor", "noxor"), (1, 0)):
        system_wrapper(f"rm -rf {template_paths[tag]}")
        system_wrapper(f"cp -r {default_vpp_path} {template_paths[tag]}")
        # Set USE_XOR to the correct value in the pfuzz node
        pfuzz_node_path = f"{template_paths[tag]}/src/plugins/pfuzz/node.c"
        system_wrapper(f"sed -ir 's/#define USE_XOR .*/#define USE_XOR {use_xor}/' {pfuzz_node_path}")

    # An input corresponding to "noxor" is already present in fuzz_in_dir/init.
    # Replace it with one of the same length but with only zeroes for the xor condition.
    init_filename = f"{template_paths['xor']}/extras/fuzzing/fuzz_in_dir/init"
    init_nbytes = os.stat(init_filename).st_size
    with open(init_filename, "wb") as f:
        f.write(b"\x00" * init_nbytes)

    # Now copy these templates to actual directories, and build
    for i in range(ncores):
        tag = "xor" if i < ncores // 2 else "noxor"
        vpp_dir = f"{project_dir}/container{i}_vpp"
        system_wrapper(f"rm -rf {vpp_dir}")
        system_wrapper(f"cp -r {template_paths[tag]} {vpp_dir}")
        # Build the 2 binaries we will need: one for fuzzing, one for coverage
        vpp_make(fuzzer, tag="debug", build_type="debug", use_ASAN=use_ASAN, custom_vpp_path=vpp_dir)
        # The gcov binary doesn't need ASAN as it will only be fed inputs
        # found to be non-crashing, and for which we only care about the
        # code coverage.
        vpp_make(fuzzer, tag="gcov", build_type="gcov", use_ASAN=False, custom_vpp_path=vpp_dir)


def step_fuzz():
    """Start fuzzing on each container"""
    fuzzer_path = path_from_fuzzer(fuzzer)
    for i in range(ncores):
        vpp_dir = f"{project_dir}/container{i}_vpp"
        build_exec_file("fuzz", config, custom_vpp_path=vpp_dir)
        build_startup_file("fuzz", config, custom_vpp_path=vpp_dir, coredumps=False)
        startup_file = f"{vpp_dir}/extras/fuzzing/startup.conf"
        vpp_bin = get_vpp_bin("debug", custom_vpp_path=vpp_dir)
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
    for i in range(ncores):
        system_wrapper(f"docker restart container{i}")


def step_coverage():
    """Analyze the code coverage of each instance"""
    # As this step is quite time-consuming, we also use the containers here.
    # This means we need to have the logic in a separate file: aux_file
    for i in range(ncores):
        vpp_dir = f"{project_dir}/container{i}_vpp"
        aux_file = f"{vpp_dir}/extras/fuzzing/testxor_cov_step.py"
        aux_file_out = f"{vpp_dir}/extras/fuzzing/testxor_cov_step.out"
        system_wrapper(
            f"docker container exec -dt container{i}"
            f" bash -c 'exec &> {aux_file_out} && {aux_file} {vpp_dir}'"
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
    for i in range(ncores):
        vpp_dir = f"{project_dir}/container{i}_vpp"
        fuzz_dir = f"{vpp_dir}/extras/fuzzing"
        vpp_bin = get_vpp_bin("debug", custom_vpp_path=vpp_dir)
        startup_file = f"{fuzz_dir}/startup.conf"
        crashing_inputs_dir = f"{fuzz_dir}/fuzz_out_dir/crashes"
        out_file = f"{fuzz_dir}/bugs.out"
        system_wrapper(
            f"cd {fuzz_dir}"
            # Replay all crashing inputs
            f" && for input in {crashing_inputs_dir}/id*; do"  # don't replay the README
            f" [ -f \"$input\" ] || continue;"  # there may not be any files
            f" {vpp_bin} -c {startup_file} < $input;"
            " done",
            skip_failure=True  # the commands are expected to fail
        )
        # How many core dumps are there?
        cores = [f for f in os.listdir(fuzz_dir) if f.startswith("core.")]
        # How many inputs were previously classified as crashing?
        crashing_inputs = [
            f for f in os.listdir(crashing_inputs_dir) if f.startswith("id")
        ]
        with open(out_file, "w") as f:
            f.write(f"{len(cores)} replicated out of {len(crashing_inputs)}\n")
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
