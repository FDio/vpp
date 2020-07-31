#!/usr/bin/env -S python3 -u

"""Logic for the coverage step of testxor.py.
In a separate file in order to be run in parallel from containers."""

import sys

from coverage import Coverage
from testxor_params import *
from util import *

def main():
    vpp_path = sys.argv[1]
    inputs_dir = f"{vpp_path}/extras/fuzzing/fuzz_out_dir/queue"
    crashes_dir = f"{vpp_path}/extras/fuzzing/fuzz_out_dir/crashes"
    base_input = f"{vpp_path}/extras/fuzzing/fuzz_in_dir/init"
    cov = Coverage(config, inputs_dir=inputs_dir, crashes_dir=crashes_dir,
                   base_input=base_input, custom_vpp_path=vpp_path)
    cov.pre_coverage()
    cov.compute_baseline()
    cov.compute_coverage()
    cov.custom_report(do_filter=False)
    cov.custom_report(do_filter=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        fatal("Usage: ./testxor_cov_step.py <vpp path>")
    main()
