#!/usr/bin/env python3

# Parameters for the experiment
fuzzer = "afl"
ncores = 2 * 20  # evenly divided into one set per condition
duration = 24 * 3600  # in seconds
config = "ip4"
use_ASAN = True
# How long to run VPP in replay mode as a baseline for blackbox fuzzing
blackbox_baseline_duration = 5 * 60  # in seconds
# If the greybox condition has already been evaluated during another experiment
# if True, only the first half of ncores will be used.
only_blackbox = True
