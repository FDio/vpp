#!/usr/bin/env python3

# Parameters for the experiment
fuzzer = "afl"
ncores = 2 * 20  # evenly divided into one set per condition
duration = 24 * 3600  # in seconds
config = "ip4"
use_ASAN = True
