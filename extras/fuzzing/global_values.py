#!/usr/bin/env python3

# SET MANUALLY
# (not using os.path.expanduser() because this script is sometimes run as root)
project_dir = "/home/tichauvi/fuzz"

fuzzer_paths = {
    "afl": f"{project_dir}/afl",
    "ijon": f"{project_dir}/ijon",
}
default_vpp_path = f"{project_dir}/vpp"
default_fuzzdir = f"{default_vpp_path}/extras/fuzzing"
default_startup_file = f"{default_fuzzdir}/startup.conf"
ASAN_flag = "VPP_EXTRA_CMAKE_ARGS=-DVPP_ENABLE_SANITIZE_ADDR=ON"
