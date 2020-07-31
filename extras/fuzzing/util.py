#!/usr/bin/env -S python3 -u

"""Utility functions for fuzzing and related tasks"""

import os
import sys

from global_values import *


def fatal(errmsg):
    print(f"[-] {errmsg}")
    sys.exit(1)


def system_wrapper(cmd, skip_failure=False):
    """Wrapper around os.system() printing the executed
    command and checking the return value"""
    print(f"[*] os.system(): {cmd}")
    ret = os.system(cmd)
    if ret == 0:
        print("[+] Success")
    else:
        function = print if skip_failure else fatal
        function(f"os.system() failed with return code {ret}")

def path_from_fuzzer(fuzzer):
    """From a fuzzer name, return its base directory"""
    if fuzzer not in fuzzer_paths.keys():
        fatal("unknown fuzzer name")
    return fuzzer_paths[fuzzer]


def get_vpp_bin(tag, custom_vpp_path=None):
    vpp_path = custom_vpp_path or default_vpp_path
    return f"{vpp_path}/build-root/build-vpp_{tag}-native/vpp/bin/vpp"


def build_exec_file(mode, config, custom_vpp_path=None):
    """Create the config file to be called from the startup file.
    Method: concatenate prefix_{config} with suffix_{mode}
    if these files exist."""
    vpp_path = custom_vpp_path or default_vpp_path
    fuzzdir = f"{vpp_path}/extras/fuzzing"
    prefix_file = f"{fuzzdir}/prefix_{config}"
    suffix_file = f"{fuzzdir}/suffix_{mode}"
    full_file = f"{fuzzdir}/full_{config}_{mode}"
    if not (os.path.exists(prefix_file) and os.path.exists(suffix_file)):
        fatal(f"one of {prefix_file} or {suffix_file} doesn't exist")
    system_wrapper(f"cat {prefix_file} {suffix_file} > {full_file}")


def build_startup_file(mode, config, custom_vpp_path=None, coredumps=True,
                       do_cli_listen=None):
    """Create the startup file for VPP"""
    vpp_path = custom_vpp_path or default_vpp_path
    fuzzdir = f"{vpp_path}/extras/fuzzing"
    exec_file = f"{fuzzdir}/full_{config}_{mode}"
    startup_file = f"{fuzzdir}/startup.conf"
    maybe_coredumps = coredumps * (
        "coredump-size unlimited\n"
        "full-coredump\n"
    )
    if do_cli_listen is None:
        do_cli_listen = (mode == "replay")
    maybe_cli = do_cli_listen * "cli-listen localhost:5002\n"
    content = (
        "unix {\n"
        "nodaemon\n"
        f"{maybe_coredumps}"
        f"{maybe_cli}"
        f"exec {exec_file}\n"
        "}\n"
        "plugins {\n"
        "plugin pfuzz_plugin.so { enable }\n"
        # DPDK causes issues with parallel fuzzing because it wants to bind to a CPU core
        "plugin dpdk_plugin.so { disable }\n"
        "}\n"
    )
    with open(startup_file, "w") as f:
        f.write(content)
    print(f"[+] Built startup file {startup_file} in {mode} mode")


def vpp_make(fuzzer, tag="debug", build_type="debug", use_ASAN=True, custom_vpp_path=None):
    """Compile VPP with the compiler of `fuzzer` (or the default compiler
    if fuzzer is None), an arbitrary tag and a specific build type."""
    # Before building, we want to make sure the tag is associated
    # to the build type.
    vpp_path = custom_vpp_path or default_vpp_path
    vppmk = f"{vpp_path}/build-data/platforms/vpp.mk"
    prefix = f"vpp_{tag}_TAG_BUILD_TYPE"
    full_line = f"{prefix} = {build_type}\n"
    found_prefix = False
    found_full_line = False
    for line in open(vppmk):
        if prefix in line:
            found_prefix = True
        if full_line == line:
            found_full_line = True
    if not found_full_line:
        if found_prefix:
            fatal(f"A conflicting line already exists in {vppmk}")
        else:
            with open(vppmk, "w") as f:
                f.write(full_line)
                print(f"[+] Added '{full_line}' to {vppmk}")

    # Now build
    if fuzzer is not None:
        CC = f" CC={path_from_fuzzer(fuzzer)}/afl-clang-fast"
    else:
        CC = ""  # default compiler
    asan = ASAN_flag if use_ASAN else ""
    system_wrapper(
        "AFL_DONT_OPTIMIZE=1"
        f"{CC}"
        f" make -C {vpp_path}/build-root"
        f" PLATFORM=vpp TAG=vpp_{tag} vpp-install {asan}"
    )
