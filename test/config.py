import argparse
import os
import psutil
import textwrap
import time


def positive_int_or_default(default):
    def positive_integer(v):
        if v is None or v == "":
            return default
        return int(v)
    return positive_integer


def positive_int_or_auto(v):
    if v is None or v in ("", "auto"):
        return "auto"
    if int(v) <= 0:
        raise ValueError("value must be positive or auto")
    return int(v)


def int_or_auto(v):
    if v is None or v in ("", "auto"):
        return "auto"
    if int(v) < 0:
        raise ValueError("value must be positive or auto")
    return int(v)


def int_choice_or_default(options, default):
    assert default in options

    def choice(v):
        if v is None or v == "":
            return default
        if int(v) in options:
            return int(v)
        raise ValueError("invalid choice")
    return choice


def worker_config(v):
    if v is None or v == "":
        return 0
    if v.startswith("workers "):
        return(int(v.split(" ")[1]))
    return int(v)


def directory(v):
    if not os.path.isdir(v):
        raise ValueError(f"provided path '{v}' doesn't exist "
                         "or is not a directory")
    return v


def directory_verify_or_create(v):
    if not os.path.isdir(v):
        os.mkdir(v)
    return v


parser = argparse.ArgumentParser(description="VPP unit tests",
                                 formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument("--failfast", action="store_true",
                    help="stop running tests on first failure")

parser.add_argument("--test-src-dir", action="append", type=directory,
                    help="directory containing test files "
                    "(may be specified multiple times) "
                    "(VPP_WS_DIR/test is added automatically to the set)")

default_verbose = 0

parser.add_argument("--verbose", action="store", default=default_verbose,
                    type=int_choice_or_default((0, 1, 2), default_verbose),
                    help="verbosity setting - 0 - least verbose, "
                    "2 - most verbose (default: 0)")

default_test_run_timeout = 600

parser.add_argument("--timeout", action="store",
                    type=positive_int_or_default(default_test_run_timeout),
                    default=default_test_run_timeout,
                    metavar="TEST_RUN_TIMEOUT",
                    help="test run timeout in seconds - per test "
                    f"(default: {default_test_run_timeout})")

parser.add_argument("--failed-dir", action="store", type=directory,
                    help="directory containing failed tests")

filter_help_string = """\
expression consists of 3 string selectors separated by '.' separators:

    <file>.<class>.<function>

- selectors restrict which files/classes/functions are run
- selector can be replaced with '*' or omitted entirely if not needed
- <file> selector is automatically prepended with 'test_' if required
- '.' separators are required only if selector(s) follow(s)

examples:

1. all of the following expressions are equivalent and will select
   all test classes and functions from test_bfd.py:
   'test_bfd' 'bfd' 'test_bfd..' 'bfd.' 'bfd.*.*' 'test_bfd.*.*'
2. 'bfd.BFDAPITestCase' selects all tests from test_bfd.py,
   which are part of BFDAPITestCase class
3. 'bfd.BFDAPITestCase.test_add_bfd' selects a single test named
   test_add_bfd from test_bfd.py/BFDAPITestCase
4. '.*.test_add_bfd' selects all test functions named test_add_bfd
   from all files/classes
"""
parser.add_argument("--filter", action="store",
                    metavar="FILTER_EXPRESSION", help=filter_help_string)

default_retries = 0

parser.add_argument("--retries", action="store", default=default_retries,
                    type=positive_int_or_default(default_retries),
                    help="retry failed tests RETRIES times")

parser.add_argument("--step", action="store_true", default=False,
                    help="enable stepping through tests")

debug_help_string = """\
attach     - attach to already running vpp
core       - detect coredump and load core in gdb on crash
gdb        - print VPP PID and pause allowing attaching gdb
gdbserver  - same as above, but run gdb in gdbserver
"""

parser.add_argument("--debug", action="store",
                    choices=["attach", "core", "gdb", "gdbserver"],
                    help=debug_help_string)

parser.add_argument("--debug-framework", action="store_true",
                    help="enable internal test framework debugging")

parser.add_argument("--compress-core", action="store_true",
                    help="compress core files if not debugging them")

parser.add_argument("--extended", action="store_true",
                    help="run extended tests")

parser.add_argument("--sanity", action="store_true",
                    help="perform sanity vpp run before running tests")

parser.add_argument("--force-foreground", action="store_true",
                    help="force running in foreground - don't fork")

parser.add_argument("--jobs", action="store", type=positive_int_or_auto,
                    default="auto", help="maximum concurrent test jobs")

parser.add_argument("--venv-dir", action="store",
                    type=directory, help="path to virtual environment")

default_rnd_seed = time.time()
parser.add_argument("--rnd-seed", action="store", default=default_rnd_seed,
                    type=positive_int_or_default(default_rnd_seed),
                    help="random generator seed (default: current time)")

parser.add_argument("--vpp-worker-count", action="store", type=worker_config,
                    default=0, help="number of vpp workers")

parser.add_argument("--gcov", action="store_true",
                    default=False, help="running gcov tests")

parser.add_argument("--cache-vpp-output", action="store_true", default=True,
                    help="cache VPP stdout/stderr and log as one block "
                    "after test finishes")

parser.add_argument("--vpp-ws-dir", action="store", required=True,
                    type=directory, help="vpp workspace directory")

parser.add_argument("--vpp-tag", action="store", default="vpp_debug",
                    metavar="VPP_TAG", required=True,
                    help="vpp tag (e.g. vpp, vpp_debug, vpp_gcov)")

parser.add_argument("--vpp", action="store", help="path to vpp binary "
                    "(default: derive from VPP_WS_DIR and VPP_TAG)")

parser.add_argument("--vpp-install-dir", type=directory,
                    action="store", help="path to vpp install directory"
                    "(default: derive from VPP_WS_DIR and VPP_TAG)")

parser.add_argument("--vpp-build-dir", action="store", type=directory,
                    help="vpp build directory"
                    "(default: derive from VPP_WS_DIR and VPP_TAG)")

parser.add_argument("--vpp-plugin-dir", action="append", type=directory,
                    help="directory containing vpp plugins"
                    "(default: derive from VPP_WS_DIR and VPP_TAG)")

parser.add_argument("--vpp-test-plugin-dir", action="append", type=directory,
                    help="directory containing vpp api test plugins"
                    "(default: derive from VPP_WS_DIR and VPP_TAG)")

parser.add_argument("--extern-plugin-dir", action="append", type=directory,
                    default=[], help="directory containing external plugins")

parser.add_argument("--extern-cov-dir", action="store", type=directory,
                    help="out-of-tree directory, where source, object and "
                    ".gcda files can be found for coverage report")

parser.add_argument("--vpp-coredump-size", action="store", default="unlimited",
                    help="specify vpp coredump size")

parser.add_argument("--limit-vpp-cpus", action="store", type=int_or_auto,
                    default=0, help="max cpus used by vpp")

variant_help_string = """\
specify which march node variant to unit test
  e.g. --variant=skx - test the skx march variants
  e.g. --variant=icl - test the icl march variants
"""

parser.add_argument("--variant", action="store", help=variant_help_string)

parser.add_argument("--api-fuzz", action="store", default=None,
                    help="specify api fuzzing parameters")

parser.add_argument("--wipe-tmp-dir", action="store_true", default=True,
                    help="remove test tmp directory before running test")

parser.add_argument("--tmp-dir", action="store", default="/tmp",
                    type=directory_verify_or_create,
                    help="directory where to store test temporary directories")

parser.add_argument("--log-dir", action="store",
                    type=directory_verify_or_create,
                    help="directory where to store directories "
                    "containing log files (default: TMP_DIR)")

default_keep_pcaps = False
parser.add_argument("--keep-pcaps", action="store_true",
                    default=default_keep_pcaps,
                    help="if set, keep all pcap files from a test run"
                    f" (default: {default_keep_pcaps})")

config = parser.parse_args()

ws = config.vpp_ws_dir
br = f"{ws}/build-root"
tag = config.vpp_tag

if config.vpp_install_dir is None:
    config.vpp_install_dir = f"{br}/install-{tag}-native"

if config.vpp is None:
    config.vpp = f"{config.vpp_install_dir}/vpp/bin/vpp"

if config.vpp_build_dir is None:
    config.vpp_build_dir = f"{br}/build-{tag}-native"

libs = ["lib", "lib64"]

if config.vpp_plugin_dir is None:
    config.vpp_plugin_dir = [
        f"{config.vpp_install_dir}/vpp/{lib}/vpp_plugins" for lib in libs]

if config.vpp_test_plugin_dir is None:
    config.vpp_test_plugin_dir = [
        f"{config.vpp_install_dir}/vpp/{lib}/vpp_api_test_plugins"
        for lib in libs]

test_dirs = [f"{ws}/test"]

if config.test_src_dir is not None:
    test_dirs.extend(config.test_src_dir)

config.test_src_dir = test_dirs


if config.venv_dir is None:
    config.venv_dir = f"{ws}/test/venv"

available_cpus = psutil.Process().cpu_affinity()
num_cpus = len(available_cpus)

max_vpp_cpus = config.limit_vpp_cpus

if config.limit_vpp_cpus == "auto":
    max_vpp_cpus = num_cpus
else:
    max_vpp_cpus = max(config.limit_vpp_cpus, num_cpus)

if __name__ == "__main__":
    print("Provided arguments:")
    for i in config.__dict__:
        print(f"  {i} is {config.__dict__[i]}")
