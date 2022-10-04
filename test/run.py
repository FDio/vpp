#!/usr/bin/env python3
#
# Copyright (c) 2022 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build the Virtual Environment & run VPP unit tests

import argparse
import glob
import logging
import os
from pathlib import Path
import signal
from subprocess import Popen, PIPE, STDOUT, call
import sys
import time
import venv
import datetime
import re


# Required Std. Path Variables
test_dir = os.path.dirname(os.path.realpath(__file__))
ws_root = os.path.dirname(test_dir)
build_root = os.path.join(ws_root, "build-root")
venv_dir = os.path.join(build_root, "test", "venv")
venv_bin_dir = os.path.join(venv_dir, "bin")
venv_lib_dir = os.path.join(venv_dir, "lib")
venv_run_dir = os.path.join(venv_dir, "run")
venv_install_done = os.path.join(venv_run_dir, "venv_install.done")
papi_python_src_dir = os.path.join(ws_root, "src", "vpp-api", "python")

# Path Variables Set after VPP Build/Install
vpp_build_dir = vpp_install_path = vpp_bin = vpp_lib = vpp_lib64 = None
vpp_plugin_path = vpp_test_plugin_path = ld_library_path = None

# Pip version pinning
pip_version = "22.0.4"
pip_tools_version = "6.6.0"

# Test requirement files
test_requirements_file = os.path.join(test_dir, "requirements.txt")
# Auto-generated requirement file
pip_compiled_requirements_file = os.path.join(test_dir, "requirements-3.txt")


# Gracefully exit after executing cleanup scripts
# upon receiving a SIGINT or SIGTERM
def handler(signum, frame):
    print("Received Signal {0}".format(signum))
    post_vm_test_run()


signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)


def show_progress(stream, exclude_pattern=None):
    """
    Read lines from a subprocess stdout/stderr streams and write
    to sys.stdout & the logfile

    arguments:
    stream - subprocess stdout or stderr data stream
    exclude_pattern - lines matching this reg-ex will be excluded
                      from stdout.
    """
    while True:
        s = stream.readline()
        if not s:
            break
        data = s.decode("utf-8")
        # Filter the annoying SIGTERM signal from the output when VPP is
        # terminated after a test run
        if "SIGTERM" not in data:
            if exclude_pattern is not None:
                if bool(re.search(exclude_pattern, data)) is False:
                    sys.stdout.write(data)
            else:
                sys.stdout.write(data)
            logging.debug(data)
        sys.stdout.flush()
    stream.close()


class ExtendedEnvBuilder(venv.EnvBuilder):
    """
    1. Builds a Virtual Environment for running VPP unit tests
    2. Installs all necessary scripts, pkgs & patches into the vEnv
         - python3, pip, pip-tools, papi, scapy patches &
           test-requirement pkgs
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def post_setup(self, context):
        """
        Setup all packages that need to be pre-installed into the venv
        prior to running VPP unit tests.

        :param context: The context of the virtual environment creation
                        request being processed.
        """
        os.environ["VIRTUAL_ENV"] = context.env_dir
        os.environ[
            "CUSTOM_COMPILE_COMMAND"
        ] = "make test-refresh-deps (or update requirements.txt)"
        # Cleanup previously auto-generated pip req. file
        try:
            os.unlink(pip_compiled_requirements_file)
        except OSError:
            pass
        # Set the venv python executable & binary install path
        env_exe = context.env_exe
        bin_path = context.bin_path
        # Packages/requirements to be installed in the venv
        # [python-module, cmdline-args, package-name_or_requirements-file-name]
        test_req = [
            ["pip", "install", "pip===%s" % pip_version],
            ["pip", "install", "pip-tools===%s" % pip_tools_version],
            [
                "piptools",
                "compile",
                "-q",
                "--generate-hashes",
                test_requirements_file,
                "--output-file",
                pip_compiled_requirements_file,
            ],
            ["piptools", "sync", pip_compiled_requirements_file],
            ["pip", "install", "-e", papi_python_src_dir],
        ]
        for req in test_req:
            args = [env_exe, "-m"]
            args.extend(req)
            print(args)
            p = Popen(args, stdout=PIPE, stderr=STDOUT, cwd=bin_path)
            show_progress(p.stdout)
        self.pip_patch()

    def pip_patch(self):
        """
        Apply scapy patch files
        """
        scapy_patch_dir = Path(os.path.join(test_dir, "patches", "scapy-2.4.3"))
        scapy_source_dir = glob.glob(
            os.path.join(venv_lib_dir, "python3.*", "site-packages")
        )[0]
        for f in scapy_patch_dir.iterdir():
            print("Applying patch: {}".format(os.path.basename(str(f))))
            args = ["patch", "--forward", "-p1", "-d", scapy_source_dir, "-i", str(f)]
            print(args)
            p = Popen(args, stdout=PIPE, stderr=STDOUT)
            show_progress(p.stdout)


# Build VPP Release/Debug binaries
def build_vpp(debug=True, release=False):
    """
    Install VPP Release(if release=True) or Debug(if debug=True) Binaries.

    Default is to build the debug binaries.
    """
    global vpp_build_dir, vpp_install_path, vpp_bin, vpp_lib, vpp_lib64
    global vpp_plugin_path, vpp_test_plugin_path, ld_library_path
    if debug:
        print("Building VPP debug binaries")
        args = ["make", "build"]
        build = "build-vpp_debug-native"
        install = "install-vpp_debug-native"
    elif release:
        print("Building VPP release binaries")
        args = ["make", "build-release"]
        build = "build-vpp-native"
        install = "install-vpp-native"
    p = Popen(args, stdout=PIPE, stderr=STDOUT, cwd=ws_root)
    show_progress(p.stdout)
    vpp_build_dir = os.path.join(build_root, build)
    vpp_install_path = os.path.join(build_root, install)
    vpp_bin = os.path.join(vpp_install_path, "vpp", "bin", "vpp")
    vpp_lib = os.path.join(vpp_install_path, "vpp", "lib")
    vpp_lib64 = os.path.join(vpp_install_path, "vpp", "lib64")
    vpp_plugin_path = (
        os.path.join(vpp_lib, "vpp_plugins")
        + ":"
        + os.path.join(vpp_lib64, "vpp_plugins")
    )
    vpp_test_plugin_path = (
        os.path.join(vpp_lib, "vpp_api_test_plugins")
        + ":"
        + os.path.join(vpp_lib64, "vpp_api_test_plugins")
    )
    ld_library_path = os.path.join(vpp_lib) + ":" + os.path.join(vpp_lib64)


# Environment Vars required by the test framework,
# papi_provider & unittests
def set_environ():
    os.environ["WS_ROOT"] = ws_root
    os.environ["BR"] = build_root
    os.environ["VENV_PATH"] = venv_dir
    os.environ["VENV_BIN"] = venv_bin_dir
    os.environ["RND_SEED"] = str(time.time())
    os.environ["VPP_BUILD_DIR"] = vpp_build_dir
    os.environ["VPP_BIN"] = vpp_bin
    os.environ["VPP_PLUGIN_PATH"] = vpp_plugin_path
    os.environ["VPP_TEST_PLUGIN_PATH"] = vpp_test_plugin_path
    os.environ["VPP_INSTALL_PATH"] = vpp_install_path
    os.environ["LD_LIBRARY_PATH"] = ld_library_path
    os.environ["FAILED_DIR"] = "/tmp/vpp-failed-unittests/"
    if not os.environ.get("TEST_JOBS"):
        os.environ["TEST_JOBS"] = "1"


# Runs a test inside a spawned QEMU VM
# If a kernel image is not provided, a linux-image-kvm image is
# downloaded to the test_data_dir
def vm_test_runner(test_name, kernel_image, test_data_dir, cpu_mask, mem, jobs="auto"):
    script = os.path.join(test_dir, "scripts", "run_vpp_in_vm.sh")
    os.environ["TEST_JOBS"] = str(jobs)
    p = Popen(
        [script, test_name, kernel_image, test_data_dir, cpu_mask, mem],
        stdout=PIPE,
        cwd=ws_root,
    )
    # Show only the test result without clobbering the stdout.
    # The VM console displays VPP stderr & Linux IPv6 netdev change
    # messages, which is logged by default and can be excluded.
    exclude_pattern = r"vpp\[\d+\]:|ADDRCONF\(NETDEV_CHANGE\):"
    show_progress(p.stdout, exclude_pattern)
    post_vm_test_run()


def post_vm_test_run():
    # Revert the ownership of certain directories from root to the
    # original user after running in QEMU
    print("Running post test cleanup tasks")
    dirs = ["/tmp/vpp-failed-unittests", os.path.join(ws_root, "test", "__pycache__")]
    dirs.extend(glob.glob("/tmp/vpp-unittest-*"))
    dirs.extend(glob.glob("/tmp/api_post_mortem.*"))
    user = os.getlogin()
    for dir in dirs:
        if os.path.exists(dir) and Path(dir).owner() != user:
            cmd = ["sudo", "chown", "-R", "{0}:{0}".format(user), dir]
            p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
            show_progress(p.stdout)


def build_venv():
    # Builds a virtual env containing all the required packages and patches
    # for running VPP unit tests
    if not os.path.exists(venv_install_done):
        env_builder = ExtendedEnvBuilder(clear=True, with_pip=True)
        print("Creating a vEnv for running VPP unit tests in {}".format(venv_dir))
        env_builder.create(venv_dir)
        # Write state to the venv run dir
        Path(venv_run_dir).mkdir(exist_ok=True)
        Path(venv_install_done).touch()


def expand_mix_string(s):
    # Returns an expanded string computed from a mixrange string (s)
    # E.g: If param s = '5-8,10,11' returns '5,6,7,8,10,11'
    result = []
    for val in s.split(","):
        if "-" in val:
            start, end = val.split("-")
            result.extend(list(range(int(start), int(end) + 1)))
        else:
            result.append(int(val))
    return ",".join(str(i) for i in set(result))


def set_logging(test_data_dir, test_name):
    Path(test_data_dir).mkdir(exist_ok=True)
    log_file = "vm_{0}_{1}.log".format(test_name, str(time.time())[-5:])
    filename = "{0}/{1}".format(test_data_dir, log_file)
    Path(filename).touch()
    logging.basicConfig(filename=filename, level=logging.DEBUG)


def run_tests_in_venv(
    test,
    jobs,
    log_dir,
    socket_dir="",
    running_vpp=False,
    extended=False,
):
    """Runs tests in the virtual environment set by venv_dir.

    Arguments:
    test: Name of the test to run
    jobs: Maximum concurrent test jobs
    log_dir: Directory location for storing log files
    socket_dir: Use running VPP's socket files
    running_vpp: True if tests are run against a running VPP
    extended: Run extended tests
    """
    script = os.path.join(test_dir, "scripts", "run.sh")
    args = [
        f"--venv-dir={venv_dir}",
        f"--vpp-ws-dir={ws_root}",
        f"--socket-dir={socket_dir}",
        f"--filter={test}",
        f"--jobs={jobs}",
        f"--log-dir={log_dir}",
        f"--tmp-dir={log_dir}",
        f"--cache-vpp-output",
    ]
    if running_vpp:
        args = args + [f"--use-running-vpp"]
    if extended:
        args = args + [f"--extended"]
    print(f"Running script: {script} " f"{' '.join(args)}")
    process_args = [script] + args
    call(process_args)


if __name__ == "__main__":
    # Build a Virtual Environment for running tests on host & QEMU
    # (TODO): Create a single config object by merging the below args with
    # config.py after gathering dev use-cases.
    parser = argparse.ArgumentParser(
        description="Run VPP Unit Tests", formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--vm",
        dest="vm",
        required=False,
        action="store_true",
        help="Run Test Inside a QEMU VM",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        required=False,
        default=True,
        action="store_true",
        help="Run Tests on Debug Build",
    )
    parser.add_argument(
        "--release",
        dest="release",
        required=False,
        default=False,
        action="store_true",
        help="Run Tests on release Build",
    )
    parser.add_argument(
        "-t",
        "--test",
        dest="test_name",
        required=False,
        action="store",
        default="",
        help="Test Name or Test filter",
    )
    parser.add_argument(
        "--vm-kernel-image",
        dest="kernel_image",
        required=False,
        action="store",
        default="",
        help="Kernel Image Selection to Boot",
    )
    parser.add_argument(
        "--vm-cpu-list",
        dest="vm_cpu_list",
        required=False,
        action="store",
        default="5-8",
        help="Set CPU Affinity\n"
        "E.g. 5-7,10 will schedule on processors "
        "#5, #6, #7 and #10. (Default: 5-8)",
    )
    parser.add_argument(
        "--vm-mem",
        dest="vm_mem",
        required=False,
        action="store",
        default="2",
        help="Guest Memory in Gibibytes\n" "E.g. 4 (Default: 2)",
    )
    parser.add_argument(
        "--log-dir",
        action="store",
        default=os.path.abspath(f"./test-run-{datetime.date.today()}"),
        help="directory where to store directories "
        "containing log files (default: ./test-run-YYYY-MM-DD)",
    )
    parser.add_argument(
        "--jobs",
        action="store",
        default="auto",
        help="maximum concurrent test jobs",
    )
    parser.add_argument(
        "-r",
        "--use-running-vpp",
        dest="running_vpp",
        required=False,
        action="store_true",
        default=False,
        help="Runs tests against a running VPP.",
    )
    parser.add_argument(
        "-d",
        "--socket-dir",
        dest="socket_dir",
        required=False,
        action="store",
        default="",
        help="Relative or absolute path of running VPP's socket directory "
        "containing api.sock & stats.sock files.\n"
        "Default: /var/run/vpp if VPP is started as the root user, else "
        "/var/run/user/${uid}/vpp.",
    )
    parser.add_argument(
        "-e",
        "--extended",
        dest="extended",
        required=False,
        action="store_true",
        default=False,
        help="Run extended tests.",
    )
    args = parser.parse_args()
    vm_tests = False
    # Enable VM tests
    if args.vm and args.test_name:
        test_data_dir = "/tmp/vpp-vm-tests"
        set_logging(test_data_dir, args.test_name)
        vm_tests = True
    elif args.vm and not args.test_name:
        print("Error: The --test argument must be set for running VM tests")
        sys.exit(1)
    build_venv()
    # Build VPP release or debug binaries
    debug = False if args.release else True
    build_vpp(debug, args.release)
    set_environ()
    if args.running_vpp:
        print("Tests will be run against a running VPP..")
    elif not vm_tests:
        print("Tests will be run by spawning a new VPP instance..")
    # Run tests against a running VPP or a new instance of VPP
    if not vm_tests:
        run_tests_in_venv(
            test=args.test_name,
            jobs=args.jobs,
            log_dir=args.log_dir,
            socket_dir=args.socket_dir,
            running_vpp=args.running_vpp,
            extended=args.extended,
        )
    # Run tests against a VPP inside a VM
    else:
        print("Running VPP unit test(s):{0} inside a QEMU VM".format(args.test_name))
        # Check Available CPUs & Usable Memory
        cpus = expand_mix_string(args.vm_cpu_list)
        num_cpus, usable_cpus = (len(cpus.split(",")), len(os.sched_getaffinity(0)))
        if num_cpus > usable_cpus:
            print(f"Error:# of CPUs:{num_cpus} > Avail CPUs:{usable_cpus}")
            sys.exit(1)
        avail_mem = int(os.popen("free -t -g").readlines()[-1].split()[-1])
        if int(args.vm_mem) > avail_mem:
            print(f"Error: Mem Size:{args.vm_mem}G > Avail Mem:{avail_mem}G")
            sys.exit(1)
        vm_test_runner(
            args.test_name,
            args.kernel_image,
            test_data_dir,
            cpus,
            f"{args.vm_mem}G",
            args.jobs,
        )
