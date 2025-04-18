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
from subprocess import Popen, PIPE, STDOUT, run, CalledProcessError
import sys
import time
import re


base_dir = Path(__file__).resolve().parent
ws_root = base_dir.parent
run_sh = base_dir / "scripts" / "run.sh"


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


def get_env(args):
    """Build and return test environment variables."""
    defaults = {
        "FAILED_DIR": "/tmp/vpp-failed-unittests/",
        "V": "1",
        "SKIP_FILTER": "",
        "RETRIES": "0",
        "WS_ROOT": str(ws_root),
        "BR": str(ws_root / "build-root"),
        "VENV_PATH": str(ws_root / "build-root" / "test" / "venv"),
        "VPP_BUILD_DIR": str(ws_root / "build-root" / "build-vpp-native" / "vpp"),
        "VPP_INSTALL_PATH": str(ws_root / "build-root" / "install-vpp-native"),
        "VPP_BIN": str(
            ws_root / "build-root" / "install-vpp-native" / "vpp" / "bin" / "vpp"
        ),
        "VPP_PLUGIN_PATH": str(
            ws_root
            / "build-root"
            / "install-vpp-native"
            / "vpp"
            / "include"
            / "vpp_plugins"
        ),
        "VPP_TEST_PLUGIN_PATH": str(
            ws_root
            / "build-root"
            / "install-vpp-native"
            / "vpp"
            / "include"
            / "vpp_plugins"
        ),
        "LD_LIBRARY_PATH": str(
            ws_root / "build-root" / "install-vpp-native" / "vpp" / "lib"
        ),
        "TAG": "vpp_debug",
        "RND_SEED": str(time.time()),
        "VPP_WORKER_COUNT": "",
        "TEST": args.test_name,
        "TEST_JOBS": args.jobs,
        "SOCKET_DIR": args.socket_dir,
        "PYTHON_OPTS": "",
        "EXTENDED": args.extended,
        "USE_RUNNING_VPP": args.running_vpp,
        "LOG_DIR": args.log_dir,
        "VM_KERNEL_IMAGE": args.kernel_image,
        "VM_CPU_LIST": args.vm_cpu_list,
        "VM_MEM": args.vm_mem,
        "VM_TEST": args.vm,
    }
    # Update values for defaults from environment variables
    # If a variable is set in os.environ, it takes priority over the defaults
    return {key: os.environ.get(key, default) for key, default in defaults.items()}


# Runs a test inside a spawned QEMU VM
# If a kernel image is not provided, a linux-image-kvm image is
# downloaded to the test_data_dir
def vm_test_runner(
    test_name, kernel_image, test_data_dir, cpu_mask, mem, jobs="auto", env=None
):
    """Runs a test inside a spawned QEMU VM."""
    run_vpp_in_vm_sh = base_dir / "scripts" / "run_vpp_in_vm.sh"
    # Set the environment variables required for running a VM test
    os.environ["TEST_JOBS"] = str(jobs)
    os.environ["WS_ROOT"] = str(ws_root)
    os.environ["BR"] = env["BR"]
    os.environ["VPP_TEST_DATA_DIR"] = str(test_data_dir)
    os.environ["VPP_BUILD_DIR"] = env["VPP_BUILD_DIR"]
    os.environ["VPP_INSTALL_PATH"] = env["VPP_INSTALL_PATH"]
    os.environ["VPP_BIN"] = env["VPP_BIN"]
    os.environ["VPP_PLUGIN_PATH"] = env["VPP_PLUGIN_PATH"]
    os.environ["VPP_TEST_PLUGIN_PATH"] = env["VPP_TEST_PLUGIN_PATH"]
    os.environ["LD_LIBRARY_PATH"] = env["LD_LIBRARY_PATH"]
    os.environ["RND_SEED"] = env["RND_SEED"]
    os.environ["VENV_PATH"] = env["VENV_PATH"]
    os.environ["TAG"] = env["TAG"]
    os.environ["VPP_WORKER_COUNT"] = env["VPP_WORKER_COUNT"]
    os.environ["FAILED_DIR"] = env["FAILED_DIR"]
    os.environ["SKIP_FILTER"] = env["SKIP_FILTER"]
    if not run_vpp_in_vm_sh.is_file():
        print(f"Error: script {base_dir}/scripts/run_vpp_in_vm.sh not found.")
        sys.exit(1)
    p = Popen(
        [run_vpp_in_vm_sh, test_name, kernel_image, test_data_dir, cpu_mask, mem],
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
    """Setup the Python virtual environment via vpp Makefile."""
    print(
        f"Setting up Python virtual environment using Makefile in "
        f"{ws_root}/test/venv..."
    )

    if not ws_root.is_dir():
        print(f"Error: WS_ROOT directory not valid at {ws_root}")
        sys.exit(1)

    try:
        run(["make", "test-dep"], cwd=str(ws_root), check=True)
    except CalledProcessError as e:
        print(f"Failed to set up test virtualenv using Makefile: {e}")
        sys.exit(e.returncode)


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


def run_tests_in_venv(env):
    """Runs tests in the Python virtual environment.

    Arguments:
    env: A dictionary of environment variables for the test run.
    """
    if not run_sh.is_file():
        print("Error: scripts/run.sh not found.")
        sys.exit(1)
    args = [
        f"--venv-dir={env['VENV_PATH']}",
        f"--vpp-ws-dir={env['WS_ROOT']}",
        f"--vpp-tag={env['TAG']}",
        f"--failed-dir={env['FAILED_DIR']}",
        f"--verbose={env['V']}",
        f"--jobs={env['TEST_JOBS']}",
        f"--filter={env['TEST']}",
        f"--skip-filter={env['SKIP_FILTER']}",
        f"--retries={env['RETRIES']}",
        f"--rnd-seed={env['RND_SEED']}",
        f"--vpp-worker-count={env['VPP_WORKER_COUNT']}",
        f"--python-opts={env['PYTHON_OPTS']}",
        f"--log-dir={env['LOG_DIR']}",
        f"--tmp-dir={env['LOG_DIR']}",
        "--keep-pcaps",
        "--cache-vpp-output",
    ]
    if env["USE_RUNNING_VPP"]:
        args = args + ["--use-running-vpp"] + [f"--socket-dir={env['SOCKET_DIR']}"]
    if env["EXTENDED"]:
        args = args + ["--extended"]
    try:
        print(f"Running: {run_sh} {' '.join(args)}")
        run([str(run_sh)] + args, check=True)
    except CalledProcessError as e:
        print(f"\nrun.sh failed with exit code {e.returncode}...")
        sys.exit(e.returncode)


if __name__ == "__main__":
    # Build a Virtual Environment for running tests on host & QEMU
    # (TODO): Create a single config object by merging the below args with
    # config.py after gathering dev use-cases.
    parser = argparse.ArgumentParser(description="Run VPP Unit Tests")
    parser.add_argument(
        "--vm",
        dest="vm",
        required=False,
        action="store_true",
        help="Run Test Inside a QEMU VM",
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
        default="/tmp/vpp-failed-unittests/",
        help="directory where to store directories "
        "default: /tmp/vpp-failed-unittests/",
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
    env = get_env(args)
    if args.running_vpp:
        print("Tests will be run against a running VPP..")
    elif not vm_tests:
        print("Tests will be run by spawning a new VPP instance..")
    # Run tests against a running VPP or a new instance of VPP
    if not vm_tests:
        run_tests_in_venv(env)
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
            env,
        )
