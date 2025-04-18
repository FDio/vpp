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
# This script supports running a test against a running VPP instance.
# Usage:
#   python3 run.py --test <test_name> --use-running-vpp --socket-dir {socket_dir}
#   The --socket-dir argument is the path to the socket directory of a
#   running VPP instance. Default: /var/run/vpp if VPP is started as the root user,
#   else  /var/run/user/${uid}/vpp.
#   The --test argument is the name of the test to run. If no test-name is provided,
#   all tests will be run.
# Any other arguments provided to the script will be passed unmodified
# to the test runner.
#
# Before running this script ensure that vpp has been built using
# make build or make build-release. This script will set up the
# python virtual environment and use the environment variable values.

import argparse
import os
import subprocess
import sys
from pathlib import Path


# Ensure the virtual environment is set up
def ensure_virtualenv():
    """Setup the Python virtual environment via the Makefile."""
    run_py_dir = Path(__file__).resolve().parent
    # Directory where the Makefile is located
    ws_root_dir = run_py_dir.parent
    print(f"Setting up Python virtual environment using Makefile in "
          f"{ws_root_dir}/test/venv...")

    if not ws_root_dir.is_dir():
        print(f"Error: WS_ROOT directory not found at {ws_root_dir}")
        sys.exit(1)

    try:
        subprocess.run(["make", "test-dep"], cwd=str(ws_root_dir), check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to set up test virtualenv via Makefile: {e}")
        sys.exit(e.returncode)


def main():
    parser = argparse.ArgumentParser(description="Run VPP unit tests.")
    parser.add_argument("--test", help="Test filter (used for --filter)", default=os.environ.get("TEST", ""))
    parser.add_argument("--test-jobs", help="Number of parallel test jobs (used for --jobs)", default=os.environ.get("TEST_JOBS", "1"))
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
    parser.add_argument("extra_args", nargs=argparse.REMAINDER, help="Additional arguments passed to make test in key=val format")
    parser_args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    ws_root = base_dir.parent
    run_sh = base_dir / "scripts" / "run.sh"
    compress_sh = base_dir / "scripts" / "compress_failed.sh"

    if not run_sh.is_file():
        print("Error: scripts/run.sh not found.")
        sys.exit(1)

    # Default test variables
    defaults = {
        "FAILED_DIR": "/tmp/vpp-failed-unittests/",
        "V": "1",
        "SKIP_TESTS": "",
        "RETRIES": "0",
        "VENV_PATH": str(ws_root) + '/build-root/test/venv',
        "WS_ROOT": str(ws_root),
        "TAG": "vpp_debug",
        "RND_SEED": "",
        "VPP_WORKER_COUNT": "",
        "COMPRESS_FAILED_TEST_LOGS": "yes",
        "TEST": parser_args.test,
        "TEST_JOBS": parser_args.test_jobs,
        "SOCKET_DIR": parser_args.socket_dir,
        "PYTHON_OPTS": "",
    }

    # Pull values from environment variables
    # If a variable is set in os.environ, it takes priority over the defaults
    env = {key: os.environ.get(key, default)
           for key, default in defaults.items()}

    # Ensure the virtual environment is set up
    ensure_virtualenv()

    # Compose args for the test runner
    args = [
        f"--venv-dir={env['VENV_PATH']}",
        f"--vpp-ws-dir={env['WS_ROOT']}",
        f"--vpp-tag={env['TAG']}",
        f"--failed-dir={env['FAILED_DIR']}",
        f"--verbose={env['V']}",
        f"--jobs={env['TEST_JOBS']}",
        f"--filter={env['TEST']}",
        f"--skip-filter={env['SKIP_TESTS']}",
        f"--retries={env['RETRIES']}",
        f"--rnd-seed={env['RND_SEED']}",
        f"--vpp-worker-count={env['VPP_WORKER_COUNT']}",
        f"--python-opts={env['PYTHON_OPTS']}",
        "--keep-pcaps",
        ] + parser_args.extra_args
    
    if parser_args.running_vpp:
        args = args + ["--use-running-vpp"] + [f"--socket-dir={env['SOCKET_DIR']}"]
 
    try:
        print(f"Running: {run_sh} {' '.join(args)}")
        subprocess.run([str(run_sh)] + args, env=env, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\nrun.sh failed with exit code {e.returncode}, attempting log compression...")
        if compress_sh.is_file():
            try:
                subprocess.run([str(compress_sh)], env=env, check=True)
                print("Compressed failed test logs.")
            except subprocess.CalledProcessError:
                print("compress_failed.sh failed.")
        else:
            print("compress_failed.sh not found.")
        sys.exit(e.returncode)


if __name__ == "__main__":
    main()
