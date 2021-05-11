#!/usr/bin/env python3
#
# Copyright (c) 2016 Cisco and/or its affiliates.
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
import os
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT
import venv
import sys
import time
import logging

# Path variables required for test run
test_dir = os.path.dirname(os.path.realpath(__file__))
ws_root = os.path.dirname(test_dir)
build_root = os.path.join(ws_root, 'build-root')
venv_dir = os.path.join(test_dir, 'venv')
venv_bin_dir = os.path.join(venv_dir, 'bin')
venv_lib_dir = os.path.join(venv_dir, 'lib')
venv_run_dir = os.path.join(venv_dir, 'run')
venv_install_done = os.path.join(venv_run_dir, 'venv_install.done')
papi_python_src_dir = os.path.join(ws_root, 'src', 'vpp-api', 'python')
vpp_build_dir = os.path.join(build_root, 'build-vpp-native')
vpp_install_path = os.path.join(build_root, 'install-vpp-native')
vpp_bin = os.path.join(vpp_install_path, 'vpp', 'bin', 'vpp')
vpp_lib = os.path.join(vpp_install_path, 'vpp', 'lib')
vpp_lib64 = os.path.join(vpp_install_path, 'vpp', 'lib64')
vpp_plugin_path = os.path.join(vpp_lib, 'vpp_plugins') + ':' + \
    os.path.join(vpp_lib64, 'vpp_plugins')
vpp_test_plugin_path = os.path.join(vpp_lib, 'vpp_api_test_plugins') + \
    ':' + os.path.join(vpp_lib64, 'vpp_api_test_plugins')
ld_library_path = os.path.join(vpp_lib) + ':' + os.path.join(vpp_lib64)

# Pin version pinning
pip_version = '20.1.1'
pip_tools_version = '5.1.2'

# Test requirement files
test_requirements_file = os.path.join(test_dir, 'requirements.txt')
# Auto-generated requirement file
pip_compiled_requirements_file = os.path.join(test_dir, 'requirements-3.txt')


def show_progress(stream):
    """
    Read lines from a subprocess stdout/stderr streams and write
    to sys.stdout & the logfile
    """
    while True:
        s = stream.readline()
        if not s:
            break
        data = s.decode('utf-8')
        # Filter the annoying SIGTERM signal from the output when VPP is
        # terminated after a test run
        if 'SIGTERM' not in data:
            sys.stdout.write(data)
            logging.debug(data)
        sys.stdout.flush()
    stream.close()


class ExtendedEnvBuilder(venv.EnvBuilder):
    """
    1. Builds the Virtual Environment for running VPP unit tests
    2. Installs all the necessary scripts & pkgs in the new vEnv
         - python3, pip, pip-tools, papi & test-requirement pkgs
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
        os.environ['VIRTUAL_ENV'] = context.env_dir
        os.environ['CUSTOM_COMPILE_COMMAND'] = \
            'make test-refresh-deps (or update requirements.txt)'
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
            ['pip', 'install', 'pip===%s' % pip_version],
            ['pip', 'install', 'pip-tools===%s' % pip_tools_version],
            ['piptools', 'compile', '-q', '--generate-hashes',
             test_requirements_file,
             '--output-file',  pip_compiled_requirements_file],
            ['piptools', 'sync', pip_compiled_requirements_file],
            ['pip', 'install', '-e', papi_python_src_dir], ]
        for req in test_req:
            args = [env_exe, '-m']
            args.extend(req)
            print(args)
            p = Popen(args, stdout=PIPE, stderr=STDOUT, cwd=bin_path)
            show_progress(p.stdout)
        self.pip_patch(context)
        self.install_test_apps(context)

    def pip_patch(self, context):
        """
        Apply scapy patch files
        """
        scapy_patch_dir = Path(os.path.join(test_dir,
                                            'patches',
                                            'scapy-2.4.3'))
        scapy_source_dir = glob.glob(os.path.join(venv_lib_dir,
                                                  'python3.*',
                                                  'site-packages'))[0]
        for f in scapy_patch_dir.iterdir():
            print("Applying patch: {}".format(os.path.basename(str(f))))
            args = ['patch', '--forward', '-p1', '-d',
                    scapy_source_dir, '-i', str(f)]
            print(args)
            p = Popen(args, stdout=PIPE, stderr=STDOUT)
            show_progress(p.stdout)

    def install_test_apps(self, context):
        """
        Install VPP & VAPI Binaries and Libs
        """
        print("Installing VPP and VAPI binaries")
        args = ["make", "test-apps"]
        p = Popen(args, stdout=PIPE, stderr=STDOUT, cwd=ws_root)
        show_progress(p.stdout)


# Sets common env variables required for test runs
def set_environ():
    os.environ['WS_ROOT'] = ws_root
    os.environ['VENV_PATH'] = venv_dir
    os.environ['VENV_BIN'] = venv_bin_dir
    os.environ['RND_SEED'] = str(time.time())
    os.environ['VPP_BUILD_DIR'] = vpp_build_dir
    os.environ['VPP_BIN'] = vpp_bin
    os.environ['VPP_PLUGIN_PATH'] = vpp_plugin_path
    os.environ['VPP_TEST_PLUGIN_PATH'] = vpp_test_plugin_path
    os.environ['VPP_INSTALL_PATH'] = vpp_install_path
    os.environ['LD_LIBRARY_PATH'] = ld_library_path
    os.environ['FAILED_DIR'] = '/tmp/vpp-failed-unittests/'


# Runs a test inside a spawned QEMU VM
# If a kernel image is not provided, a linux-image-kvm image is
# downloaded into the test_data_dir
def vm_test_runner(test_name='',
                   kernel_image='',
                   test_data_dir=''):
    if test_name:
        os.environ['TEST'] = test_name
    if kernel_image:
        os.environ['KERNEL_BIN'] = kernel_image
    if test_data_dir:
        os.environ['TEST_DATA_DIR'] = test_data_dir
    if not os.environ.get('TEST_JOBS'):
        os.environ['TEST_JOBS'] = '1'
    script = os.path.join(test_dir, "scripts", "run_vpp_in_vm.sh")
    p = Popen([script], stdout=PIPE, stderr=STDOUT, cwd=ws_root)
    show_progress(p.stdout)


def build_venv():
    # Builds a virtual env containing all the required packages and patches
    # for running VPP unit tests
    if not os.path.exists(venv_install_done):
        env_builder = ExtendedEnvBuilder(clear=True,
                                         with_pip=True)
        print('Creating a vEnv for running VPP unit tests in {}'.format(
              venv_dir))
        env_builder.create(venv_dir)
        # Write state to the venv run dir
        Path(venv_run_dir).mkdir(exist_ok=True)
        Path(venv_install_done).touch()


if __name__ == '__main__':
    # Build a Virtual Environment for running tests on host & QEMU
    parser = argparse.ArgumentParser(description="Run VPP Unit Tests")
    parser.add_argument('--vm', dest='vm', required=True,
                        action='store_true',
                        help="Run test in a QEMU VM")
    parser.add_argument('--test', dest='test_name', required=False,
                        action='store', default='',
                        help="Unit test to run inside the VM")
    parser.add_argument('--kernel-image', dest='kernel_image',
                        required=False, action='store', default='',
                        help='Select a Kernel Image to boot')
    args = parser.parse_args()
    build_venv()
    set_environ()
    test_data_dir = '/tmp/vpp-vm-tests'
    Path(test_data_dir).mkdir(exist_ok=True)
    if args.test_name:
        log_file = "vm_{0}_{1}.log".format(args.test_name,
                                           str(time.time())[-5:])
    else:
        log_file = "vm_tests_{0}.log".format(str(time.time())[-5:])
    filename = "{0}/{1}".format(test_data_dir, log_file)
    Path(filename).touch()
    logging.basicConfig(filename=filename, level=logging.DEBUG)
    if args.vm:
        print("Running VPP unit tests inside a QEMU VM")
        vm_test_runner(args.test_name, args.kernel_image, test_data_dir)
