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

try:
    from setuptools import setup, command, Extension
except ImportError:
    from distutils.core import setup

import distutils.cmd, distutils.log, subprocess, os, glob
import setuptools.command.build_py

class GenAPICommand(distutils.cmd.Command):
    """A custom command to build VPP API Python definition."""

    description = 'run pyvvpapigen on VPP API files'
    user_options = []

    def initialize_options(self):
        """Set default values for options."""
    def finalize_options(self):
        """Post-process options."""

    def run(self):
        """Run command."""
        vppapigen = '/vpp/papi/build-root/build-tool-native/vppapigen/vppapigen'
        pyvppapigen = '/vpp/papi/build-root/tools/bin/pyvppapigen.py'
        cc = '/usr/bin/cc'

        # Core API definitions.
        apifiles = ['../../vpp/vpp-api/vpe.api',
                    '../../vlib-api/vlibmemory/memclnt.api']
        for apifile in apifiles:
            apibasename = os.path.basename(apifile)
            apifile_no_ext = os.path.splitext(apibasename)[0]
            command = cc +  ' -E -P -C -x c ' + apifile + ' | ' + vppapigen + \
                      ' --input - --python - | ' + pyvppapigen + \
                      ' --input - > ' + 'vpp_papi/' + apifile_no_ext + '.py'
            self.announce('Running command: %s' % str(command),
                      level=distutils.log.INFO)

            subprocess.check_call(command, shell=True)

import setuptools

class BuildAPICommand(setuptools.command.build_py.build_py):
    """Custom build command."""

    def run(self):
        self.run_command('apigen')
        setuptools.command.build_py.build_py.run(self)

setup (name = 'vpp_papi',
       cmdclass={
           'apigen': GenAPICommand,
           'build_py': BuildAPICommand,
       },
       version = '1.2',
       description = 'VPP Python binding',
       author = 'Ole Troan',
       author_email = 'ot@cisco.com',
       test_suite = 'tests',
       packages=['vpp_papi'],
       ext_modules = [
           Extension(
               'vpp_api',
               sources = ['vpp_papi/pneum_wrap.c'],
               libraries = ['pneum'],
               library_dirs = [os.path.dirname(glob.glob('../../build-root/install*/vpp-api/lib64/libpneum.so')[0])],
           )],
       long_description = '''VPP Python language binding.''',
)
