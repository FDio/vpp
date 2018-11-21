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

import os
import pkg_resources
import shlex
import subprocess
import sys

vpp_versioned = os.getenv("VPP_VERSIONED_PAPI", 'n').lower()[0] in \
                ('y', 't', '1')

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

# dont auto normalize, so we can have a release 20.01
from setuptools.extern.packaging import version
version.Version = version.LegacyVersion
pkg_resources.safe_version = lambda v: v

requirements = ['cffi >= 1.6']


def get_pep404_version_from_git():
    if vpp_versioned:
        cmd = shlex.split("git describe --tags --first-parent --abbrev=0")
    else:
        cmd = shlex.split("git describe")
    version = subprocess.check_output(cmd)[1:].strip()
    # v19.01-rc0-289-g391d328 -> 19.1rc0.dev289+g391d328

    count = version.count(b"-")
    if count == 3:
        version = b'+'.join(version.rsplit(b'-', 1))
        count -= 1
    if count == 2:
        version = b'.dev'.join(version.rsplit(b'-', 1))
        count -= 1
    if count == 1:
        version = version.replace(b'-', b'')
    if not vpp_versioned:
        version = version.replace(b'.0', b'.')

    return version.decode('utf-8')


setup(name='vpp_papi',
      version=get_pep404_version_from_git(),
      description='VPP Python binding',
      author='Ole Troan',
      author_email='ot@cisco.com',
      url='https://wiki.fd.io/view/VPP/Python_API',
      license='Apache-2.0',
      test_suite='vpp_papi.tests',
      install_requires=requirements,
      packages=find_packages(),
      long_description='''VPP Python language binding.''',
      zip_safe=True)
