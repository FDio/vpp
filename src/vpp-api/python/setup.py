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
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

setup(name='vpp_papi',
      version='1.6.1',
      description='VPP Python binding',
      author='Ole Troan',
      author_email='ot@cisco.com',
      url='https://wiki.fd.io/view/VPP/Python_API',
      license='Apache-2.0',
      test_suite='vpp_papi.tests',
      # Add when we don't need to support 2.7.5
      # 'enum34;python_version<"3.4"'],
      install_requires=['cffi >= 1.6', 'enum34'],
      packages=find_packages(),
      long_description='''VPP Python language binding.''',
      zip_safe=True)
