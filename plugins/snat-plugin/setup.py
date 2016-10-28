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
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

setup (name = 'vpp-snat-plugin',
       version = '1.0',
       description = 'VPP snat plugin Python bindings',
       requires='vpp_papi',
       packages=['snat'],
       long_description = '''VPP snat plugin Python language binding.''',
)
