# Copyright (c) 2020 Cisco and/or its affiliates.
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

from setuptools import setup, find_packages
import os


# parse requirements
thelibFolder = os.path.dirname(os.path.realpath(__file__))
requirementPath = thelibFolder + '/requirements.txt'
requirements = []
if os.path.isfile(requirementPath):
    with open(requirementPath) as f:
        requirements = f.read().splitlines()

def find_plugins_packages():
    pkgs = []
    for root, dirs, _ in os.walk("../../plugins"):
        for d in dirs:
            for p in find_packages(os.path.join(root, d)):
                pkgs.append(os.path.join(root, d, p))
    print(pkgs)
    return pkgs

setup(
    name="vpp_pom",
    version='0.1.0',
    description='VPP Python Object Model',
    license='Apache-2.0',
    install_requires=requirements,
    packages=find_packages(),
    long_description='''VPP Python Object Model.''',

    # metadata
    author='Jakub Grajciar',
    author_email='jgrajcia@cisco.com',
    url='https://wiki.fd.io/view/VPP/Python_API'
)