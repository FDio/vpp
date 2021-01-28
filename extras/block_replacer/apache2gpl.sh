#!/usr/bin/env bash

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

set -exuo pipefail

if [[ "${#}" != "1" ]]; then
    echo 'An utility to switch license comment blocks.'
    echo 'Requires files "gpl_block.txt" and "apache_block.txt" in the working'
    echo 'directory, and a single argument pointing to root directory.'
    echo 'Affects only .sh and .py files.'
    exit 1
fi

find "${1}" \( -name "*.py" -o -name "*.sh" \) -print0 | xargs -0 \
python3 replace.py "apache_block.txt" "gpl_block.txt"
