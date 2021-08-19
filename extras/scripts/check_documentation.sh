#!/bin/bash

# Copyright (c) 2021 Cisco and/or its affiliates.
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

set -eEo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
WS_ROOT=$( realpath ${SCRIPTDIR}/../.. )

function red   () { printf "\e[0;31m$1\e[0m\n" ; }
function green () { printf "\e[0;32m$1\e[0m\n" ; }

find_linked_docs () {
  find ${WS_ROOT}/docs -type l \
      \( -name '*.rst' -o -name '*.md' \) \
      -exec readlink -f {} \; | sort
}

find_excluded_docs () {
    cat ${WS_ROOT}/docs/docsignore \
      | grep -v '#' \
      | sed s@^@${WS_ROOT}/@ \
      | sort
}

find_linked_and_excluded_docs () {
  cat <( find_linked_docs ) <( find_excluded_docs  ) | sort
}

find_candidate_docs () {
  find \
    ${WS_ROOT}/src \
    ${WS_ROOT}/test \
    ${WS_ROOT}/extras \
    -not -path "${WS_ROOT}/test/venv/*" \
    \( -name '*.rst' -o -name '*.md' \) \
    | sort
}

spellcheck () {
    make -C ${WS_ROOT} docs-spell
}

if [ "x$(comm -13 <( find_linked_and_excluded_docs ) <( find_candidate_docs ))" != x ]; then
    red "The following files need to be linked"
    red "in the doc folder e.g. :"
    red "$ cd vpp/docs/developer/plugins"
    red "$ ln -s ../../../src/plugins/my_plugin/my_plugin.rst"
    echo ""
    cat <( comm -13 <( find_linked_and_excluded_docs ) <( find_candidate_docs ) )
    exit 1
fi
spellcheck
green "**********************************************"
green "* VPP Docs Checkstyle Successfully Completed *"
green "**********************************************"
