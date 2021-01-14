#!/bin/bash

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

set -eEo pipefail

CLANG_FORMAT_VER=10
GIT_DIFF_ARGS="-U0 --no-color --relative HEAD~1"
CLANG_FORMAT_DIFF_ARGS="-style file -p1"
SUFFIX="-${CLANG_FORMAT_VER}"

clang-format${SUFFIX} --version

in=$(mktemp)
git diff ${GIT_DIFF_ARGS} ':!*.patch' > ${in}

line_count=$(sed -n '/^+.*\*INDENT-O[NF][F]\{0,1\}\*/p' ${in} | wc -l)
if [ ${line_count} -gt 0 ] ; then
    echo
    sed -n '/^+++ /{h}; /^+.*\*INDENT-O[NF][F]\{0,1\}\*/{x;p;x;p;}' ${in}
    echo
    echo "*******************************************************************"
    echo "* CHECKSTYLE FAILED"
    echo "* Please remove INDENT-ON and INDENT-OFF from modified lines."
    echo "*******************************************************************"
    rm ${in}
    exit 1
fi

if [ "${1}" == "--fix" ]; then
  cat ${in} | clang-format-diff${SUFFIX} ${CLANG_FORMAT_DIFF_ARGS} -i
  filelist=$(sed -n 's/^+++ b\/\(.*\.[ch]\)/\1/p' ${in})
  git status ${filelist}
  rm ${in}
  exit 0
fi

line_count=$(sed -n '/^+.*\s\+$/p' ${in} | wc -l)
if [ ${line_count} -gt 0 ] ; then
    echo
    sed -n '/^+++/h; /^+.*\s\+$/{x;p;x;p;}' ${in}
    echo
    echo "*******************************************************************"
    echo "* CHECKSTYLE FAILED"
    echo "* Trailing whitespace detected"
    echo "*******************************************************************"
    rm ${in}
    exit 1
fi

out=$(mktemp)

cat ${in} | clang-format-diff${SUFFIX} ${CLANG_FORMAT_DIFF_ARGS} > ${out}
rm ${in}

line_count=$(cat ${out} | wc -l)

if [ -t 1 ] && [ -n $(tput colors) ] && [ $(tput colors) -ge 1 ] && \
   command -v highlight &> /dev/null ; then
  highlight --syntax diff -O ansi ${out}
else
  cat ${out}
fi

rm ${out}

if [ ${line_count} -gt 0 ] ; then
    echo "*******************************************************************"
    echo "* CHECKSTYLE FAILED"
    echo "* CONSULT DIFF ABOVE"
    echo "* NOTE: Running 'extras/scripts/checkstyle.sh --fix' *MAY* fix the issue"
    echo "*******************************************************************"
    exit 1
else
    echo "*******************************************************************"
    echo "* CHECKSTYLE SUCCESSFULLY COMPLETED"
    echo "*******************************************************************"
    exit 0
fi
