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

CLANG_FORMAT_VER_REGEX='([0-9]+)\.[0-9]+\.[0-9]+'
CLANG_FORMAT_DIFF="/usr/share/clang/clang-format-diff.py"

# TODO: Remove clang-format-${CLANG_FORMAT_VER} from 'make install-deps' when
#       CLANG_FORMAT_VER default value is upgraded
CLANG_FORMAT_VER=${CLANG_FORMAT_VER:-11}
GIT_DIFF_ARGS="-U0 --no-color --relative HEAD~1"
CLANG_FORMAT_DIFF_ARGS="-style file -p1"
SUFFIX="-${CLANG_FORMAT_VER}"

# Attempt to find clang-format to confirm Clang version.
if command -v clang-format${SUFFIX} &> /dev/null;
then
    CLANG_FORMAT=clang-format${SUFFIX}
elif command -v clang-format &> /dev/null;
then
    CLANG_FORMAT=clang-format
fi

CLANG_FORMAT_VERSION=$(${CLANG_FORMAT} --version)
echo $CLANG_FORMAT_VERSION

# Confirm that Clang is the expected version.
if [[ ! $CLANG_FORMAT_VERSION =~ $CLANG_FORMAT_VER_REGEX ]];
then
    echo "*******************************************************************"
    echo "* CHECKSTYLE VERSION REGEX CHECK FAILED"
    echo "* $CLANG_FORMAT_VERSION"
    echo "*******************************************************************"
    exit 1
fi

if [[ ! $CLANG_FORMAT_VER == "${BASH_REMATCH[1]}" ]];
then
    echo "*******************************************************************"
    echo "* CHECKSTYLE VERSION CHECK FAILED"
    echo "* Expected major version $CLANG_FORMAT_VER, found ${BASH_REMATCH[1]}"
    echo "*******************************************************************"
    exit 1
fi

# Attempt to find clang-format-diff.
if command -v clang-format-diff${SUFFIX} &> /dev/null;
then
    CLANG_FORMAT_DIFF=clang-format-diff${SUFFIX}
elif command -v clang-format-diff &> /dev/null;
then
    CLANG_FORMAT=clang-format-diff
elif [ ! -f $CLANG_FORMAT_DIFF ] ;
then
    echo "*******************************************************************"
    echo "* CHECKSTYLE FAILED"
    echo "* Could not locate the clang-format-diff script"
    echo "*******************************************************************"
    exit 1
fi

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
  cat ${in} | ${CLANG_FORMAT_DIFF} ${CLANG_FORMAT_DIFF_ARGS} -i
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

cat ${in} | ${CLANG_FORMAT_DIFF} ${CLANG_FORMAT_DIFF_ARGS} > ${out}
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
