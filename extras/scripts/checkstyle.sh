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

GIT_DIFF_ARGS="-U0 --no-color --relative HEAD~1"
CLANG_FORMAT_DIFF_ARGS="-style file -p1"

while true; do
  case ${1} in
    --fix)
      is_fix=true
      ;;
  esac
  shift || break
done

clang-format --version

if [ "${is_fix}" == "true" ]; then
  git diff ${GIT_DIFF_ARGS} | clang-format-diff ${CLANG_FORMAT_DIFF_ARGS} -i
  git status
  exit 0
fi

if test -t 1 && \
   test -n $(tput colors) && \
   test $(tput colors) -ge 1 && \
   command -v highlight &> /dev/null ; then
  HIGHLIGHT="highlight --syntax diff -O ansi "
else
  HIGHLIGHT="cat"
fi

git diff ${GIT_DIFF_ARGS} | clang-format-diff ${CLANG_FORMAT_DIFF_ARGS} | ${HIGHLIGHT} | grep .


if [ $? == 1 ]; then
    echo "*******************************************************************"
    echo "* VPP CHECKSTYLE SUCCESSFULLY COMPLETED"
    echo "*******************************************************************"
    exit 0
else
    echo "*******************************************************************"
    echo "* VPP CHECKSTYLE FAILED"
    echo "* CONSULT FAILURE LOG ABOVE"
    echo "* NOTE: Running 'extras/scripts/checkstyle.sh --fix' *MAY* fix the issue"
    echo "*******************************************************************"
    exit 1
fi
