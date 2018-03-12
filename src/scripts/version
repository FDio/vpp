#!/bin/bash

# Copyright (c) 2015 Cisco and/or its affiliates.
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

path=$( cd "$(dirname "${BASH_SOURCE}")" ; pwd -P )

cd "$path"

if [ -f .version ]; then
    vstring=$(cat .version)
else
    vstring=$(git describe)
    if [ $? != 0 ]; then
      exit 1
    fi
fi

TAG=$(echo ${vstring} | cut -d- -f1 | sed -e 's/^v//')
ADD=$(echo ${vstring} | cut -s -d- -f2)

git rev-parse 2> /dev/null
if [ $? == 0 ]; then
    CMT=$(git describe --dirty --match 'v*'| cut -s -d- -f3,4)
else
    CMT=$(echo ${vstring} | cut -s -d- -f3,4)
fi
CMTR=$(echo $CMT | sed 's/-/_/')

if [ -n "${BUILD_NUMBER}" ]; then
       BLD="~b${BUILD_NUMBER}"
fi

if [ "$1" = "rpm-version" ]; then
  echo ${TAG}
  exit
fi

if [ "$1" = "rpm-release" ]; then
  [ -z "${ADD}" ] && echo release && exit
  echo ${ADD}${CMTR:+~${CMTR}}${BLD}
  exit
fi

  if [ -n "${ADD}" ]; then
    if [ "$1" = "rpm-string" ]; then
      echo ${TAG}-${ADD}${CMTR:+~${CMTR}}${BLD}
    else
      echo ${TAG}-${ADD}${CMT:+~${CMT}}${BLD}
    fi
  else
    echo ${TAG}-release
fi
