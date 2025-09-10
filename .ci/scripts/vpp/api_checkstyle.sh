#!/bin/bash

# Copyright (c) 2025 Cisco and/or its affiliates.
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

VPP_CRC_CHECKER="extras/scripts/crcchecker.py"
VPP_CRC_CHECKER_CMD="$VPP_CRC_CHECKER --check-patchset"


if [ -f $VPP_CRC_CHECKER ]; then
    # API checker complains if the git repo is not clean.
    # Help diagnosing those issues easier
    git --no-pager diff
    echo "Running $VPP_CRC_CHECKER_CMD"
    if $VPP_CRC_CHECKER_CMD; then
	    echo "API check successful"
    else
	    RET_CODE=$?
	    echo "API check failed: ret code $RET_CODE; please read https://wiki.fd.io/view/VPP/ApiChangeProcess and discuss with ayourtch@gmail.com if unsure how to proceed"
	    echo "::error file=.ci/scripts/vpp/crcchecker.py,line=1::API check FAILED for $GITHUB_REF. See run: https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
	    exit $RET_CODE
    fi
else
    echo "Cannot find $VPP_CRC_CHECKER - skipping API compatibility check"
fi
