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

# If mlx_rdma_dpdk_matrix.txt file has been updated in the current changeset,
# verify the current rdma-core_version and dpdk_version exist in the matrix
# file
LINE="*******************************************************************"
BUILD_EXT_DIR="build/external"
MATRIX_FILE="$BUILD_EXT_DIR/mlx_rdma_dpdk_matrix.txt"
PKGS_DIR="$BUILD_EXT_DIR/packages"
if git show --stat | grep -q "$MATRIX_FILE" ; then
    RDMA_CORE_VERSION="$(grep rdma-core_version $PKGS_DIR/rdma-core.mk | grep -v '(' | mawk '{print $3}')"
    DPDK_VERSION="$(grep dpdk_version $PKGS_DIR/dpdk.mk | grep -v '(' | mawk '{print $3}')"
    CURRENT_MATRIX="rdma=$RDMA_CORE_VERSION dpdk=$DPDK_VERSION"
    if grep -q "$CURRENT_MATRIX" "$MATRIX_FILE"; then
        echo -e "$LINE\n* DPDK/RDMA-CORE matrix file update successfully verified\n$LINE"
    else
        echo -e "$LINE\n* ERROR: 'rdma=$RDMA_CORE_VERSION dpdk=$DPDK_VERSION' not found in $MATRIX_FILE!\n$LINE"
        exit 1
    fi
fi

if grep -qE '^checkstyle:' Makefile
then
    make UNATTENDED=yes install-deps checkstyle
else
    echo "Can't find checkstyle target in Makefile - skipping checkstyle"
fi
