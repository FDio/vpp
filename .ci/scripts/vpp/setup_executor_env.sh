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

echo "---> .ci/scripts/setup_executor_env.sh"

set -e -o pipefail

OS_ID=$(grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION_ID=$(grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_ARCH=$(uname -m)
# dockerfile="/scratch/docker-build/Dockerfile"
file_delimiter="----- %< -----"
long_line="************************************************************************"
downloads_cache="/root/Downloads"

# Requires all nomad client machines to run the following command
# and mount /scratch/nomad into the docker container:
# sudo mkdir -p /scratch/nomad && echo "$(hostname)-$(uname -m)" | sudo tee /scratch/nomad/nomad-client
# nomad_client_file="/scratch/nomad/nomad-client"
# if [ -f "$nomad_client_file" ] ; then
#     NOMAD_CLIENT="$(cat $nomad_client_file)"
# else
#     NOMAD_CLIENT="Unknown"
# fi
# Remove Nomad and Include GitHub Actions runner information
GITHUB_RUNNER="${RUNNER_NAME:-Unknown}"
GITHUB_WORKFLOW="${GITHUB_WORKFLOW:-Unknown}"
GITHUB_RUN_ID="${GITHUB_RUN_ID:-Unknown}"

# Node info
# echo "$long_line"
# echo "Executor Runtime Attributes:"
# echo "OS: $OS_ID-$OS_VERSION_ID"
# echo "Arch: $OS_ARCH"
# echo "Nomad Client Hostname: $NOMAD_CLIENT"
# echo "Container ID: $(hostname)"

echo "$long_line"
echo "GitHub Runner Attributes:"
echo "OS: $OS_ID-$OS_VERSION_ID"
echo "Arch: $OS_ARCH" 
echo "GitHub Runner: $GITHUB_RUNNER"
echo "GitHub Workflow: $GITHUB_WORKFLOW"
echo "GitHub Run ID: $GITHUB_RUN_ID"
echo "Runner Hostname: $(hostname)"

# Github Hosted Runner doesn't use Dockerfile, so skip this part
# echo "$long_line"
# if [ -f "$dockerfile" ] ; then
#     echo -e "Executor Dockerfile: ${dockerfile}\n${file_delimiter}"
#     cat $dockerfile
#     echo "$file_delimiter"
# else
#     echo "Unknown Executor: '$dockerfile' not found!"
# fi

# Performance analysis
perf_trials=2
perf_interval=1
if [ "$OS_ID" == "ubuntu" ] || [ "$OS_ID" = "debian" ] ; then
    SYSSTAT_PATH="/var/log/sysstat"
elif [ "$OS_ID" == "centos" ] ; then
    if [ "$OS_VERSION_ID" = "7" ] ; then
        SYSSTAT_PATH="/var/log/sa/sa02"
    else
        SYSSTAT_PATH="/var/log/sa"
    fi
fi
echo "$long_line"
echo "Virtual memory stat"
vmstat ${perf_interval} ${perf_trials} 2>/dev/null || echo "vmstat not available"
echo "CPU time breakdowns per CPU"
mpstat -P ALL ${perf_interval}  ${perf_trials} 2>/dev/null || echo "mpstat not available"
echo "Per-process summary"
pidstat ${perf_interval} ${perf_trials} 2>/dev/null || echo "pidstat not available"
echo "Block device stats"
iostat -xz ${perf_interval} ${perf_trials} 2>/dev/null || echo "iostat not available"
echo "Memory utilization"
free -m 2>/dev/null || echo "free not available"
echo "Network interface throughput"
sar -n DEV -o ${SYSSTAT_PATH} ${perf_interval} ${perf_trials} 2>/dev/null || echo "sar not available"
echo "TCP metrics"
sar -n TCP,ETCP -o ${SYSSTAT_PATH} ${perf_interval} ${perf_trials} 2>/dev/null || echo "sar not available"

# SW stack
echo "$long_line"
echo "Executor package list:"
if [ "$OS_ID" == "ubuntu" ] || [ "$OS_ID" = "debian" ] ; then
    dpkg-query -W -f='${binary:Package}\t${Version}\n' | column -t || true
elif [ "$OS_ID" == "centos" ] ; then
    yum list installed || true
fi

echo "$long_line"
echo "Python3 package list:"
pip3 list 2>/dev/null | column -t || true

echo "$long_line"
echo "Executor Downloads cache '$downloads_cache':"
ls -lh "$downloads_cache" || true

echo "$long_line"
echo "DNS nameserver config in '/etc/resolv.conf':"
cat /etc/resolv.conf || true

echo "$long_line"
# if [ -n "$(which ccache || true)" ] ; then
#     if  [ -z "${CCACHE_DIR:-}" ] || [ ! -d "$CCACHE_DIR" ] ; then
#         echo "CCACHE_DIR='$CCACHE_DIR' is missing, disabling CCACHE..."
#         export CCACHE_DISABLE="1"
#     fi
#     if [ -n "${CCACHE_DISABLE:-}" ] ; then
#         echo "CCACHE_DISABLE = '$CCACHE_DISABLE'"
#     fi
#     echo "ccache statistics:"
#     ccache -s
# else
#     echo "WARNING: ccache is not installed!"
#     export CCACHE_DISABLE="1"
# fi

# Update cache directory for GitHub Actions
downloads_cache="${GITHUB_WORKSPACE:-/github/workspace}/.cache"
mkdir -p "$downloads_cache" 2>/dev/null || true
echo "$long_line"

# GitHub Actions Environment Variables
echo "$long_line"
echo "GitHub Actions Environment:"
echo "GITHUB_WORKSPACE: ${GITHUB_WORKSPACE:-Not set}"
echo "GITHUB_REPOSITORY: ${GITHUB_REPOSITORY:-Not set}"
echo "GITHUB_REF: ${GITHUB_REF:-Not set}"
echo "GITHUB_SHA: ${GITHUB_SHA:-Not set}"
echo "GITHUB_EVENT_NAME: ${GITHUB_EVENT_NAME:-Not set}"
echo "$long_line"
