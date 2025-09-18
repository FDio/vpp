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

# Strict mode
set -euo pipefail
IFS=$' \t\n'

trap 'ec=$?; echo "[ERROR] setup_executor_env.sh failed at line $LINENO with exit code $ec" >&2' ERR

# Load OS metadata
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_VERSION_ID="${VERSION_ID:-unknown}"
else
  OS_ID="unknown"
  OS_VERSION_ID="unknown"
fi
OS_ARCH=$(uname -m)

file_delimiter="----- %< -----"
long_line="************************************************************************"
# Original downloads cache (may be ephemeral inside container)
downloads_cache="/root/Downloads"

GITHUB_RUNNER="${RUNNER_NAME:-Unknown}"
GITHUB_WORKFLOW="${GITHUB_WORKFLOW:-Unknown}"
GITHUB_RUN_ID="${GITHUB_RUN_ID:-Unknown}"

# Toggle envs (can be overridden from workflow)
: "${PERF_PROBE:=1}"            # 1 to collect perf snapshots
: "${VERBOSE_PACKAGES:=1}"      # 1 to list installed OS packages
: "${VERBOSE_PY:=1}"            # 1 to list python packages
: "${CCACHE_MAXSIZE:=20G}"      # Max ccache size
: "${CCACHE_COMPILERCHECK:=content}" # Safer compiler change detection

log_line() { echo "$long_line"; }

print_runner_attrs() {
  log_line
  echo "GitHub Runner Attributes:"
  echo "OS: ${OS_ID}-${OS_VERSION_ID}"
  echo "Arch: ${OS_ARCH}"
  echo "GitHub Runner: ${GITHUB_RUNNER}"
  echo "GitHub Workflow: ${GITHUB_WORKFLOW}"
  echo "GitHub Run ID: ${GITHUB_RUN_ID}"
  echo "Runner Hostname: $(hostname)"
}

collect_perf_snapshots() {
  [ "${PERF_PROBE}" = "1" ] || { echo "PERF_PROBE disabled"; return 0; }
  log_line
  echo "Collecting lightweight performance snapshots"
  perf_trials=2
  perf_interval=1
  # Determine SYSSTAT path (retain legacy logic)
  if [ "${OS_ID}" = "ubuntu" ] || [ "${OS_ID}" = "debian" ]; then
    SYSSTAT_PATH="/var/log/sysstat"
  elif [ "${OS_ID}" = "centos" ]; then
    if [ "${OS_VERSION_ID}" = "7" ]; then
      SYSSTAT_PATH="/var/log/sa/sa02"
    else
      SYSSTAT_PATH="/var/log/sa"
    fi
  else
    SYSSTAT_PATH="/var/log"
  fi
  echo "Virtual memory stat"; vmstat ${perf_interval} ${perf_trials} 2>/dev/null || echo "vmstat not available"
  echo "CPU time breakdowns per CPU"; mpstat -P ALL ${perf_interval} ${perf_trials} 2>/dev/null || echo "mpstat not available"
  echo "Per-process summary"; pidstat ${perf_interval} ${perf_trials} 2>/dev/null || echo "pidstat not available"
  echo "Block device stats"; iostat -xz ${perf_interval} ${perf_trials} 2>/dev/null || echo "iostat not available"
  echo "Memory utilization"; free -m 2>/dev/null || echo "free not available"
  echo "Network interface throughput"; sar -n DEV -o "${SYSSTAT_PATH}" ${perf_interval} ${perf_trials} 2>/dev/null || echo "sar not available"
  echo "TCP metrics"; sar -n TCP,ETCP -o "${SYSSTAT_PATH}" ${perf_interval} ${perf_trials} 2>/dev/null || echo "sar not available"
}

show_os_packages() {
  [ "${VERBOSE_PACKAGES}" = "1" ] || { echo "Skipping OS package list (VERBOSE_PACKAGES=0)"; return 0; }
  log_line
  echo "Executor package list:"
  if [ "${OS_ID}" = "ubuntu" ] || [ "${OS_ID}" = "debian" ]; then
    dpkg-query -W -f='${binary:Package}\t${Version}\n' | column -t || true
  elif [ "${OS_ID}" = "centos" ]; then
    yum list installed || true
  else
    echo "Unsupported OS for package listing"
  fi
}

show_python_packages() {
  [ "${VERBOSE_PY}" = "1" ] || { echo "Skipping Python package list (VERBOSE_PY=0)"; return 0; }
  log_line
  echo "Python3 package list:"
  pip3 list 2>/dev/null | column -t || true
}

show_downloads_cache() {
  log_line
  echo "Executor Downloads cache '${downloads_cache}':"
  ls -lh "${downloads_cache}" || true
}

show_resolver() {
  log_line
  echo "DNS nameserver config in '/etc/resolv.conf':"
  # Mask potential search domains if needed; currently print full
  cat /etc/resolv.conf || true
}

setup_ccache() {
  log_line
  if command -v ccache >/dev/null 2>&1; then
    # Ensure CCACHE_DIR is set and exists
    if [ -z "${CCACHE_DIR:-}" ]; then
      # Derive a default if not provided (caller may pass one via env)
      CCACHE_DIR="/scratch/ccache/${OS_ID}-${OS_VERSION_ID}-${OS_ARCH}"
      export CCACHE_DIR
    fi
    if [ ! -d "${CCACHE_DIR}" ]; then
      echo "Creating CCACHE_DIR='${CCACHE_DIR}'"
      if ! mkdir -p "${CCACHE_DIR}" 2>/dev/null; then
        echo "Failed to create CCACHE_DIR; disabling ccache"
        export CCACHE_DISABLE=1
      fi
    fi
    if [ -z "${CCACHE_DISABLE:-}" ]; then
      export CCACHE_MAXSIZE CCACHE_COMPILERCHECK
      echo "ccache enabled: dir='${CCACHE_DIR}' max='${CCACHE_MAXSIZE}' compilercheck='${CCACHE_COMPILERCHECK}'"
      echo "Initial ccache stats:"; ccache -s || true
    else
      echo "ccache explicitly disabled (CCACHE_DISABLE='${CCACHE_DISABLE}')"
    fi
  else
    echo "WARNING: ccache is not installed (will proceed without caching)"
    export CCACHE_DISABLE=1
  fi
}

prepare_workspace_cache() {
  # Update cache directory for GitHub Actions (for other tooling reuse)
  downloads_cache="${GITHUB_WORKSPACE:-/github/workspace}/.cache"
  mkdir -p "${downloads_cache}" 2>/dev/null || true
  log_line
}

show_github_env() {
  log_line
  echo "GitHub Actions Environment:"
  echo "GITHUB_WORKSPACE: ${GITHUB_WORKSPACE:-Not set}"
  echo "GITHUB_REPOSITORY: ${GITHUB_REPOSITORY:-Not set}"
  echo "GITHUB_REF: ${GITHUB_REF:-Not set}"
  echo "GITHUB_SHA: ${GITHUB_SHA:-Not set}"
  echo "GITHUB_EVENT_NAME: ${GITHUB_EVENT_NAME:-Not set}"
  log_line
}

# Execution sequence
print_runner_attrs
collect_perf_snapshots
show_os_packages
show_python_packages
show_downloads_cache
show_resolver
setup_ccache
prepare_workspace_cache
show_github_env

# Success footer
echo "Executor environment setup complete."
