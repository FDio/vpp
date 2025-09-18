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

# Normally we would have the settings in any bash script stricter:
#    set -e -o pipefail
#
# But there is a corner case scenario that triggers an error,
# namely when a new packagecloud repo is created, it is completely
# empty. Then the installation fails. However, since this
# script is an optimization, it is okay for it to fail without failing
# the entire job.
#
# Therefore, we do not use the "-e" here.

set -o pipefail

SCRIPT_NAME="setup_vpp_ext_deps"
START_TS=$(date +%s)

#--------------------- Configuration / Env ---------------------#
: "${STREAM:=master}"                 # default stream
: "${VERBOSE:=0}"                     # set 1 for verbose logs
: "${DRY_RUN:=0}"                     # set 1 to only simulate actions
: "${DOWNLOADS_DIR:=/root/Downloads}" # override cache dir
: "${APT_RETRIES:=3}"                 # retry count
: "${APT_RETRY_DELAY:=3}"             # initial backoff seconds
: "${SUMMARY_JSON:=1}"                # output JSON summary line

LOG_PREFIX="[${SCRIPT_NAME}]"
ACTION="none"
RESULT="unknown"
CACHED=false
PKG_VERSION=""
PKG_ARCH=""
SKIP_REASON=""
ADDED_LIST_FILE=""  # track repo list to remove

#--------------------- Logging Helpers -------------------------#
log() { printf '%s %s\n' "$LOG_PREFIX" "$*" ; }
logv() { [ "$VERBOSE" = "1" ] && log "$*" || true; }
warn() { printf '%s WARN: %s\n' "$LOG_PREFIX" "$*" >&2; }
err()  { printf '%s ERROR: %s\n' "$LOG_PREFIX" "$*" >&2; }

json_summary() {
  [ "$SUMMARY_JSON" = "1" ] || return 0
  local end_ts dur
  end_ts=$(date +%s)
  dur=$(( end_ts - START_TS ))
  printf '{"script":"%s","stream":"%s","os":"%s","action":"%s","result":"%s","cached":%s,"version":"%s","arch":"%s","duration_sec":%s,"skip_reason":"%s"}\n' \
    "$SCRIPT_NAME" "$STREAM" "$OS_ID" "$ACTION" "$RESULT" "$CACHED" "${PKG_VERSION}" "${PKG_ARCH}" "$dur" "${SKIP_REASON}" || true
}

finish() { json_summary; exit 0; }
trap 'RESULT="error"; json_summary' EXIT

log "---> ${SCRIPT_NAME}: starting (STREAM=$STREAM VERBOSE=$VERBOSE DRY_RUN=$DRY_RUN)"

#--------------------- Validation ------------------------------#
if ! printf '%s' "$STREAM" | grep -Eq '^(master|stable/[0-9]{4})$'; then
  warn "STREAM '$STREAM' does not match expected patterns; proceeding anyway (treated as custom)."
fi

#--------------------- OS Detection ----------------------------#
OS_ID=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -f2- -d= | sed -e 's/"//g') || OS_ID="unknown"
OS_VERSION_ID=$(grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -f2- -d= | sed -e 's/"//g') || OS_VERSION_ID="unknown"
OS_ID_LC=${OS_ID,,}
logv "Detected OS: ${OS_ID} ${OS_VERSION_ID}"

case "$OS_ID_LC" in
  ubuntu|debian) : ;;
  *) SKIP_REASON="unsupported_os"; warn "Unsupported OS '$OS_ID' – skipping."; RESULT="skip"; finish ;;
esac

#--------------------- Preparation -----------------------------#
mkdir -p "$DOWNLOADS_DIR" 2>/dev/null || true
logv "Using downloads cache dir: $DOWNLOADS_DIR"

REPO_URL="https://packagecloud.io/fdio/${STREAM}"
INSTALL_URL="https://packagecloud.io/install/repositories/fdio/${STREAM}"
logv "REPO_URL: $REPO_URL"
logv "INSTALL_URL: $INSTALL_URL"

# Global lock to avoid concurrent apt operations (best effort)
LOCK_FD=99
LOCK_FILE=/tmp/${SCRIPT_NAME}.lock
if command -v flock >/dev/null 2>&1; then
  exec {LOCK_FD}>"$LOCK_FILE" || true
  if flock -n $LOCK_FD; then
    logv "Acquired lock $LOCK_FILE"
  else
    logv "Waiting for lock $LOCK_FILE"
    flock $LOCK_FD || true
  fi
else
  logv "flock not available; continuing without lock"
fi

#--------------------- Utility Functions -----------------------#
retry_cmd() {
  local attempt=1 rc
  while true; do
    "$@" && return 0
    rc=$?
    if [ $attempt -ge "$APT_RETRIES" ]; then
      return $rc
    fi
    local sleep_for=$(( APT_RETRY_DELAY * attempt ))
    warn "Command failed (rc=$rc). Attempt $attempt/$APT_RETRIES. Retrying in ${sleep_for}s: $*"
    sleep "$sleep_for"
    attempt=$(( attempt + 1 ))
  done
}

apt_update() {
  [ "$DRY_RUN" = "1" ] && { log "DRY_RUN: apt-get update skipped"; return 0; }
  retry_cmd sudo apt-get update -qq || return $?
}

apt_install_pkg() {
  [ "$DRY_RUN" = "1" ] && { log "DRY_RUN: apt-get install $* skipped"; return 0; }
  DEBIAN_FRONTEND=noninteractive retry_cmd sudo apt-get -y \
    -o Dpkg::Use-Pty=0 --no-install-recommends \
    --allow-downgrades --allow-remove-essential --allow-change-held-packages install "$@"
}

add_stream_repo_if_needed() {
  if [ "$STREAM" != "master" ]; then
    log "Configuring stream-specific apt repository for '$STREAM'"
    [ "$DRY_RUN" = "1" ] && { log "DRY_RUN: repo setup skipped"; return 0; }
    sudo apt-get -y remove vpp-ext-deps >/dev/null 2>&1 || true
    sudo rm -f /etc/apt/sources.list.d/fdio_master.list || true
    # The packagecloud script handles key and list creation; tolerate empty repo.
    if ! curl --fail --show-error --location --retry 3 --connect-timeout 10 -s "$INSTALL_URL/script.deb.sh" | sudo bash; then
      warn "Repository setup script failed (possibly empty repo). Proceeding (optimization only)."
    else
      # Attempt to capture the list file we added (best effort)
      ADDED_LIST_FILE=$(ls -1t /etc/apt/sources.list.d/fdio_*.list 2>/dev/null | head -1 || true)
      logv "Added list file: $ADDED_LIST_FILE"
    fi
  else
    logv "STREAM is master; using existing default repo configuration if any"
  fi
}

remove_added_repo() {
  [ "$DRY_RUN" = "1" ] && return 0
  if [ -n "$ADDED_LIST_FILE" ] && [ -f "$ADDED_LIST_FILE" ]; then
    logv "Removing added repo list $ADDED_LIST_FILE"
    sudo rm -f "$ADDED_LIST_FILE" || true
  else
    # Fall back to broad removal only for safety
    sudo rm -f /etc/apt/sources.list.d/fdio_*.list || true
  fi
}

read_pkg_metadata() {
  PKG_VERSION=$(apt-cache show vpp-ext-deps 2>/dev/null | awk '/^Version:/ {print $2; exit}') || PKG_VERSION=""
  PKG_ARCH=$(apt-cache show vpp-ext-deps 2>/dev/null | awk '/^Architecture:/ {print $2; exit}') || PKG_ARCH=""
  [ -n "$PKG_VERSION" ] && logv "Metadata: version=$PKG_VERSION arch=$PKG_ARCH" || logv "No metadata retrieved (maybe empty repo)"
}

#----- Use a cache dir so later jobs/steps can reuse it even after container lifecycle ends. ---------##
cache_pkg_if_present() {
  [ "$DRY_RUN" = "1" ] && return 0
  local deb="/var/cache/apt/archives/vpp-ext-deps_${PKG_VERSION}_${PKG_ARCH}.deb"
  if [ -f "$deb" ]; then
    cp -n "$deb" "$DOWNLOADS_DIR/" 2>/dev/null || true
  fi
}

#--------------------- Package Installation from Cache if Present --------------------#
install_from_cache() {
  local cached_pkg="$DOWNLOADS_DIR/vpp-ext-deps_${PKG_VERSION}_${PKG_ARCH}.deb"
  if [ -f "$cached_pkg" ]; then
    # Validate archive looks sane
    if dpkg-deb --info "$cached_pkg" >/dev/null 2>&1; then
      log "Installing cached package $cached_pkg"
      [ "$DRY_RUN" = "1" ] && { log "DRY_RUN: skip dpkg -i $cached_pkg"; return 0; }
      if sudo dpkg -i "$cached_pkg"; then
        CACHED=true
        return 0
      else
        warn "Cached package install failed; will attempt network install"
      fi
    else
      warn "Cached package invalid; deleting $cached_pkg"
      rm -f "$cached_pkg" || true
    fi
  fi
  return 1
}

install_remote() {
  log "Installing vpp-ext-deps from packagecloud"
  apt_install_pkg vpp-ext-deps || return $?
  cache_pkg_if_present
}

#--------------------- Main Flow -------------------------------#
(
  set +e  # still allow manual control
  add_stream_repo_if_needed
  apt_update || true
  read_pkg_metadata
  if [ -n "$PKG_VERSION" ] && install_from_cache; then
    ACTION="install"; RESULT="success"; exit 0
  fi
  if [ -n "$PKG_VERSION" ]; then
    if install_remote; then
      ACTION="install"; RESULT="success"; exit 0
    else
      warn "Remote install attempt failed"
    fi
  else
    warn "Package metadata unavailable (empty or unreachable repo)"
  fi
  ACTION="install"; RESULT="failed"; exit 0  # still success exit for optimization script
) || true

# Cleanup repo references regardless of outcome
remove_added_repo || true
apt_update || true

log "Completed optimization attempt (RESULT=$RESULT CACHED=$CACHED VERSION=$PKG_VERSION)"

# Adjust RESULT if still unknown
[ "$RESULT" = "unknown" ] && RESULT="noop"

# End (always success exit status for optimization nature)
json_summary
trap - EXIT
exit 0
