#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for kube-test scripts (setup-cluster.sh, quick-import.sh).
#
# Callers MUST set these variables before sourcing this file:
#   CALICOVPP_DIR   — path to the vpp-dataplane checkout
#   VPP_REPO_DIR    — path to the VPP source repository
#   VPP_BUILD_DIR   — path to the VPP build worktree
#   VPP_BASE_REF    — commit/branch to build VPP from (may be empty)
#   COMMIT_HASH     — HEAD commit of the VPP source repo
#   TAG             — Docker image tag (e.g. "kt-master")

STASH_SAVED=0
EXPECTED_VPP_HASH=

red ()   { printf "\e[0;31m$1\e[0m\n" >&2 ; }
green () { printf "\e[0;32m$1\e[0m\n" >&2 ; }

save_stash() {
  local prev_dir
  prev_dir=$(pwd)
  cd "$VPP_BUILD_DIR"
  git fetch --tags --force
  if [[ -n $(git status --porcelain) ]]; then
    git stash -u
    STASH_SAVED=1
    git stash apply
  fi
  cd "$prev_dir"
}

restore_repo() {
  local prev_dir
  prev_dir=$(pwd)
  cd "$VPP_BUILD_DIR"
  git reset --hard "$COMMIT_HASH" || true
  if [ "$STASH_SAVED" -eq 1 ]; then
    git stash pop
  fi
  cd "$prev_dir"
}

clean_vpp_build_artifacts() {
  if [ -d "$CALICOVPP_DIR/vpp-manager" ]; then
    make -C "$CALICOVPP_DIR/vpp-manager" clean-vpp VPP_DIR="$VPP_BUILD_DIR" || true
  fi
  rm "$VPP_BUILD_DIR"/build-root/build-vpp*/vpp/CMakeCache.txt || true
}

set_expected_vpp_hash() {
  if [ -n "$VPP_BASE_REF" ]; then
    EXPECTED_VPP_HASH=$(git -C "$VPP_REPO_DIR" rev-parse --short=9 \
      "$VPP_BASE_REF^{commit}" 2>/dev/null || true)
  fi
}

verify_vpp_image() {
  if [ -z "$EXPECTED_VPP_HASH" ]; then
    echo "*** Skipping VPP image commit verification: unable to resolve VPP_BASE_REF '$VPP_BASE_REF' ***"
    return 0
  fi

  local vpp_version
  vpp_version=$(docker run --rm --entrypoint /usr/bin/vpp "docker.io/calicovpp/vpp:$TAG" -v)
  echo "$vpp_version"
  if ! grep -q "$EXPECTED_VPP_HASH" <<< "$vpp_version"; then
    red "*** Built docker.io/calicovpp/vpp:$TAG does not contain expected VPP commit $EXPECTED_VPP_HASH ***"
    return 1
  fi
}

build_and_verify_vpp() {
  set_expected_vpp_hash
  clean_vpp_build_artifacts
  if ! build_calicovpp; then
    red "*** Build failed. Restoring repo. Try running 'make -C ../.. wipe' and 'make -C ../.. wipe-release' ***"
    restore_repo
    exit 1
  fi
  if ! verify_vpp_image; then
    restore_repo
    exit 1
  fi
}
