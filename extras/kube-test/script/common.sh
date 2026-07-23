#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for kube-test scripts (setup-cluster.sh, quick-import.sh).
#
# Callers MUST set these variables before sourcing this file:
#   CALICOVPP_DIR   — path to the vpp-dataplane checkout
#   VPP_BUILD_DIR   — path to the VPP build worktree
#   VPP_BASE_REF    — commit/branch the build was based on (may be empty)
#   COMMIT_HASH     — HEAD commit of the VPP source repo
#   TAG             — Docker image tag (e.g. "kt-master")

STASH_SAVED=0

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
    # vpp-manager caches the built VPP artifacts as a tarball. Remove it
    # so the next rebuild path actually re-runs vpp_clone_current.sh and
    #  produces fresh artifacts even when the hash inputs are unchanged.
    rm -f "$CALICOVPP_DIR/vpp-manager/"vpp-*.tar || true
  fi
  rm "$VPP_BUILD_DIR"/build-root/build-vpp*/vpp/CMakeCache.txt || true
}

verify_vpp_image() {
  if [ ! -d "$VPP_BUILD_DIR/.git" ]; then
    echo "*** Skipping VPP image commit verification: $VPP_BUILD_DIR is not a git checkout ***"
    return 0
  fi

  # 1) Sanity-check that the vpp_build worktree descends from the expected
  # base commit. This catches cases where vpp_clone_current.sh silently falls
  # back to its hard-coded default BASE (e.g. when caller passes empty $BASE).
  if [ -n "$VPP_BASE_REF" ]; then
    if ! git -C "$VPP_BUILD_DIR" merge-base --is-ancestor \
         "$VPP_BASE_REF^{commit}" HEAD 2>/dev/null; then
      red "*** vpp_build HEAD does not descend from expected VPP base commit $VPP_BASE_REF ***"
      return 1
    fi
  fi

  # 2) Verify the built docker image binary matches vpp_build's HEAD.
  # CalicoVPP applies cherry-picks, patches and private plugins on top
  # of $VPP_BASE_REF, so vpp's version banner reflects vpp_build's tip
  # (post-patch), not the bare base commit. This catches cached/stale
  # tarballs or docker layers serving an older vpp binary.
  local expected_tip vpp_version
  expected_tip=$(git -C "$VPP_BUILD_DIR" rev-parse --short=9 HEAD)
  vpp_version=$(docker run --rm --entrypoint /usr/bin/vpp \
                "docker.io/calicovpp/vpp:$TAG" -v)
  echo "$vpp_version"

  if ! grep -q "$expected_tip" <<< "$vpp_version"; then
    red "*** Built docker.io/calicovpp/vpp:$TAG does not contain expected VPP commit $expected_tip (vpp_build HEAD) ***"
    return 1
  fi
}

build_and_verify_vpp() {
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
