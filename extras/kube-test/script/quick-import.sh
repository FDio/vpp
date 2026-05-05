#!/usr/bin/env bash

export DOCKER_BUILD_PROXY=$http_proxy

CALICOVPP_DIR=${CALICOVPP_DIR:-"$HOME/vpp-dataplane"}
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%extras*}
COMMIT_HASH=$(git rev-parse HEAD)
STASH_SAVED=0

# Query repo layout via 'make repo-layout' (present from v3.33.0).
# Sets: CALICOVPP_MAKE_DIR, VPP_BUILD_REL_PATH, CALICOVPP_AGENT_IMAGE
# Returns 0 if successful, 1 if repo absent or target missing (old layout).
query_calicovpp_layout() {
  [ -d "$CALICOVPP_DIR" ] || return 1
  local layout_tmp
  layout_tmp=$(mktemp)
  if make -C "$CALICOVPP_DIR" repo-layout > "$layout_tmp" 2>/dev/null; then
    . "$layout_tmp"
    CALICOVPP_MAKE_DIR="$CALICOVPP_DIR/${VPP_MANAGER_REL_PATH}"
    export VPP_BUILD_REL_PATH CALICOVPP_AGENT_IMAGE
    rm -f "$layout_tmp"
    return 0
  fi
  rm -f "$layout_tmp"
  # Old layout fallback
  CALICOVPP_MAKE_DIR="$CALICOVPP_DIR/vpp-manager"
  export VPP_BUILD_REL_PATH="vpp-manager/vpp_build"
  export CALICOVPP_AGENT_IMAGE="calicovpp/agent"
  return 1
}

TAG=${TAG:-"kt-master"}
VPP_BASE=${VPP_BASE:-"$COMMIT_HASH"}
[ "$VPP_BASE" = "default" ] && VPP_BASE=""
CALICOVPP_BASE=${CALICOVPP_BASE:-"origin/master"}

# Determine VPP_BUILD_DIR at startup for CMakeCache cleanup (probes directories)
if [ -d "$CALICOVPP_DIR/vpp-manager/vpp_build" ]; then
  _VPP_BUILD_DEFAULT="$CALICOVPP_DIR/vpp-manager/vpp_build"
else
  _VPP_BUILD_DEFAULT="$CALICOVPP_DIR/vpp_build"
fi
VPP_BUILD_DIR=${VPP_BUILD_DIR:-"$_VPP_BUILD_DEFAULT"}

if [ "$1" = "" ]; then
    echo "This script will build, save and import images to both nodes.
To import kube-test images only, \$2 = kt or kt-dbg
To import CalicoVPP images only, \$2 = cv
To import all, leave \$2 empty.
Only run this script on the master node.
    Usage:
    ./quick-import.sh user@remote:path [ kt | kt-dbg | cv ]
    Env vars:
    TAG - CalicoVPP image tag (default: kt-master)
    VPP_BASE - commit or branch to build VPP from (default: current commit)
    VPP_BUILD_DIR - path to where VPP will be built (default: auto-detected from \$CALICOVPP_DIR)"
    exit 1
fi

remote_user="${1%%:*}"
remote_path="${1#*:}"

save_stash() {
  tmp_path=$(pwd)
  cd $VPP_BUILD_DIR
  if [[ -n $(git status --porcelain) ]]; then
    git stash -u
    STASH_SAVED=1
    git stash apply
  fi
  cd $tmp_path
}

restore_repo() {
  tmp_path=$(pwd)
  cd $VPP_BUILD_DIR
  git reset --hard $COMMIT_HASH
  if [ "$STASH_SAVED" -eq 1 ]; then
    git stash pop
  fi
  cd $tmp_path
}

build_calicovpp() {
  if [ ! -d "$CALICOVPP_DIR" ]; then
      git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
  fi

  cd $CALICOVPP_DIR
  git fetch --tags --force
  git reset --hard $CALICOVPP_BASE
  cd $VPP_DIR/extras/kube-test

  query_calicovpp_layout

  make -C $CALICOVPP_MAKE_DIR vpp VPP_DIR=$VPP_BUILD_DIR BASE=$VPP_BASE && \
  make -C $CALICOVPP_DIR dev TAG=$TAG && \
  make -C $CALICOVPP_DIR image TAG=$TAG BASE=$VPP_BASE
}

set -x

if [ "$2" = "kt" ] || [ "$2" = "kt-dbg" ] || [ "$2" = "" ]; then
    if [ "$2" = "kt-dbg" ]; then
        make build-debug
    else
        make build
    fi
    docker save -o kube-test-images.tar $(docker images | grep kube-test | awk '{print $1":"$2}')
    sudo ctr -n k8s.io images import kube-test-images.tar
    scp kube-test-images.tar $1
    ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/kube-test-images.tar
fi

if [ "$2" = "cv" ] || [ "$2" = "" ]; then
    save_stash
    # delete CMakeCache so compiler is re-detected (should avoid compilation errors)
    rm $VPP_BUILD_DIR/build-root/build-vpp*/vpp/CMakeCache.txt || true
    if ! build_calicovpp; then
      echo "*** Build failed. Restoring repo. Try running 'make -C ../.. wipe' and 'make -C ../.. wipe-release' ***"
      restore_repo
      exit 1
    fi

    restore_repo
    # Save all available calicovpp images (unified or separate)
    calicovpp_images="docker.io/calicovpp/vpp:$TAG"
    for component in agent multinet-monitor; do
      if docker image inspect docker.io/calicovpp/$component:$TAG >/dev/null 2>&1; then
        calicovpp_images="$calicovpp_images docker.io/calicovpp/$component:$TAG"
      fi
    done
    docker save -o calicovpp-images.tar $calicovpp_images
    sudo ctr -n k8s.io images import calicovpp-images.tar
    scp calicovpp-images.tar $1
    ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/calicovpp-images.tar
fi
