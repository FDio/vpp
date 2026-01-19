#!/usr/bin/env bash

CALICOVPP_DIR=${CALICOVPP_DIR:-"$HOME/vpp-dataplane"}
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%extras*}
COMMIT_HASH=$(git rev-parse HEAD)
STASH_SAVED=0

# Tag of built CalicoVPP images.
# CALICOVPP_VERSION should be the same as TAG when running kube-test
TAG=${TAG:-"kt-master"}
VPP_BASE=${VPP_BASE:-"$COMMIT_HASH"}
# branch name or commit hash
CALICOVPP_BASE=${CALICOVPP_BASE:-"origin/master"}

if [ "$1" = "" ]; then
    echo "This script will build, save and import images to both nodes.
To import kube-test images only, \$2 = kt
To import CalicoVPP images only, \$2 = cv
To import all, leave \$2 empty.
Only run this script on the master node.
    Usage:
    ./quick-import.sh user@remote:path [ kt | cv ]"
    exit 1
fi

remote_user="${1%%:*}"
remote_path="${1#*:}"

save_stash() {
  if [[ -n $(git status --porcelain) ]]; then
    git stash -u
    STASH_SAVED=1
    git stash apply
  fi
}

restore_repo() {
  git reset --hard $COMMIT_HASH
  if [ "$STASH_SAVED" -eq 1 ]; then
    git stash pop
  fi
}

build_calicovpp() {
  if [ ! -d "$CALICOVPP_DIR" ]; then
      git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
  fi

  cd $CALICOVPP_DIR
  git fetch --tags --force
  git reset --hard $CALICOVPP_BASE
  cd $VPP_DIR/extras/kube-test

  make -C $CALICOVPP_DIR/vpp-manager vpp VPP_DIR=$VPP_DIR VPP_BASE=$VPP_BASE && \
  make -C $CALICOVPP_DIR dev TAG=$TAG && \
  make -C $CALICOVPP_DIR image TAG=$TAG
}

set -x

if [ "$2" = "kt" ] || [ "$2" = "" ]; then
    make build
    docker save -o kube-test-images.tar $(docker images | grep kube-test | awk '{print $1":"$2}')
    sudo ctr -n k8s.io images import kube-test-images.tar
    scp kube-test-images.tar $1
    ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/kube-test-images.tar
fi

if [ "$2" = "cv" ] || [ "$2" = "" ]; then
    save_stash
    # delete CMakeCache so compiler is re-detected (should avoid compilation errors)
    rm $VPP_DIR/build-root/build-vpp*/vpp/CMakeCache.txt || true
    if ! build_calicovpp; then
      echo "*** Build failed. Restoring repo. Try running 'make -C ../.. wipe' and 'make -C ../.. wipe-release' ***"
      restore_repo
      exit 1
    fi

    restore_repo
    docker save -o calicovpp-images.tar docker.io/calicovpp/vpp:$TAG docker.io/calicovpp/agent:$TAG docker.io/calicovpp/multinet-monitor:$TAG
    sudo ctr -n k8s.io images import calicovpp-images.tar
    scp calicovpp-images.tar $1
    ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/calicovpp-images.tar
fi
