#!/usr/bin/env bash

CALICOVPP_DIR=${CALICOVPP_DIR:-"$HOME/vpp-dataplane"}
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%test-c*}
COMMIT_HASH=$(git rev-parse HEAD)

# Tag of built CalicoVPP images.
# CALICOVPP_VERSION should be the same as TAG when running kube-test
TAG=${TAG:-"kt-master"}
BASE=${BASE:-"$COMMIT_HASH"}

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

restore_repo() {
  git reset --hard $COMMIT_HASH
  git stash pop
}

build_calicovpp() {
  if [ ! -d "$CALICOVPP_DIR" ]; then
      git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
  else
      echo "Repo found, resetting"
      cd $CALICOVPP_DIR
      git reset --hard origin/master
      git fetch --tags --force
      git pull
      cd $VPP_DIR/test-c/kube-test
  fi

  make -C $CALICOVPP_DIR/vpp-manager vpp VPP_DIR=$VPP_DIR BASE=$BASE && \
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
    git stash -u && git stash apply
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
