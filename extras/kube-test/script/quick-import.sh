#!/usr/bin/env bash

export DOCKER_BUILD_PROXY=$http_proxy

CALICOVPP_DIR=${CALICOVPP_DIR:-"$HOME/vpp-dataplane"}
VPP_REPO_DIR=$(pwd)
VPP_REPO_DIR=${VPP_REPO_DIR%extras*}
COMMIT_HASH=$(git rev-parse HEAD)

# Tag of built CalicoVPP images.
# CALICOVPP_VERSION must be the same as TAG when running kube-test
TAG=${TAG:-"kt-master"}
VPP_BASE=${VPP_BASE:-"$COMMIT_HASH"}
[ "$VPP_BASE" = "default" ] && VPP_BASE=""
VPP_BUILD_DIR=${VPP_BUILD_DIR:-"$CALICOVPP_DIR/vpp-manager/vpp_build"}
VPP_BASE_REF=$VPP_BASE
# branch name or commit hash
CALICOVPP_BASE=${CALICOVPP_BASE:-"origin/master"}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/common.sh"

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
    VPP_BUILD_DIR - path to where VPP will be built (default: \$CALICOVPP_DIR/vpp-manager/vpp_build)"
    exit 1
fi

remote_user="${1%%:*}"
remote_path="${1#*:}"

build_calicovpp() {
  if [ ! -d "$CALICOVPP_DIR" ]; then
      git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
  fi

  cd $CALICOVPP_DIR
  git fetch --tags --force
  git reset --hard $CALICOVPP_BASE
  cd $VPP_REPO_DIR/extras/kube-test

  make -C $CALICOVPP_DIR/vpp-manager vpp VPP_DIR=$VPP_BUILD_DIR BASE=$VPP_BASE && \
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
    build_and_verify_vpp

    restore_repo
    docker save -o calicovpp-images.tar docker.io/calicovpp/vpp:$TAG docker.io/calicovpp/agent:$TAG docker.io/calicovpp/multinet-monitor:$TAG
    sudo ctr -n k8s.io images import calicovpp-images.tar
    scp calicovpp-images.tar $1
    ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/calicovpp-images.tar
fi
