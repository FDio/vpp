#!/usr/bin/env bash

CALICOVPP_DIR="$HOME/vpp-dataplane"
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%test-c*}

if [ "$1" = "" ]; then
    echo "This script will save and import images to both nodes.
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

set -xe

if [ "$2" = "kt" ] || [ "$2" = "" ]; then
    make build
    docker save -o kube-test-images.tar $(docker images | grep kube-test | awk '{print $1":"$2}')
    sudo ctr -n k8s.io images import kube-test-images.tar
    scp kube-test-images.tar $1
    ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/kube-test-images.tar
fi

if [ "$2" = "cv" ] || [ "$2" = "" ]; then
    if [ ! -d "$CALICOVPP_DIR" ]; then
          git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
    else
        echo "Repo found, resetting"
        cd $CALICOVPP_DIR
        git reset --hard origin/master
        git pull
        cd $CALICOVPP_DIR/vpp-manager/vpp_build
        git reset --hard origin/master
        cd $VPP_DIR/test-c/kube-test
    fi

    make -C $CALICOVPP_DIR image TAG=latest
    docker save -o calicovpp-images.tar docker.io/calicovpp/vpp:latest docker.io/calicovpp/agent:latest docker.io/calicovpp/multinet-monitor:latest
    sudo ctr -n k8s.io images import calicovpp-images.tar
    scp calicovpp-images.tar $1
    ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/calicovpp-images.tar
fi
