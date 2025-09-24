#!/usr/bin/env bash

if [ "$1" = "" ]; then
    echo "This script will save and import images to both nodes.
Only run this script on the master node.
    Usage:
    ./quick-import.sh user@remote:path"
    exit 1
fi

remote_user="${1%%:*}"
remote_path="${1#*:}"

set -x
docker save -o kube-test-images.tar $(docker images | grep kube-test | awk '{print $1":"$2}')
sudo ctr -n k8s.io images import kube-test-images.tar

scp kube-test-images.tar $1
ssh $remote_user "sudo ctr -n k8s.io images import \"$remote_path\""/kube-test-images.tar
