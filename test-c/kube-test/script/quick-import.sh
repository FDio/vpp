#!/usr/bin/env bash

if [ "$1" = "" ]; then
    echo "Export docker images first with 'docker save'. This script will import an image to both nodes.
Only run this script on the master node.
    Usage:
    1st arg: source/image path
    2nd arg: user@remote:path"
    exit 1
fi

user_remote="${2%%:*}"
path="${2#*:}"

set -x
sudo ctr -n k8s.io images import $1

scp $1 $2
ssh $user_remote "sudo ctr -n k8s.io images import \"$path\""
