#!/usr/bin/env bash

# idea is to "source ./env.sh" so Vagrantfile env vars are set.

export VPP_VAGRANT_ENV_SET=1
export VPP_VAGRANT_NICS=2
export VPP_VAGRANT_DISTRO="ubuntu1404" #Options: "centos7"
export VPP_VAGRANT_RAM="4096"
export VPP_VAGRANT_VCPUS="2"
