#!/bin/sh
#
# An example to test the reproducible builds
#
# If the two build hosts have the same set of packages installed,
# the below should result in the identical .deb packages
#
set -eux
export VPP_BUILD_USER=builduser
export VPP_BUILD_HOST=buildhost
export SOURCE_DATE_EPOCH=1000000000
make pkg-deb
