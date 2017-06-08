#!/bin/bash
VPP_DIR=`dirname $0`
VER=$($VPP_DIR/version)
MAJOR=$(echo $VER | sed -r 's/(.{5}).*/\1/')
MAJOR_NODOT=$(echo $MAJOR | sed -e "s/\.//")
FULL=$(echo $VER | sed -e "s/-release//")

sed -e "s/\${major_release_nodot}/$MAJOR_NODOT/g" \
    -e "s/\${major_release}/$MAJOR/g" \
    -e "s/\${full_release}/$FULL/g" \
    $VPP_DIR/lf-release.txt
