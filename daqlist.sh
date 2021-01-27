#!/usr/bin/env bash

DIR=/home/damarion/cisco/vpp4/build-root/install-vpp_debug-native/vpp/lib/daq \
DIR=/opt/vpp/external/x86_64/lib/daq

export LD_LIBRARY_PATH=/opt/vpp/external/x86_64/lib
/opt/vpp/external/x86_64/bin/snort \
    --daq-dir $DIR \
    --daq-list
