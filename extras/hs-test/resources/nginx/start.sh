#!/bin/bash

LDP_PATH=/usr/lib/libvcl_ldpreload.so
VCL_CFG=/vcl.conf
LD_PRELOAD=$LDP_PATH VCL_CONFIG=$VCL_CFG nginx -c /nginx.conf
tail -f /dev/null
