#!/bin/bash

echo "Initialization Image"

git clone https://github.com/FDio/vpp.git ./vpp

cd vpp
yes | make install-dep
