#!/bin/bash

set -x

# This is meant to be run from the root doirectory

rm ./docs/gettingstarted/developers/punt.rst
cp ./src/vnet/ip/punt.rst ./docs/gettingstarted/developers/.
make docs-clean

set +x
