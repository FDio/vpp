# vcl-ldpreload a LD_PRELOAD library that uses the VPP Communications Library (VCL).

User can LD_PRELOAD any application that uses POSIX socket API.

NOTE: The sources have been moved to .../vpp/src/vcl and libvcl_ldpreload.so
      libvcl-ldpreload.so is built with VPP and can be found in
      .../vpp/build-root/install-vpp[_debug]-native/vpp/lib64

## HowTo

# 1. Running the demo
## Run test script without parameters to see help menu:

export WS_ROOT=<top level vpp git repo dir>  (e.g. /scratch/my_name/vpp)
$WS_ROOT/test/scripts/socket_test.sh

# 2. Docker iPerf examples.
## These launch xterms. To quit, close xterms and run following docker kill cmd (WARNING: This will kill all docker containers!) 'docker kill $(docker ps -q)'


## Docker iPerf using default Linux Bridge

$WS_ROOT/test/scripts/socket_test.sh -bi docker-kernel

## Docker iPerf using VPP
$WS_ROOT/test/scripts/socket_test.sh -bi docker-preload

