# vcl-ldpreload a LD_PRELOAD library that uses the VPP Communications Library (VCL).

User can LD_PRELOAD any application that uses POSIX socket API.
This library internally uses libvppcom.so library from VPP project.


## HowTo

If VPP is not installed, but rather built in a separate directory, you can use the VPP_DIR 'configure' argument.
```bash
# 1. Set environment variables for source
cd vpp/extras/vcl-ldpreload
source ./env.sh

# 2. Change to VPP source directory and build
- Change director and modify uri.am to enable socket_test program

cd $VPP_DIR
perl -pi -e 's/noinst_PROGRAMS/bin_PROGRAMS/g' $VPP_DIR/src/uri.am

- Build VPP release 

make install-dep wipe-release bootstrap dpdk-install-dev build-release

# 2. Build LD_PRELOAD library against VPP build above
## This does not install the LD_PRELOAD library in your system.
## Instead it will be referenced from the build directory set in VCL_LDPRELOAD_LIB

cd $LDP_DIR/vcl-ldpreload/src
autoreconf -i -f
./configure VPP_DIR=$VPP_DIR
make
```bash


# 3. Running the demo
## Run test script without parameters to see help menu:

cd $VPP_DIR/test/scripts
./socket_test.sh

# 4. Docker iPerf examples.
## These launch xterms. To quit, close xterms and run following docker kill cmd (WARNING: This will kill all docker containers!) 'docker kill $(docker ps -q)'


## Docker iPerf using default Linux Bridge

./socket_test.sh -bi docker-kernel

## Docker iPerf using VPP
./socket_test.sh -bi docker-preload

