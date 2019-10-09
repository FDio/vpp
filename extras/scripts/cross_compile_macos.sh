#!/bin/bash

VPP_DIR=$(dirname ${BASH_SOURCE[0]})/../..
VPP_TOOLCHAIN_FILE=$VPP_DIR/extras/scripts/.config/macos.toolchain
BUILD_PATCH=$VPP_DIR/extras/scripts/patches/macos_build_externals.patch
VPP_EXPORT_CC=""

function help() {
cat << __EOF__
Usage: $0 [COMMAND]
conf <dir>        create the configuration file
                  with the give cross-toolchain directory
build             run Macos <make build>
build-release     run Macos <make build-release>
compile_commands  Generate compile_commands.json
__EOF__
}

function create_toolchain_file () {
    if [ x$1 = x ]; then
        echo "Please specify the cross toolchain directory"
        exit 1
    fi
    XCHAIN=$1
    if [ ! -e  ]; then
      mkdir -p $VPP_DIR/extras/scripts/.config
      echo "
SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_VERSION 1)

# specify the cross compiler
SET(CMAKE_C_COMPILER   $XCHAIN/x86_64-ubuntu16.04-linux-gnu/bin/x86_64-ubuntu16.04-linux-gnu-gcc)
SET(CMAKE_CXX_COMPILER $XCHAIN/x86_64-ubuntu16.04-linux-gnu/bin/x86_64-ubuntu16.04-linux-gnu-g++)

# where is the target environment
SET(CMAKE_FIND_ROOT_PATH  $XCHAIN/x86_64-ubuntu16.04-linux-gnu $XCHAIN/x86_64-ubuntu16.04-linux-gnu/x86_64-ubuntu16.04-linux-gnu/sysroot/)

SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
SET(CMAKE_SYSTEM_PROCESSOR x86_64)
# This is needed to build vpp-papi
SET(PYTHON_EXECUTABLE /usr/local/bin/python)" | tee $VPP_TOOLCHAIN_FILE > /dev/null
      echo "Configration file created"
      echo "please edit $VPP_TOOLCHAIN_FILE"
    else
      echo "configuration file already exists"
      echo "please edit $VPP_TOOLCHAIN_FILE"
    fi
}

function vpp_make () {
  cd $VPP_DIR ; git apply $BUILD_PATCH
  trap "cd $VPP_DIR ; git apply -R $BUILD_PATCH" EXIT
  export VPP_EXTRA_CMAKE_ARGS="-DCMAKE_TOOLCHAIN_FILE=${VPP_TOOLCHAIN_FILE} -DCMAKE_EXPORT_COMPILE_COMMANDS=${VPP_EXPORT_CC}" ; make -C $VPP_DIR $1
}

case $1 in
    conf)
        create_toolchain_file $2
        ;;
    build)
        vpp_make build
        ;;
    build-release)
        vpp_make build-release
        ;;
    compile_commands)
        VPP_EXPORT_CC=ON vpp_make build
        echo "compile_commands.json should be generated"
        echo "check $VPP_DIR/build-root/build-vpp_debug-native/vpp/compile_commands.json"
        ;;
    *)
        help
        ;;
esac