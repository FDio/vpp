#!/usr/bin/env bash
# set -o xtrace

# Run VPP in a QEMU VM

if [[ -z ${WS_ROOT} ]];then
    echo "WS_ROOT must be set before running VM tests"
    exit 1
fi

HUGEPAGES=${HUGEPAGES:-256}
mkdir -p ${TEST_DATA_DIR}
mkdir -p ${FAILED_DIR}

# Download the Linux KVM Kernel Image, if not provided into the test data dir
function ensure_kvm_kernel_image {
    if [[ -z "${KERNEL_BIN}" ]] || [[ ! -f "${KERNEL_BIN}" ]]; then
       PWD=$(pwd)
       PKG=$(apt-cache depends -i linux-image-kvm | grep Depends: | cut -d: -f2)
       echo "Getting Linux KVM Kernel image..${PKG}"
       cd ${TEST_DATA_DIR}
       apt-get download ${PKG}
       dpkg --fsys-tarfile ${PKG}_*.deb | tar xvf - ./boot
       KERNEL_BIN=$(ls ${TEST_DATA_DIR}/boot/vmlinuz-*-kvm)
       cd ${PWD}
    fi
}

# Template to make a custom VPP startup.conf
# for running unit tests in QEMU VM (Optional)
function make_vpp_startup_conf {
   CONF=$(mktemp -p $TEST_DATA_DIR)
   GROUP=$(id -g -n)
   API_SEG=$(basename $CONF)
   IFS=$'\n'
   read -r -a VPP_CONF -d '' << _EOF_
unix { nodaemon
       full-coredump
       coredump-size unlimited
       runtime-dir ${TEST_DATA_DIR}
       cli-listen ${TEST_DATA_DIR}/cli.sock
       log ${TEST_DATA_DIR}/vpp.log
       gid ${GROUP}
      }

api-trace { on }

api-segment {
    gid ${GROUP}
}

physmem {
max-size 32m
}

statseg {
socket-name ${TEST_DATA_DIR}/stats.sock
}

socksvr {
socket-name ${TEST_DATA_DIR}/api.sock
}

node {   }

plugins {
plugin dpdk_plugin.so { disable }
plugin rdma_plugin.so { disable }
plugin lisp_unittest_plugin.so { enable }
plugin unittest_plugin.so { enable }
}

plugin_path ${WS_ROOT}/build-root/install-vpp-native/vpp/lib/vpp_plugins:${WS_ROOT}/build-root/install-vpp-native/vpp/lib64/vpp_plugins
test_plugin_path ${WS_ROOT}/build-root/install-vpp-native/vpp/lib/vpp_api_test_plugins:${WS_ROOT}/build-root/install-vpp-native/vpp/lib64/vpp_api_test_plugins
_EOF_

echo "${VPP_CONF[*]}"  > ${CONF}
}

# Run VPP in QEMU KVM
function run_in_vm {
    # make_vpp_startup_conf
    INIT=$(mktemp -p $TEST_DATA_DIR)
    cat > ${INIT} << __EOF__
#!/bin/bash
mount -t sysfs -o nodev,noexec,nosuid sysfs /sys
mount -t proc -o nodev,noexec,nosuid proc /proc
mkdir /dev/pts
mount -t devpts -o noexec,nosuid,gid=5,mode=0620 devpts /dev/pts || true
mount -t tmpfs -o "noexec,nosuid,size=10%,mode=0755" tmpfs /run
mkdir /dev/shm
mount -t tmpfs -o rw,nosuid,nodev tmpfs /dev/shm

mount -t 9p /dev/vpp9p ${WS_ROOT}
mount -t 9p /dev/tmp9p /tmp
echo "============================================================================="
# Uncomment the below lines to run VPP inside the QEMU VM with a custom config file
# echo "VPP config:"
# cat ${CONF}
# echo "Starting vpp..."
# ${WS_ROOT}/build-root/install-vpp-native/vpp/bin/vpp -c ${CONF}
# echo "==========================================================================="
env SOCKET=1 SANITY=no \
    FAILED_DIR=${FAILED_DIR} RND_SEED=${RND_SEED} \
    VENV_PATH=${VENV_PATH} TEST=${TEST} TEST_JOBS=${TEST_JOBS} \
    VPP_BUILD_DIR=${VPP_BUILD_DIR} VPP_BIN=${VPP_BIN} VPP_PLUGIN_PATH=${VPP_PLUGIN_PATH} \
    VPP_TEST_PLUGIN_PATH=${VPP_TEST_PLUGIN_PATH} VPP_INSTALL_PATH=${VPP_INSTALL_PATH} \
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH} \
    bash -c "source ${VENV_BIN}/activate && python3 ${WS_ROOT}/test/run_tests.py -d ${WS_ROOT}/test"
poweroff -f
__EOF__

chmod +x ${INIT}

sudo taskset -c 5-8 qemu-system-x86_64 \
             -nodefaults \
             -name test_$(basename $INIT) \
             -chardev stdio,mux=on,id=char0 \
             -mon chardev=char0,mode=readline,pretty=on \
             -serial chardev:char0 \
             -machine pc,accel=kvm,usb=off,mem-merge=off \
             -cpu host \
             -smp 4,sockets=1,cores=4,threads=1 \
             -m 2G \
             -no-user-config \
             -kernel ${KERNEL_BIN} \
             -virtfs local,path=/,mount_tag=/dev/root,security_model=none,id=root9p,multidevs=remap \
             -virtfs local,path=${WS_ROOT},mount_tag=/dev/vpp9p,security_model=none,id=vpp9p,multidevs=remap \
             -virtfs local,path=/tmp,mount_tag=/dev/tmp9p,security_model=none,id=tmp9p,multidevs=remap \
             -device virtio-net-pci,netdev=net0 \
             -netdev user,id=net0  \
             -nographic \
             -append "ro rootfstype=9p rootflags=trans=virtio console=ttyS0 hugepages=${HUGEPAGES} init=${INIT}"
}

ensure_kvm_kernel_image
run_in_vm
