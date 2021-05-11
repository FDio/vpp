#!/usr/bin/env bash
# Run VPP in a QEMU VM
# set -o xtrace
set -o nounset

# Arguments:
# $1:- Test Filter
# $2:- Kernel Binary
# $3:- Test Data Directory

if [[ "$#" -ne 3 ]]; then
    echo "Incorrect number of arguments..3 args required"
    exit 1
fi

if [[ -z "${1:-}" ]]; then
    echo "Must provide a valid test to run in inside the QEMU VM"
    exit 1
fi
TEST=${1:-}

# Ensure test dir
TEST_DATA_DIR=${3:-"/tmp/vpp-vm-tests"}
if [[ ! -d ${TEST_DATA_DIR} ]]; then
    mkdir -p ${TEST_DATA_DIR}
fi

# Set the OS Package
os_VENDOR=$(lsb_release -i -s)
if [[ $os_VENDOR =~ (Debian|Ubuntu) ]]; then
    os_PACKAGE="deb"
else
    os_PACKAGE="rpm"
fi

# Download a KVM Kernel Image for Debian/Ubuntu
if [[ -z "${2:-}" ]] || [[ ! -f "${2:-}" ]]; then
    if [[ $os_PACKAGE == "deb" ]]; then
        PWD=$(pwd)
        cd ${TEST_DATA_DIR}
        PKG=$(apt-cache depends -i linux-image-kvm | grep Depends: | cut -d: -f2)
        echo "Getting Linux KVM Kernel image..${PKG}"
        apt-get download ${PKG}
        dpkg --fsys-tarfile ${PKG}_*.deb | tar xvf - ./boot
        KERNEL_BIN=$(ls ${TEST_DATA_DIR}/boot/vmlinuz-*-kvm)
        cd ${PWD}
    else
        echo "Ensure that the qemu-kvm package is installed, the QEMU environment variable
        points to the qemu-kvm binary path & a KVM Kernel is selected."
        exit 1
    fi
else
    KERNEL_BIN=${2}
fi

FAILED_DIR="/tmp/vpp-failed-unittests/"
if [[ ! -d ${FAILED_DIR} ]]; then
    mkdir -p ${FAILED_DIR}
fi

HUGEPAGES=${HUGEPAGES:-256}
QEMU=${QEMU:-"qemu-system-x86_64"}

# Ensure the required env. vars are set
WS_ROOT=$(echo $WS_ROOT)
RND_SEED=$(echo $RND_SEED)
BR=$(echo $BR)
VENV_PATH=$(echo $VENV_PATH)
TEST_JOBS=$(echo $TEST_JOBS)
VPP_BUILD_DIR=$(echo $VPP_BUILD_DIR)
VPP_BIN=$(echo $VPP_BIN)
VPP_PLUGIN_PATH=$(echo $VPP_PLUGIN_PATH)
VPP_TEST_PLUGIN_PATH=$(echo $VPP_TEST_PLUGIN_PATH)
VPP_INSTALL_PATH=$(echo $VPP_INSTALL_PATH)
LD_LIBRARY_PATH=$(echo $LD_LIBRARY_PATH)

# Boot a QEMU VM and run the test
function run_in_vm {
    INIT=$(mktemp -p ${TEST_DATA_DIR})
    cat > ${INIT} << _EOF_
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

env SOCKET=1 SANITY=no \
FAILED_DIR=${FAILED_DIR} RND_SEED=${RND_SEED} BR=${BR} \
VENV_PATH=${VENV_PATH} TEST=${TEST} TEST_JOBS=${TEST_JOBS} \
VPP_BUILD_DIR=${VPP_BUILD_DIR} VPP_BIN=${VPP_BIN} VPP_PLUGIN_PATH=${VPP_PLUGIN_PATH} \
VPP_TEST_PLUGIN_PATH=${VPP_TEST_PLUGIN_PATH} VPP_INSTALL_PATH=${VPP_INSTALL_PATH} \
LD_LIBRARY_PATH=${LD_LIBRARY_PATH} \
bash -c "source ${VENV_PATH}/bin/activate && python3 ${WS_ROOT}/test/run_tests.py -d ${WS_ROOT}/test"
poweroff -f
_EOF_

chmod +x ${INIT}

sudo taskset -c 5-8 ${QEMU} \
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

run_in_vm
