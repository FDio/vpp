#!/usr/bin/env bash
# Run VPP in a QEMU VM
# set -o xtrace
set -o nounset

# Arguments:
# $1:- Test Filter
# $2:- Kernel Image
# $3:- Test Data Directory
# $4:- CPU Mask String (e.g. "5,6,7,8")
# $5:- Guest MEM in Gibibytes (e.g. 2G)

if [[ -z "${1:-}" ]]; then
    echo "ERROR: A non-empty test selection is required to run
    tests in a QEMU VM"
    exit 1
fi
TEST=${1:-}
TEST_JOBS=${TEST_JOBS:-1}

# Ensure test dir
TEST_DATA_DIR=${3:-"/tmp/vpp-vm-tests"}
if [[ ! -d ${TEST_DATA_DIR} ]]; then
    mkdir -p ${TEST_DATA_DIR}
fi

# CPU Affinity for taskset
CPU_MASK=${4:-"5,6,7,8"}
IFS=',' read -r -a CPU_MASK_ARRAY <<< ${CPU_MASK}
CPUS=${#CPU_MASK_ARRAY[@]}

# Guest MEM (Default 2G)
MEM=${5:-"2G"}

# Set the QEMU executable for the OS pkg.
os_VENDOR=$(lsb_release -i -s)
if [[ $os_VENDOR =~ (Debian|Ubuntu) ]]; then
    os_PACKAGE="deb"
    QEMU=${QEMU:-"qemu-system-x86_64"}
else
    os_PACKAGE="rpm"
    QEMU=${QEMU:-"qemu-kvm"}
fi

# Exit if the ${QEMU} executable is not available
if ! command -v ${QEMU} &> /dev/null; then
    echo "Error: ${QEMU} is required, but could not be found."
    exit 1
fi

# Download a default Kernel Image for Debian/Ubuntu Pkgs.
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
        echo "ERROR: Kernel Image selection is required for RPM pkgs."
        exit 1
    fi
else
    KERNEL_BIN=${2:-}
fi

FAILED_DIR=${FAILED_DIR:-"/tmp/vpp-failed-unittests/"}
if [[ ! -d ${FAILED_DIR} ]]; then
    mkdir -p ${FAILED_DIR}
fi

HUGEPAGES=${HUGEPAGES:-256}

# Ensure all required Env vars are bound to non-zero values
EnvVarArray=("WS_ROOT=${WS_ROOT:-}"
             "RND_SEED=${RND_SEED:-}"
             "BR=${BR:-}"
             "VENV_PATH=${VENV_PATH:-}"
             "VPP_BUILD_DIR=${VPP_BUILD_DIR:-}"
             "VPP_BIN=${VPP_BIN:-}"
             "VPP_PLUGIN_PATH=${VPP_PLUGIN_PATH:-}"
             "VPP_TEST_PLUGIN_PATH=${VPP_TEST_PLUGIN_PATH:-}"
             "VPP_INSTALL_PATH=${VPP_INSTALL_PATH:-}"
             "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}")

for envVar in ${EnvVarArray[*]}; do
    var_name=$(echo $envVar | cut -d= -f1)
    var_val=$(echo $envVar | cut -d= -f2)
    if [[ -z "$var_val" ]]; then
        echo "ERROR: Env var: $var_name is not set"
        exit 1
    fi
done

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

    sudo taskset -c ${CPU_MASK} ${QEMU} \
                 -nodefaults \
                 -name test_$(basename $INIT) \
                 -chardev stdio,mux=on,id=char0 \
                 -mon chardev=char0,mode=readline,pretty=on \
                 -serial chardev:char0 \
                 -machine pc,accel=kvm,usb=off,mem-merge=off \
                 -cpu host \
                 -smp ${CPUS},sockets=1,cores=${CPUS},threads=1 \
                 -m ${MEM} \
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
