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

# Init RAM disk image to boot the QEMU VM
INITRD=${INITRD:-}

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

# Download the Generic Linux Kernel, if needed
if [[ -z "${2:-}" ]] || [[ ! -f "${2:-}" ]]; then
    if [[ $os_PACKAGE == "deb" ]]; then
        PWD=$(pwd)
        cd ${TEST_DATA_DIR}
        PKG="linux-image-$(uname -r)"
        echo "Getting the Linux Kernel image..${PKG}"
        apt-get download ${PKG}
        dpkg --fsys-tarfile ${PKG}_*.deb | tar xvf - ./boot
        KERNEL_BIN=$(ls ${TEST_DATA_DIR}/boot/vmlinuz-*-generic)
        cd ${PWD}
    else
        echo "ERROR: Kernel Image selection is required for RPM pkgs."
        exit 1
    fi
else
    KERNEL_BIN=${2:-}
fi

## Create initrd with 9p drivers, if ${INITRD} is null
DRIVERS_9P=""
if [[ -z "${INITRD}" ]] && [[ ! -d "/etc/initramfs-tools" ]]; then
   echo "To boot the QEMU VM, an initial RAM disk with 9p drivers is needed"
   echo "Install the initramfs-tools package or set env var INITRD to the RAM disk path"
   exit 1
elif [[ -z "${INITRD}" ]]; then
   if [[ -f "/etc/initramfs-tools/modules" ]]; then
       DRIVERS_9P=$(grep 9p /etc/initramfs-tools/modules | awk '{print $1}' | cut -d$'\n' -f1)
   fi
   if [[ -z "${DRIVERS_9P}" ]]; then
       echo "You'll need to update the file /etc/initramfs-tools/modules with the below 9p drivers"
       echo "9p >> /etc/initramfs-tools/modules"
       echo "9pnet >> /etc/initramfs-tools/modules"
       echo "9pnet_virtio >> /etc/initramfs-tools/modules"
       exit 1
   fi
   # Generate the initramfs image, if the we haven't generated one yet
   if ! ls ${TEST_DATA_DIR}/boot/initrd.img-*-generic &> /dev/null; then
       echo "Generating a bootable initramfs image in ${TEST_DATA_DIR}/boot/"
       update-initramfs -c -k $(uname -r) -b ${TEST_DATA_DIR}/boot >/dev/null 2>&1
       echo "Generated the INITRD image"
   fi
   INITRD=$(ls ${TEST_DATA_DIR}/boot/initrd.img-*-generic)
fi
echo "Using INITRD=${TEST_DATA_DIR}/boot/${INITRD} for booting the QEMU VM"


## Install iperf into ${TEST_DATA_DIR}
IPERF=${TEST_DATA_DIR}/usr/bin/iperf
if [[ ! -x ${IPERF} ]] && [[ $os_PACKAGE == "deb" ]]; then
    echo "Installing iperf: ${IPERF}"
    PWD=$(pwd)
    cd ${TEST_DATA_DIR}
    IPRF_PKG="iperf_2.0.5+dfsg1-2_amd64.deb"
    wget https://iperf.fr/download/ubuntu/${IPRF_PKG}
    dpkg --fsys-tarfile ${IPRF_PKG} | tar xvf -
    if [[ -x ${IPERF} ]]; then
       echo "${IPERF} installed successfully"
    else
       echo "ERROR: iperf executable ${IPERF} installation failed"
       exit 1
    fi
    cd ${PWD}
elif [[ ! -x ${IPERF} ]] && [[ $os_PACKAGE != "deb" ]]; then
    echo "ERROR: install iperf: ${IPERF} before running QEMU tests"
    exit 1
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

# Boot QEMU VM and run the test
function run_in_vm {
    INIT=$(mktemp -p ${TEST_DATA_DIR})
    cat > ${INIT} << _EOF_
#!/bin/bash
mkdir -p /dev/shm
mount -t tmpfs -o rw,nosuid,nodev tmpfs /dev/shm
mount -t devpts -o noexec,nosuid,gid=5,mode=0620 devpts /dev/pts || true
mount -t tmpfs -o "noexec,nosuid,size=10%,mode=0755" tmpfs /run
mount -t 9p /dev/vpp9p ${WS_ROOT}
mount -t 9p tmp9p /tmp
modprobe -a vhost_net
${VENV_PATH}/bin/python3 ${WS_ROOT}/test/run_tests.py --filter=${TEST} --jobs=${TEST_JOBS} \
--failed-dir=${FAILED_DIR} --venv-dir=${VENV_PATH} --vpp-ws-dir=${WS_ROOT} --extended \
--vpp-tag=vpp_debug --cache-vpp-output
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
                 -initrd ${INITRD} \
                 -fsdev local,id=root9p,path=/,security_model=none,multidevs=remap \
                 -device virtio-9p-pci,fsdev=root9p,mount_tag=fsRoot \
                 -virtfs local,path=${WS_ROOT},mount_tag=/dev/vpp9p,security_model=none,id=vpp9p,multidevs=remap \
                 -virtfs local,path=/tmp,mount_tag=tmp9p,security_model=passthrough,id=tmp9p,multidevs=remap \
                 -netdev tap,id=net0,vhost=on \
                 -device virtio-net-pci,netdev=net0,mac=52:54:00:de:64:01 \
                 -nographic \
                 -append "ro root=fsRoot rootfstype=9p rootflags=trans=virtio,cache=mmap console=ttyS0 hugepages=${HUGEPAGES} init=${INIT}"
    }

run_in_vm
