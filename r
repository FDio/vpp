#!/bin/bash

echo "DEBUG: Running with ARG1='$1'"

# Check if we are running inside the guest
if [ "$1" = "--guest-init" ]; then
    echo "Running inside QEMU..."

    # Mount essential filesystems
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    if ! mountpoint -q /dev; then
        mount -t devtmpfs devtmpfs /dev
    fi
    mkdir -p /dev/pts
    mount -t devpts devpts /dev/pts
    mkdir -p /dev/shm
    mount -t tmpfs tmpfs /dev/shm
    mkdir -p /dev/hugepages
    mount -t hugetlbfs hugetlbfs /dev/hugepages

    # Fix PATH to include common locations
    export PATH=/usr/bin:/bin:/usr/sbin:/sbin:$PATH

    # Navigate to project directory
    cd /home/dmarion/vpp2

    # Find the virtio-net-pci device (Vendor 0x1af4, Device 0x1041)
    PCI_ADDR=$(grep -l "0x1041" /sys/bus/pci/devices/*/device | head -n 1 | awk -F/ '{print $6}')

    if [ -n "$PCI_ADDR" ]; then
        echo "Found virtio-net device at $PCI_ADDR"
        echo "Binding $PCI_ADDR to vfio-pci..."
        # Unbind from current driver if any
        if [ -e "/sys/bus/pci/devices/$PCI_ADDR/driver/unbind" ]; then
            echo "$PCI_ADDR" > "/sys/bus/pci/devices/$PCI_ADDR/driver/unbind"
        fi
        # Get vendor/device ID
        VENDOR=$(cat "/sys/bus/pci/devices/$PCI_ADDR/vendor")
        DEVICE=$(cat "/sys/bus/pci/devices/$PCI_ADDR/device")
        # Add ID to vfio-pci and bind
        echo "$VENDOR $DEVICE" > /sys/bus/pci/drivers/vfio-pci/new_id
        echo "$PCI_ADDR" > /sys/bus/pci/drivers/vfio-pci/bind || dmesg | tail -n 5
    fi

    echo "Guest environment ready. Starting interactive shell..."

    # Use PROMPT_COMMAND to set alias without creating files
    export PROMPT_COMMAND="alias r='bin/vpp -c startup.conf'; unset PROMPT_COMMAND"

    # Try to get a proper TTY
    if [ -x /usr/bin/setsid ]; then
        exec setsid /bin/bash -i
    else
        exec /bin/bash -i
    fi
    exit 0
fi

# --- Host side logic below ---

# Use the newly built monolithic kernel
KERNEL="./linux/linux-6.18/arch/x86/boot/bzImage"

if [ ! -f "$KERNEL" ]; then
    echo "Kernel not found: $KERNEL"
    exit 1
fi

echo "Using kernel: $KERNEL"

# We pass this script itself as the init process.
# Since we mount host / as guest /, this script is available at the same path.
INIT_SCRIPT=$(realpath "$0")

sudo qemu-system-x86_64 \
  -enable-kvm \
  -m 2G \
  -smp 4 \
  -machine q35,kernel-irqchip=split \
  -cpu host \
  -device intel-iommu,intremap=on \
  -display none \
  -kernel "$KERNEL" \
  -append "console=ttyS0 reboot=k panic=1 root=host0 rootfstype=9p rootflags=trans=virtio,version=9p2000.L rw intel_iommu=on iommu=pt init=/bin/bash -- -c \"$INIT_SCRIPT --guest-init\"" \
  -fsdev local,id=fsdev0,path=/,security_model=none,multidevs=remap \
  -device virtio-9p-pci,fsdev=fsdev0,mount_tag=host0 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off,iommu_platform=on \
  -serial mon:stdio
