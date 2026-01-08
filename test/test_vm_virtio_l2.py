#!/usr/bin/env python3

#
# Copyright 2026 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Virtio interfaces L2 xconnect test with QEMU guest"""

import unittest
import subprocess
import time
import os
from framework import VppTestCase
from asfframework import VppTestRunner, tag_fixme_debian11
from config import config
from vpp_qemu_utils import (
    create_namespace,
    delete_all_namespaces,
)
from vpp_iperf import start_iperf, stop_iperf


@unittest.skip(
    "Manual test only - requires QEMU, network namespaces, and root privileges"
)
@unittest.skipUnless(config.extended, "part of extended tests")
@tag_fixme_debian11
class TestVirtioQemuL2(VppTestCase):
    """Virtio L2 xconnect test with VPP in QEMU guest.

    Test topology:
    Host NS1 (iperf client) <-> tap1 <-> QEMU guest (VPP: virtio0 xconnect virtio1) <-> tap2 <-> Host NS2 (iperf server)

    The guest uses the host's filesystem via 9p (no separate disk image needed).
    """

    @classmethod
    def setUpClass(cls):
        super(TestVirtioQemuL2, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVirtioQemuL2, cls).tearDownClass()

    def setUp(self):
        super(TestVirtioQemuL2, self).setUp()
        self.qemu_process = None
        self.iperf_cmd = None
        self.client_namespace = "virtio_client_ns"
        self.server_namespace = "virtio_server_ns"
        self.test_dir = f"{config.tmp_dir}/vpp-unittest-virtio"
        self.ns_history_file = f"{self.test_dir}/history_ns.txt"
        self.created_interfaces = []

        # Create test directory
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        # Stop iperf
        if self.iperf_cmd:
            try:
                stop_iperf(self.iperf_cmd, self.logger)
            except:
                pass

        # Close QEMU log file
        if hasattr(self, "qemu_log"):
            try:
                self.qemu_log.close()
            except:
                pass

        # Kill QEMU if running
        if self.qemu_process:
            try:
                self.qemu_process.terminate()
                self.qemu_process.wait(timeout=5)
            except:
                try:
                    self.qemu_process.kill()
                    self.qemu_process.wait(timeout=2)
                except:
                    pass

        # Cleanup namespaces
        delete_all_namespaces(self.ns_history_file)

        # Cleanup interfaces in root namespace
        for iface in self.created_interfaces:
            try:
                result = subprocess.run(
                    ["ip", "link", "show", iface], capture_output=True, timeout=2
                )
                if result.returncode == 0:
                    subprocess.run(
                        ["ip", "link", "del", iface], capture_output=True, timeout=5
                    )
            except:
                pass

        super(TestVirtioQemuL2, self).tearDown()

    def create_tap(self, tap_name):
        """Create a TAP interface in root namespace."""
        try:
            subprocess.run(
                ["ip", "tuntap", "add", "name", tap_name, "mode", "tap"],
                check=True,
                capture_output=True,
            )
            self.created_interfaces.append(tap_name)
            subprocess.run(["ip", "link", "set", tap_name, "up"], check=True)
            self.logger.info(f"Created TAP {tap_name}")
            return tap_name
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to create tap: {e}")
            raise

    def move_tap_to_namespace(self, tap_name, ns_name, ip_addr):
        """Move TAP to namespace and configure it."""
        try:
            subprocess.run(
                ["ip", "link", "set", tap_name, "netns", ns_name], check=True
            )
            subprocess.run(
                ["ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"],
                check=True,
            )
            subprocess.run(
                ["ip", "netns", "exec", ns_name, "ip", "link", "set", tap_name, "up"],
                check=True,
            )
            subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    ns_name,
                    "ip",
                    "addr",
                    "add",
                    ip_addr,
                    "dev",
                    tap_name,
                ],
                check=True,
            )
            self.logger.info(f"Moved {tap_name} to {ns_name} with IP {ip_addr}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to move tap: {e}")
            raise

    def create_vpp_init_script(self):
        """Create init script for VPP in guest (uses host filesystem via 9p)."""

        init_script = f"{self.test_dir}/vpp_init.sh"

        # Get VPP binary - it will be available in guest via 9p mount
        ws_root = os.environ.get(
            "WS_ROOT", os.path.dirname(os.path.dirname(config.vpp))
        )
        vpp_bin = f"{ws_root}/build-root/install-vpp-native/vpp/bin/vpp"

        if not os.path.exists(vpp_bin):
            vpp_bin = f"{ws_root}/build-root/install-vpp-native/vpp/bin/vpp"

        if not os.path.exists(vpp_bin):
            raise Exception(f"VPP binary not found. Build VPP first: make build")

        # Get vppctl binary path
        vppctl_bin = vpp_bin.replace("/bin/vpp", "/bin/vppctl")

        script_content = f"""#!/bin/bash
set -ex

# Basic mounts
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true

# Mount VPP workspace via 9p
mkdir -p /vpp
mount -t 9p -o trans=virtio,version=9p2000.L vpp9p /vpp || true

# Load modules for virtio native plugin
modprobe vfio-pci || modprobe uio_pci_generic || modprobe igb_uio || true
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true

# Bind PCI devices to vfio-pci for native virtio driver
echo "Binding PCI devices to vfio-pci..."
echo vfio-pci > /sys/bus/pci/devices/0000:00:0a.0/driver_override || true
echo vfio-pci > /sys/bus/pci/devices/0000:00:0b.0/driver_override || true
echo 0000:00:0a.0 > /sys/bus/pci/drivers/virtio-pci/unbind 2>/dev/null || true
echo 0000:00:0b.0 > /sys/bus/pci/drivers/virtio-pci/unbind 2>/dev/null || true
echo 0000:00:0a.0 > /sys/bus/pci/drivers_probe || true
echo 0000:00:0b.0 > /sys/bus/pci/drivers_probe || true

# Create hugepages directory (VPP needs this even if not using hugepages)
mkdir -p /dev/hugepages
mount -t hugetlbfs nodev /dev/hugepages || true

# Mount /dev/shm for VPP's shared memory
mkdir -p /dev/shm
mount -t tmpfs tmpfs /dev/shm || true

sleep 2

# Create VPP config
cat > /tmp/vpp.conf << 'EOFVPP'
unix {{
  nodaemon
  log /tmp/vpp.log
  full-coredump
  cli-listen /tmp/vpp_cli.sock
}}

cpu {{
  main-core 0
}}

physmem {{
  max-size 256m
}}

buffers {{
  buffers-per-numa 16384
}}

plugins {{
  plugin dpdk_plugin.so {{ disable }}
}}
EOFVPP

# Start VPP (use the one from host via 9p)
{vpp_bin} -c /tmp/vpp.conf 2>&1 &
VPP_PID=$!

sleep 5

# Check if VPP is running
if ! kill -0 $VPP_PID 2>/dev/null; then
    echo "ERROR: VPP process ($VPP_PID) is not running!"
    ps aux | grep vpp || true
    exit 1
fi
echo "VPP is running (PID: $VPP_PID)"

# Wait for VPP CLI socket to be ready
SOCKET_WAIT=0
while [ ! -S /tmp/vpp_cli.sock ] && [ $SOCKET_WAIT -lt 30 ]; do
    sleep 1
    SOCKET_WAIT=$(($SOCKET_WAIT + 1))
    echo "Waiting for VPP CLI socket... ($SOCKET_WAIT/30)"
done

if [ ! -S /tmp/vpp_cli.sock ]; then
    echo "ERROR: VPP CLI socket not created after 30 seconds!"
    ls -la /tmp/ | grep vpp || true
    exit 1
fi
echo "VPP CLI socket is ready"

# Create virtio interfaces with native plugin (DPDK disabled)
{vppctl_bin} -s /tmp/vpp_cli.sock create interface virtio 0000:00:0a.0
{vppctl_bin} -s /tmp/vpp_cli.sock create interface virtio 0000:00:0b.0

# Configure L2 xconnect
{vppctl_bin} -s /tmp/vpp_cli.sock set interface state virtio-0/0/a/0 up
{vppctl_bin} -s /tmp/vpp_cli.sock set interface state virtio-0/0/b/0 up
{vppctl_bin} -s /tmp/vpp_cli.sock set interface l2 xconnect virtio-0/0/a/0 virtio-0/0/b/0
{vppctl_bin} -s /tmp/vpp_cli.sock set interface l2 xconnect virtio-0/0/b/0 virtio-0/0/a/0

# Keep init process alive by waiting for VPP (this is init, it must not exit)
wait $VPP_PID
"""

        with open(init_script, "w") as f:
            f.write(script_content)
        os.chmod(init_script, 0o755)

        return init_script

    def launch_qemu(self, tap1, tap2, kernel, initrd):
        """Launch QEMU with host filesystem via 9p."""

        init_script = self.create_vpp_init_script()
        ws_root = os.environ.get(
            "WS_ROOT", os.path.dirname(os.path.dirname(config.vpp))
        )

        qemu_cmd = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-cpu",
            "host",
            "-smp",
            "2",
            "-m",
            "2G",
            "-nographic",
            "-kernel",
            kernel,
            "-initrd",
            initrd,
            # Mount host root filesystem via 9p
            "-fsdev",
            "local,id=root9p,path=/,security_model=none,multidevs=remap",
            "-device",
            "virtio-9p-pci,fsdev=root9p,mount_tag=fsRoot",
            # Mount VPP workspace
            "-virtfs",
            f"local,path={ws_root},mount_tag=vpp9p,security_model=none,id=vpp9p,multidevs=remap",
            # Mount /tmp
            "-virtfs",
            f"local,path=/tmp,mount_tag=tmp9p,security_model=passthrough,id=tmp9p,multidevs=remap",
            # Virtio network devices
            "-netdev",
            f"tap,id=net0,ifname={tap1},script=no,downscript=no,vhost=on",
            "-device",
            "virtio-net-pci,netdev=net0,mac=52:54:00:00:00:01,addr=0xa",
            "-netdev",
            f"tap,id=net1,ifname={tap2},script=no,downscript=no,vhost=on",
            "-device",
            "virtio-net-pci,netdev=net1,mac=52:54:00:00:00:02,addr=0xb",
            # Kernel command line
            "-append",
            f"ro root=fsRoot rootfstype=9p rootflags=trans=virtio,cache=mmap console=ttyS0 init={init_script}",
        ]

        self.logger.info(f"Launching QEMU...\n{' '.join(qemu_cmd)}")

        # Create log file for QEMU guest output
        qemu_log_file = f"{self.test_dir}/qemu_guest.log"

        try:
            qemu_log = open(qemu_log_file, "w", buffering=1)
            self.qemu_log_file = qemu_log_file
            self.qemu_log = qemu_log

            self.qemu_process = subprocess.Popen(
                qemu_cmd,
                stdout=qemu_log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True,
            )
            self.logger.info(f"QEMU PID: {self.qemu_process.pid}")
            return self.qemu_process
        except Exception as e:
            self.logger.error(f"Failed to launch QEMU: {e}")
            raise

    @unittest.skipIf(config.skip_netns_tests, "netns not available or disabled")
    @unittest.skipUnless(
        os.environ.get("KERNEL_IMAGE") and os.environ.get("INITRD_IMAGE"),
        "Requires KERNEL_IMAGE and INITRD_IMAGE environment variables. "
        "See test/README_virtio_test.md for setup instructions.",
    )
    def test_virtio_l2_xconnect_ipv4(self):
        """Test virtio L2 xconnect with VPP in QEMU guest.

        Set these environment variables before running:
          export KERNEL_IMAGE=/boot/vmlinuz-25.2.0
          export INITRD_IMAGE=/boot/initrd.img-25.2.0

        Then run: sudo -E make test TEST=test_vm_virtio_l2
        """

        kernel = os.environ.get("KERNEL_IMAGE", f"/boot/vmlinuz-{os.uname().release}")
        initrd = os.environ.get(
            "INITRD_IMAGE", f"/boot/initrd.img-{os.uname().release}"
        )

        if not os.path.exists(kernel):
            self.skipTest(f"Kernel not found: {kernel}")
        if not os.path.exists(initrd):
            # Try custom initrd with 9p modules
            custom_initrd = "/tmp/vpp-test-initrd.img"
            if os.path.exists(custom_initrd):
                self.logger.info(f"Using custom initrd with 9p: {custom_initrd}")
                initrd = custom_initrd
            else:
                self.skipTest(f"Initrd not found: {initrd}")

        self.logger.info(f"Using kernel: {kernel}")
        self.logger.info(f"Using initrd: {initrd}")

        # Create namespaces
        self.logger.info("Creating namespaces")
        delete_all_namespaces(self.ns_history_file)
        create_namespace(
            self.ns_history_file, ns=[self.client_namespace, self.server_namespace]
        )

        # Create TAPs
        tap1 = "tap_virtio_0"
        tap2 = "tap_virtio_1"
        self.create_tap(tap1)
        self.create_tap(tap2)

        # Launch QEMU
        self.logger.info("Launching QEMU with VPP")
        self.launch_qemu(tap1, tap2, kernel, initrd)
        time.sleep(2)

        # Move TAPs to namespaces
        self.move_tap_to_namespace(tap1, self.client_namespace, "10.10.1.1/24")
        self.move_tap_to_namespace(tap2, self.server_namespace, "10.10.1.2/24")

        # Wait for VPP to configure L2 xconnect
        self.logger.info("Waiting for VPP to configure L2 xconnect...")
        time.sleep(15)

        # Check QEMU is still running
        if self.qemu_process.poll() is not None:
            self.logger.error("QEMU exited prematurely!")
            stdout, _ = self.qemu_process.communicate(timeout=1)
            self.logger.error(f"QEMU output:\n{stdout}")
            self.fail("QEMU exited")

        # Start iperf
        self.logger.info("Starting iperf server")
        self.iperf_cmd = start_iperf(
            ip_version=4,
            client_ns=self.client_namespace,
            server_ns=self.server_namespace,
            server_only=True,
            server_args="-p 5201",
            logger=self.logger,
        )

        time.sleep(2)

        self.logger.info("Starting iperf client")
        result = start_iperf(
            ip_version=4,
            client_ns=self.client_namespace,
            server_ns=self.server_namespace,
            server_ipv4_address="10.10.1.2",
            client_args="-p 5201 -t 5",
            client_only=True,
            duration=5,
            logger=self.logger,
        )

        self.assertTrue(result, "iPerf failed - no traffic through QEMU/VPP")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
