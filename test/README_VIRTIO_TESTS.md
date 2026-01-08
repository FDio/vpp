# VPP Virtio PCI Interface Tests

This document describes the virtio PCI interface tests for VPP running in a QEMU VM.

## Overview

The virtio tests verify VPP's ability to create and use virtio PCI interfaces directly (not tap interfaces). VPP runs inside a QEMU VM and creates virtio interfaces via PCI bus addresses.

## Architecture

```
┌─────────────────────────────────────────┐
│          Host (Linux)                    │
│  ┌─────────────┐      ┌─────────────┐  │
│  │ Namespace   │      │ Namespace   │  │
│  │ (iPerf      │      │ (iPerf      │  │
│  │  client)    │      │  server)    │  │
│  │             │      │             │  │
│  │   vtap0     │      │   vtap1     │  │
│  └──────┬──────┘      └──────┬──────┘  │
│         │                    │          │
│  ┌──────▼────────────────────▼──────┐  │
│  │         QEMU VM                  │  │
│  │  ┌───────────────────────────┐  │  │
│  │  │       VPP                 │  │  │
│  │  │                           │  │  │
│  │  │  virtio0     virtio1      │  │  │
│  │  │  (PCI)        (PCI)       │  │  │
│  │  │  0000:00:06.0  0000:00:07.0│ │  │
│  │  │     │            │         │  │  │
│  │  │     └────L2/L3───┘         │  │  │
│  │  └───────────────────────────┘  │  │
│  │         │            │           │  │
│  │    virtio-net    virtio-net     │  │
│  │    backend       backend        │  │
│  └──────┬────────────┬─────────────┘  │
│         │            │                 │
│       vtap0        vtap1               │
└─────────────────────────────────────────┘
```

## How It Works

1. **QEMU Setup**:
   - Creates 2 virtio-net-pci devices at PCI addresses 0000:00:06.0 and 0000:00:07.0
   - Each device has a tap backend (vtap0, vtap1) on the host

2. **Test Framework**:
   - Moves vtap0 to iPerf client namespace
   - Moves vtap1 to iPerf server namespace
   - Configures IP addresses on tap interfaces

3. **VPP**:
   - Creates virtio PCI interfaces using `virtio_pci_create_v2` API
   - Bridges or routes traffic between virtio0 and virtio1
   - Traffic flows: iPerf client → vtap0 → virtio0 → VPP → virtio1 → vtap1 → iPerf server

## Test Files

- `test_vm_virtio_l2.py` - L2 bridge tests (test ID 30, 31)
- `test_vm_virtio_l3.py` - L3 routing tests (test ID 32)
- `vm_test_config.py` - Test configurations
- `vm_vpp_interfaces.py` - Interface creation logic
- `scripts/run_vpp_in_vm.sh` - QEMU VM launch script

## Running Tests

### Prerequisites

- QEMU/KVM installed
- Root/sudo access for network namespace operations
- VPP compiled with debug or release build

### Run L2 Tests

```bash
# From VPP root directory
make test TEST=test_vm_virtio_l2
```

### Run L3 Tests

```bash
make test TEST=test_vm_virtio_l3
```

### Run Specific Test ID

```bash
# Test ID 30: Basic L2 virtio without GSO
make test TEST=test_vm_virtio_l2

# Test ID 31: L2 virtio with GSO enabled
# Edit test_vm_virtio_l2.py and change tests_to_run = "31"
```

## Test Configurations

From `vm_test_config.py`:

- **Test 30**: virtio L2 bridge, no GSO/GRO
- **Test 31**: virtio L2 bridge, GSO enabled
- **Test 32**: virtio L3 routing, no GSO/GRO

## Implementation Details

### PCI Addresses

The PCI addresses are hardcoded in `vm_test_config.py`:
- Client virtio: `0000:00:06.0` (PCI slot 6)
- Server virtio: `0000:00:07.0` (PCI slot 7)

These correspond to QEMU's `-device virtio-net-pci,addr=0x6` and `addr=0x7`.

### VPP API

VPP creates virtio interfaces using `virtio_pci_create_v2`:
```python
api_args = {
    "pci_addr": {
        "domain": 0,
        "bus": 0,
        "slot": 6,  # or 7
        "function": 0,
    },
    "use_random_mac": True,
    "virtio_flags": VIRTIO_API_FLAG_GSO,  # if GSO enabled
    "features": 0,
}
result = vapi.virtio_pci_create_v2(**api_args)
```

### Backend Tap Configuration

QEMU creates tap interfaces with:
```bash
-netdev tap,id=vtap0,ifname=vtap0,script=no,downscript=no
-device virtio-net-pci,netdev=vtap0,mac=52:54:00:de:64:02,addr=0x6
```

The test framework then:
1. Moves tap to namespace: `ip link set vtap0 netns <namespace>`
2. Assigns IP address: `ip addr add 10.0.0.101/24 dev vtap0`
3. Brings interface up: `ip link set vtap0 up`

## Troubleshooting

### VPP Cannot Find PCI Device

**Symptom**: Error creating virtio interface, PCI device not found

**Solution**:
- Verify QEMU command includes virtio-net-pci devices
- Check PCI addresses match: `lspci` inside VM
- Ensure `addr=0x6` and `addr=0x7` in QEMU command

### Tap Interface Not Found

**Symptom**: `ip link set vtap0 netns` fails

**Solution**:
- Verify QEMU created tap interfaces
- Check `ip link show` on host before moving to namespace
- Ensure script creates tap interfaces before QEMU launch

### No Traffic Between Interfaces

**Symptom**: iPerf shows 0 bandwidth

**Solution**:
- Check VPP interface status: `show interface`
- Verify L2/L3 configuration in VPP
- Check namespace routing: `ip netns exec <ns> ip route`
- Verify GSO/GRO settings match test configuration

## Future Enhancements

- Add tests with different MTU sizes
- Test packed ring support (VIRTIO_API_FLAG_PACKED)
- Test RSS support (VIRTIO_API_FLAG_RSS)
- Test with multiple queues
- Add performance benchmarks

## References

- VPP virtio driver: `src/vnet/devices/virtio/`
- VPP virtio API: `src/vnet/devices/virtio/virtio.api`
- QEMU virtio documentation: https://wiki.qemu.org/Documentation/Networking
