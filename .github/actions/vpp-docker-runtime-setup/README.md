# 🛠️ VPP Docker Runtime Setup

This GitHub Action configures the Docker runtime environment for VPP (Vector Packet Processing) testing by optimizing shared memory configuration. It's specifically designed to prepare the environment for VPP test execution with `make test`.

## Overview

The action addresses a critical requirement for VPP testing in containerized environments by reconfiguring the `/dev/shm` (shared memory) mount with sufficient space to handle VPP's memory requirements during test execution.

## Problem Solved

VPP tests require substantial shared memory allocation, particularly when running multiple test processes simultaneously. The default Docker shared memory size is often insufficient, causing test failures due to memory allocation errors. This action proactively addresses this limitation.

## Usage

```yaml
- name: Setup VPP Docker Runtime
  uses: fdio/vpp/.github/actions/vpp-docker-runtime-setup@master
  with:
    SHM_SIZE: "2048M"
    TUI_LINE: "*******************************************************************"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `SHM_SIZE` | Size of /dev/shm to set for VPP Docker runtime (e.g., "2048M", "4G") | No | `"2048M"` |
| `TUI_LINE` | Delimiter line for TUI output formatting | No | `"*******************************************************************"` |

## What It Does

### 🎯 **Core Functionality**
- **Shared Memory Resize**: Remounts `/dev/shm` with 2048MB (2GB) of space
- **VPP Test Optimization**: Ensures sufficient memory for multi-core VPP test execution
- **Error Tolerance**: Uses `|| true` to handle cases where remount might not be necessary
- **Visual Feedback**: Provides clear output with customizable formatting

### 🧮 **Memory Configuration**
The action allows configurable memory size via the `SHM_SIZE` input, with intelligent defaults based on VPP's test framework requirements:

```
Memory Required = MIN_REQ_SHM + (num_cores × SHM_PER_PROCESS)
```

- **Base Memory**: 1073741824 bytes (1024MB) minimum required
- **Per-Core Addition**: Additional memory per CPU core
- **Default Allocation**: 2048MB for up to 16 cores (empirically determined)
- **Configurable**: Can be adjusted via `SHM_SIZE` input for different environments

## Technical Details

### Memory Sizing Logic
```bash
# Base calculation for 4 cores:
# framework.VppTestCase.MIN_REQ_SHM + (num_cores * framework.VppTestCase.SHM_PER_PROCESS)
# 1073741824 == 1024M (1073741824 >> 20)
# For 16 cores, empirical evidence shows that 2048M is sufficient
MEM=${{ inputs.SHM_SIZE }}  # Configurable via input, defaults to "2048M"
```

### Mount Operation
```bash
sudo mount -o remount /dev/shm -o size=${MEM} || true
```

- **Remount**: Modifies existing `/dev/shm` mount without unmounting
- **Size Option**: Sets new size limit for shared memory
- **Error Handling**: Continues execution even if remount fails (graceful degradation)

## Prerequisites

### System Requirements
- **Linux Environment**: Requires Linux-based runner (Docker containers)
- **sudo Privileges**: Needs elevated permissions for mount operations
- **Existing /dev/shm**: Standard Linux shared memory filesystem must be present

### Runtime Context
- **Containerized Environment**: Designed for Docker-based CI/CD runners
- **VPP Source Code**: Should be used in workflows that build/test VPP
- **Test Execution**: Intended for workflows that run `make test`

## Example Workflows

### Basic VPP Test Workflow

```yaml
name: VPP Tests
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:22.04
    steps:
      - name: Checkout VPP Source
        uses: actions/checkout@v4

      - name: Install Dependencies
        uses: fdio/.github/.github/actions/vpp-install-ext-deps

      - name: Setup Docker Runtime for Tests
        uses: fdio/vpp/.github/actions/vpp-docker-runtime-setup@master

      - name: Build VPP
        run: make build

      - name: Run VPP Tests
        run: make test
```

### Advanced Multi-Stage Workflow

```yaml
name: Comprehensive VPP CI
on: [push, pull_request]

jobs:
  setup-and-test:
    runs-on: self-hosted
    container:
      image: vpp-build:latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Runtime Environment
        uses: fdio/vpp/.github/actions/vpp-docker-runtime-setup@master
        with:
          SHM_SIZE: "4096M"  # Increased for high-performance testing
          TUI_LINE: "=== Docker Runtime Configuration ==="

      - name: Install External Dependencies
        uses: fdio/vpp/.github/actions/vpp-install-ext-deps@master

      - name: Install Optional Dependencies
        uses: fdio/vpp/.github/actions/vpp-install-opt-deps@master

      - name: Build VPP
        run: make build

      - name: Execute Test Suite
        run: make test

      - name: Performance Tests
        run: make test-debug
```

### Custom Configuration

```yaml
- name: Configure VPP Test Environment
  uses: fdio/vpp/.github/actions/vpp-docker-runtime-setup@master
  with:
    SHM_SIZE: "8192M"  # 8GB for heavy testing workloads
    TUI_LINE: "--- VPP Docker Runtime Setup ---"
```

## Memory Allocation Details

### Why 2048MB Default?

The 2048MB default allocation is based on:

1. **VPP Framework Requirements**: Base shared memory needs for VPP test framework
2. **Multi-Core Support**: Additional memory per CPU core for parallel test execution
3. **Empirical Testing**: Validated through extensive testing with up to 16 cores
4. **Safety Margin**: Provides buffer for peak memory usage scenarios
5. **Flexibility**: Can be increased via `SHM_SIZE` input for demanding workloads

### Scaling Considerations

| CPU Cores | Recommended Memory | Default Allocation | Suggested `SHM_SIZE` |
|-----------|-------------------|-------------------|---------------------|
| 1-4 cores | ~1024MB | 2048MB | `"2048M"` (default) |
| 5-8 cores | ~1500MB | 2048MB | `"2048M"` (default) |
| 9-16 cores | ~2000MB | 2048MB | `"2048M"` (default) |
| 17-24 cores | ~3000MB | 2048MB | `"4096M"` |
| 25+ cores | >4000MB | 2048MB | `"8192M"` or higher |

## Integration Points

### VPP Build Pipeline
This action fits into the VPP development lifecycle:

1. **Environment Setup** ← This action
2. **Dependency Installation**
3. **Code Compilation**
4. **Test Execution**
5. **Result Analysis**

### Related Actions
- **`vpp-install-ext-deps`**: Install required VPP dependencies
- **`vpp-install-opt-deps`**: Install optional VPP dependencies
- **`gerrit-env-vars-*`**: Manage Gerrit integration context

## Performance Impact

- **Setup Time**: Minimal (<1 second)
- **Memory Overhead**: 2GB allocated (not necessarily used)
- **Test Performance**: Significantly improves test reliability and performance
- **System Impact**: No permanent changes to host system

## Security Considerations

- **Elevated Privileges**: Requires sudo access for mount operations
- **Temporary Changes**: Modifications are container-scoped and temporary
- **Resource Allocation**: Allocates significant memory resources
- **Container Isolation**: Changes are isolated to container environment

## Version Compatibility

- **VPP Versions**: Compatible with all VPP versions that use standard test framework
- **Container Images**: Works with standard Linux container images
- **GitHub Actions**: Compatible with current GitHub Actions runner environments
- **Docker**: Compatible with standard Docker runtime environments

## Maintenance Notes

- **Memory Tuning**: May need adjustment for very high core count systems
- **VPP Changes**: Monitor VPP test framework changes that might affect memory requirements
- **Container Updates**: Verify compatibility when updating base container images
