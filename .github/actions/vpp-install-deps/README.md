# 🛠️ VPP Install Dependencies Action

This GitHub composite action installs the necessary build and development dependencies required for VPP (Vector Packet Processing) compilation and development. It provides a standardized way to set up the VPP build environment across different CI/CD workflows.

## Description

The action executes the VPP project's dependency installation process using the standard `make install-deps` target. This ensures that all required system packages, development tools, and libraries are properly installed before attempting to build VPP.

## Usage

```yaml
- name: Install VPP Dependencies
  uses: fdio/vpp/.github/actions/vpp-install-deps@master
```

With custom formatting:
```yaml
- name: Install VPP Dependencies
  uses: fdio/vpp/.github/actions/vpp-install-deps@master
  with:
    TUI_LINE: "=== Installing VPP Dependencies ==="
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `TUI_LINE` | Delimiter line for terminal UI output formatting | No | `"*******************************************************************"` |

## What It Installs

The action runs `make UNATTENDED=yes install-deps`, which typically installs:

### Build Tools
- **Compilers**: GCC, Clang, build-essential packages
- **Build Systems**: Make, CMake, Ninja
- **Version Control**: Git (if not already present)
- **Package Management**: pkg-config, autotools

### Development Libraries
- **Networking**: libssl-dev, libpcap-dev, libnuma-dev
- **Compression**: zlib1g-dev, liblz4-dev
- **Cryptography**: libcrypto++-dev, libssl-dev
- **System**: libapr1-dev, libconfuse-dev

### Python Dependencies
- **Python 3**: Python 3 interpreter and development headers
- **pip**: Python package installer
- **Virtual Environment**: venv module
- **Development Tools**: python3-dev, python3-setuptools

### Platform-Specific Packages
The exact packages installed depend on the target operating system:
- **Ubuntu/Debian**: Uses `apt-get` package manager
- **CentOS/RHEL/Fedora**: Uses `yum` or `dnf` package manager
- **Other Distributions**: May require manual dependency specification

## Prerequisites

### System Requirements
- **Linux Environment**: Requires Linux-based runner or container
- **Package Manager**: System must have a supported package manager (apt, yum, dnf)
- **sudo Privileges**: Needs elevated permissions for package installation
- **Internet Access**: Requires network connectivity to download packages

### Repository Context
- **VPP Source Code**: Must be run in a workspace containing VPP source code
- **Makefile**: Requires VPP's main Makefile to be present
- **Build Scripts**: Depends on VPP's build system configuration

## Example Workflows

### Basic VPP Build Workflow
```yaml
name: VPP Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout VPP Source
        uses: actions/checkout@v5

      - name: Install VPP Dependencies
        uses: fdio/vpp/.github/actions/vpp-install-deps@master

      - name: Build VPP
        run: make build
```

### Multi-OS Dependency Installation
```yaml
name: VPP Cross-Platform Build
on: [push, pull_request]

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-22.04, ubuntu-24.04]
    runs-on: ${{ matrix.os }}

    steps:
      - name: Checkout Code
        uses: actions/checkout@v5

      - name: Install Dependencies on ${{ matrix.os }}
        uses: fdio/vpp/.github/actions/vpp-install-deps@master
        with:
          TUI_LINE: "--- Installing Dependencies for ${{ matrix.os }} ---"

      - name: Build VPP
        run: make build

      - name: Run Tests
        run: make test
```

### Container-Based Workflow
```yaml
name: VPP Container Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ubuntu:24.04

    steps:
      - name: Update Package Index
        run: apt-get update

      - name: Install Git
        run: apt-get install -y git

      - name: Checkout VPP
        uses: actions/checkout@v5

      - name: Install VPP Dependencies
        uses: fdio/vpp/.github/actions/vpp-install-deps@master

      - name: Build and Test VPP
        run: |
          make build
          make test
```

## Technical Details

### Command Execution
```bash
make UNATTENDED=yes install-deps
```

**Parameters:**
- `UNATTENDED=yes`: Prevents interactive prompts during installation
- `install-deps`: VPP Makefile target for dependency installation

### Error Handling
- **Fail Fast**: Uses `set -euo pipefail` for immediate failure on errors
- **Exit Codes**: Returns non-zero exit code on any installation failure
- **Detailed Output**: Provides verbose output for troubleshooting

### Output Formatting
- **Visual Separators**: Uses configurable delimiter lines for clear output
- **Progress Indication**: Shows installation progress and completion status
- **Error Messages**: Displays clear error context on failures

## Integration Points

### VPP Build Pipeline
This action fits early in the VPP development lifecycle:

1. **Source Checkout**
2. **Dependency Installation** ← This action
3. **External Dependencies** (vpp-install-ext-deps)
4. **Environment Setup**
5. **Code Compilation**
6. **Testing**

### Related Actions
- **`vpp-install-ext-deps`**: Installs external VPP dependencies (DPDK, etc.)
- **`vpp-install-opt-deps`**: Installs optional VPP dependencies
- **`vpp-build`**: Builds VPP after dependencies are installed
- **`vpp-test`**: Runs VPP tests after successful build

## Dependency Categories

### Essential Build Dependencies
- C/C++ compiler toolchain
- Make and build utilities
- Development headers for system libraries

### VPP-Specific Dependencies
- Networking library development packages
- Performance optimization libraries
- Hardware acceleration support libraries

### Development Tools
- Debugging tools (GDB, Valgrind)
- Static analysis tools
- Documentation generation tools

### Python Environment
- Python 3 runtime and development packages
- Package management tools
- Virtual environment support

## Platform Support

### Supported Operating Systems
- **Ubuntu 20.04 LTS** (Focal Fossa)
- **Ubuntu 22.04 LTS** (Jammy Jellyfish)
- **Ubuntu 24.04 LTS** (Noble Numbat)
- **Debian 11** (Bullseye)
- **Debian 12** (Bookworm)
- **CentOS 8** (with limitations)
- **Rocky Linux 8/9**

### Architecture Support
- **x86_64** (AMD64)
- **aarch64** (ARM64)
- Other architectures may work but are not officially tested

## Performance Considerations

### Installation Time
- **First Run**: 5-15 minutes depending on system and network speed
- **Cached Runs**: Significantly faster with package cache
- **Container Images**: Pre-installing dependencies in base images reduces CI time

### Resource Usage
- **Disk Space**: Requires 2-5GB of additional disk space
- **Memory**: Minimal memory overhead during installation
- **Network**: Downloads 500MB-2GB of packages depending on OS

### Optimization Strategies
- **Base Images**: Use container images with pre-installed dependencies
- **Caching**: Leverage GitHub Actions caching for package managers
- **Parallel Installation**: Some package managers support parallel downloads

## Troubleshooting

### Common Issues

#### Package Manager Errors
```
E: Unable to locate package <package-name>
```
**Solution**: Update package index before running the action
```yaml
- name: Update Package Index
  run: sudo apt-get update
```

#### Permission Errors
```
E: Could not open lock file /var/lib/dpkg/lock-frontend
```
**Solution**: Ensure the runner has sudo privileges or run in privileged container

#### Network Issues
```
Temporary failure resolving 'archive.ubuntu.com'
```
**Solution**: Check network connectivity and DNS configuration

#### Disk Space Issues
```
E: You don't have enough free space in /var/cache/apt/archives/
```
**Solution**: Clean package cache or use larger runner disk space

### Debugging Steps

1. **Enable Verbose Output**: Check action logs for detailed error messages
2. **Manual Installation**: Try running `make install-deps` manually to isolate issues
3. **Package Verification**: Verify specific packages can be installed individually
4. **System Requirements**: Ensure runner meets minimum system requirements

### Platform-Specific Issues

#### Ubuntu/Debian
- Ensure `apt-get update` has been run recently
- Check for held packages that might conflict

#### CentOS/RHEL
- Verify EPEL repository is enabled for additional packages
- Check SELinux settings if installation fails

## Security Considerations

### Package Sources
- **Official Repositories**: Installs packages from official OS repositories
- **GPG Verification**: Package managers verify package signatures
- **Trusted Sources**: Only uses well-known, trusted package sources

### Privilege Requirements
- **sudo Access**: Requires elevated privileges for system package installation
- **Container Isolation**: When run in containers, changes are isolated
- **Temporary Changes**: No permanent modifications to host systems

## Version Compatibility

### VPP Versions
- **Latest Master**: Always compatible with current VPP master branch
- **LTS Releases**: Compatible with VPP LTS releases
- **Legacy Support**: May work with older VPP versions with similar dependency requirements

### OS Compatibility Matrix

| OS Version | VPP Master | VPP 23.10 | VPP 23.06 | Status |
|------------|------------|-----------|-----------|---------|
| Ubuntu 24.04 | ✅ | ✅ | ✅ | Fully Supported |
| Ubuntu 22.04 | ✅ | ✅ | ✅ | Fully Supported |
| Ubuntu 20.04 | ✅ | ✅ | ✅ | Fully Supported |
| Debian 12 | ✅ | ✅ | ⚠️ | Mostly Supported |
| Debian 11 | ✅ | ✅ | ✅ | Fully Supported |

## Best Practices

### Workflow Design
1. **Early Installation**: Run dependency installation early in workflow
2. **Caching Strategy**: Implement package caching to reduce installation time
3. **Error Handling**: Include proper error handling and retry logic
4. **Resource Planning**: Account for installation time and disk space requirements

### Container Usage
1. **Base Images**: Consider using pre-built images with dependencies
2. **Multi-stage Builds**: Separate dependency installation from application builds
3. **Layer Optimization**: Minimize Docker layers created during installation

### CI/CD Integration
1. **Parallel Jobs**: Dependencies can be installed in parallel across matrix jobs
2. **Conditional Installation**: Skip installation if dependencies are already present
3. **Artifact Sharing**: Share installed dependencies between workflow jobs when possible

## Maintenance Notes

- **Dependency Updates**: Monitor VPP dependency changes in upstream releases
- **OS Support**: Verify compatibility when new OS versions are released
- **Package Availability**: Check for deprecated packages that may need alternatives
- **Security Updates**: Regularly update base systems to get security fixes

## License

This action is part of the VPP project. See the main repository LICENSE file for details.