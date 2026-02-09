# 🛠️ VPP Install Optional Dependencies

This GitHub Action installs optional dependencies for VPP (Vector Packet Processing) on self-hosted runners. It provides a streamlined way to set up optional VPP dependencies that enhance functionality but are not strictly required for basic VPP compilation.

## Overview

The action executes the VPP makefile target `install-opt-deps` in unattended mode, installing optional dependencies that can improve VPP's capabilities or development experience. Unlike external dependencies which are required for compilation, these optional dependencies provide additional features and tools.

## Usage

```yaml
- name: Install VPP Optional Dependencies
  uses: fdio/.github/.github/actions/vpp-install-opt-deps
  with:
    TUI_LINE: "*******************************************************************"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `TUI_LINE` | Delimiter line for TUI output formatting | No | `"*******************************************************************"` |

## Features

### 🎯 **Core Functionality**
- **Optional Dependency Installation**: Installs VPP optional dependencies using the official makefile
- **Unattended Mode**: Runs in non-interactive mode suitable for CI/CD environments
- **Error Handling**: Uses strict error handling (`set -euo pipefail`)
- **Formatted Output**: Provides clear visual separation with customizable delimiter lines

### 🔧 **Integration Benefits**
- **Makefile Integration**: Uses the official VPP build system for dependency management
- **CI/CD Optimized**: Designed for automated environments with no user interaction required
- **Consistent Setup**: Ensures optional dependencies are installed consistently across builds
- **Visual Feedback**: Clear output formatting for easy identification in CI logs

## What Gets Installed

The action runs `make UNATTENDED=yes install-opt-deps`, which typically includes:

- **Development Tools**: Additional development and debugging utilities
- **Performance Tools**: Profiling and performance analysis tools
- **Testing Dependencies**: Optional testing frameworks and utilities
- **Documentation Tools**: Tools for generating documentation (if applicable)
- **Enhanced Features**: Dependencies that enable optional VPP features

*Note: The exact dependencies installed depend on the current VPP makefile configuration and may vary between VPP versions.*

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Architecture**: Compatible with VPP-supported architectures
- **Permissions**: `sudo` access may be required for system package installation
- **Build Environment**: VPP source code with makefile present

### Workspace Requirements
- VPP source code checked out in the current directory
- Valid VPP makefile with `install-opt-deps` target
- Network connectivity for downloading packages

## Example Workflows

### Basic VPP Build with Optional Dependencies

```yaml
name: Build VPP with Optional Dependencies
on: push

jobs:
  build:
    runs-on: self-hosted
    steps:
      - name: Checkout VPP Source
        uses: actions/checkout@v4

      - name: Install VPP External Dependencies
        uses: fdio/.github/.github/actions/vpp-install-ext-deps

      - name: Install VPP Optional Dependencies
        uses: fdio/.github/.github/actions/vpp-install-opt-deps

      - name: Build VPP
        run: make build
```

### Advanced Workflow with Custom Output

```yaml
- name: Install Optional Dependencies
  uses: fdio/.github/.github/actions/vpp-install-opt-deps
  with:
    TUI_LINE: "=== Optional Dependencies Setup ==="
```

### Multi-Stage Build

```yaml
name: Multi-Stage VPP Build
on: push

jobs:
  setup-dependencies:
    runs-on: self-hosted
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install External Dependencies
        uses: fdio/.github/.github/actions/vpp-install-ext-deps

      - name: Install Optional Dependencies
        uses: fdio/.github/.github/actions/vpp-install-opt-deps
        with:
          TUI_LINE: "--- Installing Optional VPP Dependencies ---"

  build:
    needs: setup-dependencies
    runs-on: self-hosted
    steps:
      - name: Build VPP
        run: make build

      - name: Run Tests
        run: make test
```

### Strict Mode
```bash
set -euo pipefail
```
- **`-e`**: Exit immediately if any command fails
- **`-u`**: Treat unset variables as errors
- **`-o pipefail`**: Fail if any command in a pipeline fails

## Integration with VPP Build System

This action is part of a comprehensive VPP build setup:

1. **Source Checkout**: Get VPP source code
2. **External Dependencies**: Install required dependencies (`vpp-install-ext-deps`)
3. **Optional Dependencies**: Install optional dependencies (this action)
4. **Build Process**: Compile VPP with enhanced capabilities
5. **Testing**: Run tests with additional tooling available

## Security Considerations

- **System Modifications**: This action may install system packages with elevated privileges
- **Network Dependencies**: Downloads packages from external repositories
- **Build Environment**: Modifies the build environment which may affect subsequent steps
- **Runner Security**: Ensure self-hosted runners are properly secured and isolated

## Maintenance

- **VPP Version Compatibility**: Ensure compatibility with your VPP version
- **System Updates**: Keep runner systems updated for security and compatibility
- **Dependency Monitoring**: Monitor for deprecated or security-vulnerable optional dependencies

## Version Compatibility

This action is designed to work with:
- **VPP**: All versions that include the `install-opt-deps` makefile target
- **Operating Systems**: Linux distributions supported by VPP
- **GitHub Actions**: Compatible with current GitHub Actions runner environments

For specific version requirements, consult the VPP documentation and makefile targets.