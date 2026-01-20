# 🛠️ VPP Install External Dependencies

This GitHub Action installs external dependencies for VPP (Vector Packet Processing) on self-hosted runners. It provides an optimized installation process with caching capabilities and fallback mechanisms to ensure reliable dependency setup for VPP builds.

## Overview

The action performs a two-stage installation process:
1. **Optimization Phase**: Attempts to install `vpp-ext-deps` from packagecloud with caching
2. **Fallback Phase**: Uses the standard VPP makefile target as a reliable backup

## Usage

```yaml
- name: Install VPP External Dependencies
  uses: fdio/vpp/.github/actions/vpp-install-ext-deps
  with:
    TUI_LINE: "*******************************************************************"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `TUI_LINE` | Delimiter line for TUI output formatting | No | `"*******************************************************************"` |

## Features

### 🚀 **Optimization Features**
- **Smart Caching**: Caches downloaded packages in `/root/Downloads` for reuse
- **Stream Support**: Supports VPP streams (`master`, `stable/YYYY`)
- **OS Detection**: Automatically detects Ubuntu/Debian distributions
- **Retry Logic**: Built-in retry mechanism with exponential backoff
- **Lock Management**: Prevents concurrent apt operations

### 🛡️ **Reliability Features**
- **Dual Installation Strategy**: Optimization + guaranteed fallback
- **Comprehensive Error Handling**: Graceful failure handling with detailed logging
- **JSON Summary Output**: Structured logging for monitoring and debugging
- **Repository Cleanup**: Automatic cleanup of temporary repository configurations

### 📊 **Monitoring & Debugging**
- **Verbose Logging**: Configurable verbosity levels
- **Performance Tracking**: Execution time measurement
- **Status Reporting**: Success/failure/skip status with reasons
- **Metadata Extraction**: Package version and architecture information

## Environment Variables

The optimization phase supports several environment variables for advanced configuration:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `VERBOSE` | Enable verbose logging | `1` | `0` or `1` |
| `DOWNLOADS_DIR` | Cache directory path | `/root/Downloads` | `/tmp/vpp-cache` |
| `APT_RETRIES` | Number of retry attempts | `3` | `5` |
| `APT_RETRY_DELAY` | Initial retry delay (seconds) | `3` | `5` |
| `SUMMARY_JSON` | Enable JSON summary output | `1` | `0` or `1` |

## Supported Platforms

- **Ubuntu** (all supported versions)
- **Debian** (all supported versions)
- **Architecture**: Multi-architecture support (detected automatically)

*Note: Unsupported OS distributions are gracefully skipped with appropriate logging.*

## Installation Process

### Phase 1: Packagecloud Optimization

1. **OS Detection**: Validates Ubuntu/Debian compatibility
2. **Repository Setup**: Configures stream-specific packagecloud repository
3. **Cache Check**: Attempts installation from local cache
4. **Network Install**: Downloads and installs from packagecloud if cache miss
5. **Cache Update**: Stores newly downloaded packages for future use
6. **Cleanup**: Removes temporary repository configuration

### Phase 2: Makefile Fallback

```bash
make UNATTENDED=yes install-ext-deps
```

Executes the standard VPP makefile target to ensure dependencies are installed regardless of optimization phase outcome.

## Example Workflows

### Basic Usage
```yaml
name: Build VPP
on: push

jobs:
  build:
    runs-on: self-hosted
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install VPP Dependencies
        uses: ./.github/actions/vpp-install-ext-deps

      - name: Build VPP
        run: make build
```

### Advanced Configuration
```yaml
- name: Install VPP Dependencies (Custom Stream)
  uses: ./.github/actions/vpp-install-ext-deps
  env:
    STREAM: stable/2024
    VERBOSE: 1
    DOWNLOADS_DIR: /tmp/vpp-cache
    APT_RETRIES: 5
  with:
    TUI_LINE: "=== VPP Dependencies ==="
```

## Caching Strategy

The action implements an intelligent caching mechanism:

```
/root/Downloads/
└── vpp-ext-deps_<version>_<arch>.deb
```

### Cache Benefits
- **Faster Builds**: Subsequent runs use cached packages
- **Network Resilience**: Reduces dependency on external repositories
- **Bandwidth Optimization**: Minimizes repeated downloads
- **Container Persistence**: Cache survives container lifecycle on self-hosted runners

## Error Handling

The action provides robust error handling at multiple levels:

### Optimization Phase
- **Graceful Degradation**: Optimization failures don't affect overall success
- **Detailed Logging**: Comprehensive error reporting with context
- **Automatic Retry**: Built-in retry logic for transient failures
- **Repository Cleanup**: Ensures clean state even after failures

### Fallback Phase
- **Guaranteed Execution**: Always runs regardless of optimization outcome
- **Standard VPP Process**: Uses well-tested VPP installation procedures
- **Error Propagation**: Properly reports failures that require attention

## JSON Output Format

When `SUMMARY_JSON=1` (default), the action outputs structured JSON for monitoring:

```json
{
  "script": "vpp_install_ext_deps",
  "stream": "master",
  "os": "ubuntu",
  "action": "install",
  "result": "success",
  "cached": true,
  "version": "24.06-rc0~123-g1234567",
  "arch": "amd64",
  "duration_sec": 45,
  "skip_reason": ""
}
```

### Result Values
- `success`: Installation completed successfully
- `skip`: Skipped due to unsupported OS or other conditions
- `failed`: Installation attempt failed
- `noop`: No action taken
- `error`: Unexpected error occurred

## Performance Considerations

- **First Run**: May take several minutes to download and install dependencies
- **Cached Runs**: Typically complete in under 30 seconds
- **Network Impact**: Optimization reduces bandwidth usage in repeated builds
- **Disk Usage**: Cache directory should have sufficient space (~500MB typical)

## Troubleshooting

### Common Issues

1. **Unsupported OS**
   - Check `/etc/os-release` for OS identification
   - Ensure running on Ubuntu or Debian

2. **Network Connectivity**
   - Verify access to packagecloud.io
   - Check firewall rules for self-hosted runners

3. **Permission Issues**
   - Ensure runner has sudo privileges
   - Check write permissions to cache directory

4. **Cache Corruption**
   - Clear cache directory: `rm -rf /root/Downloads/vpp-ext-deps*`
   - Rerun the action

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```yaml
env:
  VERBOSE: 1
```

## Security Considerations

- **Repository Trust**: Uses official FD.io packagecloud repositories
- **sudo Usage**: Requires elevated privileges for package installation
- **Network Security**: Downloads over HTTPS with retry logic
- **File Permissions**: Cache files created with appropriate permissions

## Dependencies

### System Requirements
- Ubuntu/Debian operating system
- `sudo` access for package installation
- Internet connectivity for initial package download
- Standard system utilities: `curl`, `apt-get`, `dpkg`

### Optional Dependencies
- `flock`: For concurrent operation protection (graceful fallback if unavailable)
- `jq`: Not required (error handling includes fallback)

## Maintenance

The action is designed to be self-maintaining:
- **Automatic Cleanup**: Removes temporary configurations
- **Cache Management**: Old cache entries can be manually cleaned if needed
- **Repository Updates**: Handles repository configuration changes transparently

## Integration with VPP Build System

This action is specifically designed to work with the VPP project's build system and should be used as a preparatory step before VPP compilation. It ensures all external dependencies required by VPP are properly installed and available.
