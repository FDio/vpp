# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Scope of work

The work is concentrated around developing the new Generic PCAPNG plugin, in the src/plugins/gpcapng.
Any modifications should be only concern the files in this directory, and the file test/test_gpcapng.py,
which provides the test facilities.

## VPP (Vector Packet Processing) Repository Overview

VPP is a high-performance, extensible, and production-ready switch/router framework developed by the FD.io community. This is the open-source version of Cisco's Vector Packet Processing technology.

## Build System and Common Commands

### Core Build Commands
- `make` - Display all available make targets and current configuration
- `make build` - Build debug binaries (default target)
- `make build-release` - Build optimized release binaries
- `make wipe` - Clean all debug build artifacts
- `make wipe-release` - Clean all release build artifacts
- `make rebuild` - Wipe and rebuild debug binaries
- `make rebuild-release` - Wipe and rebuild release binaries

### Configuration and Setup
- `make install-dep` - Install system dependencies for building VPP
- `make install-ext-deps` - Install external development dependencies
- `./configure` - Advanced build configuration script with cross-compilation support
- `./extras/vagrant/build.sh` - Quick setup script for development environment

### Running VPP
- `make run` - Run debug VPP binary
- `make run-release` - Run release VPP binary  
- `make debug` - Run debug VPP binary under GDB debugger
- `make debug-release` - Run release VPP binary under GDB debugger

### Testing
- `make test` - Run the Python-based test suite (functional tests)
- `make test-debug` - Run tests against debug build
- `make test-all` - Run extended test suite including longer tests
- `make retest` - Rerun tests without rebuilding VPP
- `make test-cov` - Run tests with code coverage analysis
- `make test-shell` - Interactive test environment for debugging
- `make test-help` - Display comprehensive testing options

### Code Quality and Development
- `make checkstyle` - Check C/C++ coding style compliance
- `make fixstyle` - Automatically fix coding style issues
- `make checkstyle-python` - Check Python code style using black formatter
- `make fixstyle-python` - Fix Python code style issues
- `make compdb` - Generate compile_commands.json for IDE integration
- `make ctags` / `make etags` / `make gtags` - Generate code indexing databases

### Documentation
- `make docs` - Build Sphinx documentation
- `make docs-clean` - Clean generated documentation files

## Architecture Overview

### Core Libraries and Components
- **src/vppinfra/** - Core infrastructure library (memory management, data structures, utilities)
- **src/vlib/** - VPP application library (nodes, threads, CLI, buffers, traces)
- **src/vnet/** - VPP networking library (interfaces, protocols, forwarding)
- **src/svm/** - Shared virtual memory library for inter-process communication
- **src/vlibapi/** - VPP API framework
- **src/vlibmemory/** - Memory management for API communication

### Plugin Architecture
- **src/plugins/** - Bundled VPP plugins (protocol implementations, device drivers, features)
- Plugins are dynamically loadable and follow a consistent CMake-based build pattern
- Each plugin typically has its own directory with CMakeLists.txt, API definitions, and implementation files

### API and Language Bindings
- **src/vpp-api/** - Language bindings and API client libraries
- **src/vat/** - VPP API Test program (legacy)
- **src/vat2/** - Modern VPP API Test program
- API definitions use .api files with custom VPP API language

### Testing Framework
VPP uses a sophisticated Python-based testing framework:
- **test/** - Comprehensive test suite with 100+ test modules
- Built on unittest and Scapy for packet manipulation
- Supports parallel test execution, VM-based testing, and code coverage
- Tests spawn isolated VPP instances with packet generator interfaces
- Key test runner: `test/run.py` with extensive configuration options
- Framework classes: `VppTestCase` for Scapy-based tests, `VppAsfTestCase` for basic tests

## Development Workflow

### Setting Up Development Environment
1. `make install-dep` - Install system dependencies
2. `make install-ext-deps` - Install external dependencies  
3. `make build` - Initial build
4. `make test` - Verify everything works

### Plugin Development
- Use `extras/emacs/make-plugin.sh` to generate plugin templates
- Follow existing plugin patterns in `src/plugins/`
- Each plugin needs CMakeLists.txt, API definitions, and implementation
- Test plugins using the test framework in `test/`

### Build Types and Targets
- **Debug builds** (default): Full debugging information, assertions enabled
- **Release builds**: Optimized for performance
- **Coverage builds**: Instrumented for code coverage analysis
- Multiple target platforms supported via PLATFORM variable

### Key Environment Variables
- `CC` - Compiler selection (defaults to clang)
- `PLATFORM` - Target platform (default: vpp)
- `V=1` - Verbose build output
- `STARTUP_CONF` - VPP startup configuration file path
- `DISABLED_PLUGINS` - Comma-separated list of plugins to disable

## File Organization Patterns

### Source Code Structure
- C/C++ source files follow VPP coding standards (checked by `make checkstyle`)
- Header files use `.h` extension
- API definitions in `.api` files
- Plugin-specific code organized in plugin subdirectories

### Build Artifacts
- **build-root/** contains all build outputs
- **build-root/install-*/** contains installed binaries and libraries
- **build-root/build-*/** contains intermediate build files

### Configuration Files
- **startup.conf** - VPP runtime configuration (interfaces, plugins, etc.)
- **.clang-format** - Code formatting rules
- **compile_commands.json** - Generated by `make compdb` for IDE integration

## Testing Best Practices

### Running Tests
- Always run `make test` after significant changes
- Use `make test-debug` for debugging test failures
- Use specific test patterns: `make test TEST=test_ip4` for targeted testing
- Enable coverage: `make test-cov` for coverage analysis

### Test Development
- New features should include comprehensive tests in `test/`
- Follow existing test patterns using VppTestCase base class
- Use packet generator interfaces for traffic simulation
- Verify both data plane and control plane functionality

## Common Development Tasks

### Adding New Features
1. Implement in appropriate src/ directory
2. Add API definitions if needed
3. Update CMakeLists.txt files
4. Write comprehensive tests
5. Update documentation if user-visible

### Debugging
- Use `make debug` to run VPP under GDB
- Enable core dumps and use `gdb` to analyze crashes
- Use `make test-shell` for interactive test debugging
- Check VPP logs and traces for runtime analysis

### Performance Analysis
- Use release builds (`make build-release`) for performance testing
- VPP includes built-in performance monitoring tools
- Use `make test` with performance-focused test cases
