# 🛠️ VPP MakeTest Action

This GitHub composite action runs comprehensive tests on the VPP (Vector Packet Processing) project using `make test` after it has been built. It includes unit tests, API generation tests, and multi-worker configuration tests with enhanced configurability.

## Description

The action executes the VPP test suite with configurable parallelism, retry mechanisms, and OS-specific test filtering. It supports single-worker and multi-worker test configurations, API generation validation, and configurable test retry mechanisms for improved reliability.

## Usage

```yaml
- name: Test VPP with MakeTest
  uses: fdio/vpp/.github/actions/vpp-maketest@master
  with:
    TEST_JOBS: '16'
    TEST_RETRIES: '3'
    MAKE_TEST_OS: 'ubuntu-24.04'
    MAKE_TEST_MULTIWORKER_OS: 'debian-12'
    VPPAPIGEN_TEST_OS: 'ubuntu-24.04'
    VPP_WORKER_COUNT: '2'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `TEST_JOBS` | Number of parallel jobs for `make test` execution | No | `16` |
| `TEST_RETRIES` | Number of retries for flaky tests | No | `3` |
| `MAKE_TEST_OS` | OS pattern to run standard `make test` on (e.g., `ubuntu-24.04`, `debian-12`) | No | `ubuntu-24.04` |
| `MAKE_TEST_MULTIWORKER_OS` | OS pattern to run multi-worker `make test` configuration | No | `debian-12` |
| `VPPAPIGEN_TEST_OS` | OS pattern to run VPP API generator tests | No | `ubuntu-24.04` |
| `VPP_WORKER_COUNT` | Number of VPP workers to use for multiworker tests | No | `2` |
| `TUI_LINE` | Delimiter line for terminal UI output formatting | No | `*******************************************************************` |

## Test Execution Flow

The action executes tests in the following sequence:

### 1. Test Dependencies
```bash
make UNATTENDED=yes test-dep
```
Installs all required test dependencies.

### 2. VPP API Generator Tests
```bash
src/tools/vppapigen/test_vppapigen.py
```
- Runs only on OS matching `VPPAPIGEN_TEST_OS` pattern
- Validates VPP API generation functionality
- Skipped if OS doesn't match

### 3. Standard Test Suite
```bash
make COMPRESS_FAILED_TEST_LOGS=yes TEST_JOBS="$TEST_JOBS" RETRIES=3 test
```
- Runs only on OS matching `MAKE_TEST_OS` pattern
- Uses configurable parallelism via `TEST_JOBS`
- Automatically retries failed tests up to 3 times
- Compresses failed test logs to save space
- Skipped if OS doesn't match

### 4. Multi-Worker Test Suite
```bash
make VPP_WORKER_COUNT="${VPP_WORKER_COUNT}" COMPRESS_FAILED_TEST_LOGS=yes TEST_RETRIES="${TEST_RETRIES}" TEST_JOBS="${TEST_JOBS}" test
```
- Runs only on OS matching `MAKE_TEST_MULTIWORKER_OS` pattern
- Tests VPP with configurable worker count (default: 2 workers)
- Uses `VPP_WORKER_COUNT` configuration method
- Configurable retry count via `TEST_RETRIES` parameter
- Skipped if OS doesn't match

## OS Pattern Matching

The action uses OS patterns to determine which tests to run on which platforms:

- **Current OS**: Determined from `OS_ID` and `OS_VERSION_ID` environment variables (e.g., `ubuntu-24.04`)
- **Pattern Matching**: Uses `grep -q` to match current OS against input patterns
- **Multiple OS Support**: Patterns can include multiple OS versions separated by spaces

### Example OS Patterns:
```yaml
MAKE_TEST_OS: "ubuntu-22.04 ubuntu-24.04"          # Run on Ubuntu 22.04 or 24.04
MAKE_TEST_MULTIWORKER_OS: "debian-12"               # Run only on Debian 12
VPPAPIGEN_TEST_OS: "ubuntu-24.04 debian-12"         # Run on Ubuntu 24.04 or Debian 12
```

## Prerequisites

Before using this action, ensure the following have been completed:

1. **VPP Build**: The `vpp-build` action must have run successfully
2. **Environment Setup**: Environment variables must be configured (`OS_ID`, `OS_VERSION_ID`, `OS_ARCH`)
3. **Dependencies**: All VPP dependencies and external dependencies must be installed
4. **Docker Runtime**: Docker runtime environment must be set up for containerized tests

## Example Workflow

```yaml
jobs:
  test-vpp:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        os: ['ubuntu-22.04', 'ubuntu-24.04', 'debian-12']

    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Setup Environment
        uses: fdio/.github/.github/actions/setup-executor-env@main

      - name: Setup Docker Runtime
        uses: fdio/vpp/.github/actions/vpp-docker-runtime-setup@master

      - name: Install Dependencies
        uses: fdio/vpp/.github/actions/vpp-install-deps@master

      - name: Install External Dependencies
        uses: fdio/vpp/.github/actions/vpp-install-ext-deps@master

      - name: Build VPP
        uses: fdio/vpp/.github/actions/vpp-build@master

      - name: Test VPP
        uses: fdio/vpp/.github/actions/vpp-test@master
        timeout-minutes: 75
        with:
          TEST_JOBS: '16'
          TEST_RETRIES: '3'
          MAKE_TEST_OS: ${{ matrix.os }}
          MAKE_TEST_MULTIWORKER_OS: 'debian-12'
          VPPAPIGEN_TEST_OS: ${{ matrix.os }}
          VPP_WORKER_COUNT: '2'
```

## Error Handling

The action implements robust error handling:

- **Fail Fast**: Uses `set -euxo pipefail` for immediate failure on errors
- **Specific Error Messages**: Captures detailed error context for each test phase
- **Retry Logic**: Built-in retry mechanism (3 attempts) for flaky tests
- **Log Compression**: Automatically compresses failed test logs to conserve storage
- **Graceful Skipping**: Cleanly skips tests not applicable to current OS

## Test Output and Artifacts

### Success Indicators
- Exit code `0` on successful completion
- Clear success messages for each test phase
- Multi-worker test completion messages

### Failure Information
- Exit code `1` on any test failure
- Specific error messages identifying failed test phase
- Compressed logs for failed tests (when `COMPRESS_FAILED_TEST_LOGS=yes`)

## Environment Variables Used

The action expects these environment variables to be set by upstream actions:

- `OS_ID`: Operating system identifier (e.g., `ubuntu`, `debian`)
- `OS_VERSION_ID`: OS version identifier (e.g., `22.04`, `24.04`, `12`)
- `OS_ARCH`: CPU architecture (e.g., `x86_64`, `aarch64`)

## Performance Tuning

### Parallel Test Jobs
Adjust `TEST_JOBS` based on available resources:
- **High-end runners**: 16-32 jobs
- **Standard runners**: 8-16 jobs
- **Resource-constrained**: 4-8 jobs

### Retry Configuration
Configure `TEST_RETRIES` based on test stability:
- **Stable environments**: 1-2 retries
- **Standard CI/CD**: 3 retries (default)
- **Flaky environments**: 3-5 retries

### Multi-Worker Configuration
Adjust `VPP_WORKER_COUNT` based on system capabilities:
- **Standard testing**: 2 workers (default)
- **High-performance systems**: 4-8 workers
- **Resource-limited**: 1 worker (single-threaded)

### Test Filtering
Use OS pattern matching to limit tests to appropriate platforms:
- Run resource-intensive tests only on specific OS versions
- Skip multi-worker tests on platforms with limited resources
