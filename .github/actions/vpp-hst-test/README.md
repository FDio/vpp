# VPP HostStack Test (HST) Action

This GitHub Action tests the VPP image using the HostStack Test (HST) framework.

## Description

This action runs the VPP HostStack Test framework to validate VPP's host stack functionality. It supports both debug and release build types and includes comprehensive error checking and core file detection.

## Inputs

### `WORKSPACE`

**Description:** Workspace directory where VPP is located

**Required:** Yes

**Type:** string

### `BUILD_TYPE`

**Description:** Type of build to test: `dbg` (debug) or `rel` (release)

**Required:** Yes

**Type:** string

**Valid values:** `dbg`, `rel`

### `HS_TEST_DIR`

**Description:** Directory containing HostStack Test (HST) framework tests

**Required:** Yes

**Type:** string

**Example:** `/scratch/docker-build/vpp/test-c/hs-test`

### `TUI_LINE`

**Description:** Delimiter line for TUI output

**Required:** No

**Default:** `*******************************************************************`

**Type:** string

## Usage

```yaml
- name: HST Test VPP
  uses: fdio/vpp/.github/actions/vpp-hst-test@master
  timeout-minutes: 60
  with:
    WORKSPACE: ${{ env.WORKSPACE }}
    BUILD_TYPE: ${{ matrix.build_type }}
    HS_TEST_DIR: ${{ env.HS_TEST_DIR }}
    TUI_LINE: ${{ env.TUI_LINE }}
```

### Debug Build Example

```yaml
- name: HST Test VPP Debug
  uses: fdio/vpp/.github/actions/vpp-hst-test@master
  timeout-minutes: 60
  with:
    WORKSPACE: /scratch/docker-build/vpp
    BUILD_TYPE: dbg
    HS_TEST_DIR: /scratch/docker-build/vpp/test-c/hs-test
```

### Release Build Example

```yaml
- name: HST Test VPP Release
  uses: fdio/vpp/.github/actions/vpp-hst-test@master
  timeout-minutes: 60
  with:
    WORKSPACE: /scratch/docker-build/vpp
    BUILD_TYPE: rel
    HS_TEST_DIR: /scratch/docker-build/vpp/test-c/hs-test
```

## How It Works

### Test Flow

1. **Pre-test Core File Check** - Scans for existing core files before testing
2. **Build Phase** - Builds HST test framework based on build type
3. **Test Execution** - Runs HST tests
4. **Post-test Core File Check** - Scans for new core files after testing
5. **Result Reporting** - Reports success or failure with detailed error messages

### Build Types

#### Debug Build (`dbg`)
- Executes: `make VERBOSE=true VPPSRC=$WORKSPACE -C $HS_TEST_DIR build-debug`
- Tests with: `make VERBOSE=true VPPSRC=$WORKSPACE -C $HS_TEST_DIR test-debug`

#### Release Build (`rel`)
- Executes: `make VERBOSE=true VPPSRC=$WORKSPACE -C $HS_TEST_DIR build`
- Tests with: `make VERBOSE=true VPPSRC=$WORKSPACE -C $HS_TEST_DIR test`

### Core File Detection

The action checks for system core files in:
- `/var/crash` - System crash dumps
- `/scratch/nomad` - Debug directory (for troubleshooting)
- `/scratch/ccache` - Cache directory (for troubleshooting)

Core file checks run both before and after test execution to detect crashes during testing.

## Prerequisites

- VPP must be built using the `vpp-build` action with `BUILD_HST: 'true'`
- Docker daemon must be running (use `vpp-start-docker` action)
- The workspace must contain a valid VPP source tree
- The HST test directory must exist

## Error Handling

The action will fail if:
- HST build fails for the specified build type
- HST tests fail during execution
- Required directories are not accessible

**Note:** Core file checks are run with `|| true` to prevent failure if directories don't exist, ensuring the action continues even if core file locations are unavailable.

## Example Workflow

```yaml
jobs:
  vpp-hst-test:
    name: VPP HST Test
    runs-on: self-hosted
    strategy:
      matrix:
        build_type: ['dbg', 'rel']

    env:
      WORKSPACE: /scratch/docker-build/vpp
      HS_TEST_DIR: /scratch/docker-build/vpp/test-c/hs-test

    steps:
      - name: Checkout Code
        uses: actions/checkout@v5

      - name: Install VPP Dependencies
        uses: fdio/vpp/.github/actions/vpp-install-deps@master
        with:
          WORKSPACE: ${{ env.WORKSPACE }}

      - name: Build VPP with HST
        uses: fdio/vpp/.github/actions/vpp-build@master
        with:
          WORKSPACE: ${{ env.WORKSPACE }}
          BUILD_TYPE: ${{ matrix.build_type }}
          BUILD_HST: 'true'
          MAKE_PARALLEL_JOBS: 16

      - name: Start Docker Daemon
        uses: fdio/vpp/.github/actions/vpp-start-docker@master

      - name: Run HST Tests
        if: success()
        uses: fdio/vpp/.github/actions/vpp-hst-test@master
        timeout-minutes: 60
        with:
          WORKSPACE: ${{ env.WORKSPACE }}
          BUILD_TYPE: ${{ matrix.build_type }}
          HS_TEST_DIR: ${{ env.HS_TEST_DIR }}
```

## Timeout Considerations

HST tests can be time-consuming. It's recommended to set a `timeout-minutes` value (typically 60 minutes) to prevent indefinite hanging:

```yaml
- name: HST Test VPP
  uses: fdio/vpp/.github/actions/vpp-hst-test@master
  timeout-minutes: 60
  with:
    WORKSPACE: ${{ env.WORKSPACE }}
    BUILD_TYPE: dbg
    HS_TEST_DIR: ${{ env.HS_TEST_DIR }}
```

## Output

The action provides detailed output including:
- Verbose build and test logs (`VERBOSE=true`)
- Core file detection results
- Build/test result summary with platform information
- Error messages for any failures

**Example success output:**
```
*******************************************************************
* VPP DBG UBUNTU-2404-X86_64
* HST SUCCESSFULLY COMPLETED
*******************************************************************
```

**Example failure output:**
```
*******************************************************************
* VPP REL UBUNTU-2404-X86_64
* HST FAILED 'make VERBOSE=true VPPSRC=/scratch/docker-build/vpp -C /scratch/docker-build/vpp/test-c/hs-test test'
*******************************************************************
```

## Notes

- The action uses `set -euxo pipefail` for strict error handling
- Test and build failures are captured but don't immediately exit (using `|| true`)
- Final exit code reflects whether any errors occurred during the process
- Debug builds (`dbg`) are typically slower but provide more diagnostic information
- Release builds (`rel`) are optimized for performance troubleshooting
