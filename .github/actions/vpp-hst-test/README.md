# 🛠️ VPP HostStack Test Action

Builds and runs HostStack tests from a VPP workspace that was already built in HST mode.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
| `BUILD_TYPE` | Yes | none | `debug` uses `build-debug` and `test-debug`, otherwise `build` and `test` |
| `HS_TEST_DIR` | Yes | none | Directory that contains the HST makefile |
| `TEST_JOBS` | Yes | none | Passed as `PARALLEL=<n>` |
| `LOG_DIR` | No | `/scratch/docker-build/vpp/logs/hst` | Directory used for `hst.log` |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## What It Runs

For `BUILD_TYPE=debug`:

```bash
make VERBOSE=true VPPSRC="$WORKSPACE" PARALLEL="$TEST_JOBS" -C "$HS_TEST_DIR" build-debug
make VERBOSE=true VPPSRC="$WORKSPACE" PARALLEL="$TEST_JOBS" -C "$HS_TEST_DIR" test-debug
```

For any other build type:

```bash
make VERBOSE=true VPPSRC="$WORKSPACE" PARALLEL="$TEST_JOBS" -C "$HS_TEST_DIR" build
make VERBOSE=true VPPSRC="$WORKSPACE" PARALLEL="$TEST_JOBS" -C "$HS_TEST_DIR" test
```

## Usage

```yaml
- name: Run HST
  uses: ./.github/actions/vpp-hst-test
  timeout-minutes: 90
  with:
    WORKSPACE: ${{ github.workspace }}
    BUILD_TYPE: debug
    HS_TEST_DIR: ${{ github.workspace }}/test/hs-test
    TEST_JOBS: '1'
    LOG_DIR: ${{ github.workspace }}/logs/hst
```

