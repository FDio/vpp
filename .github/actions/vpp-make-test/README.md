# 🛠️ VPP Make Test Action

Runs the current `make test` based verification flow from a built VPP workspace.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
| `BUILD_TYPE` | Yes | none | `debug` selects `test-debug`, anything else selects `test` |
| `LOG_DIR` | No | `/scratch/docker-build/vpp/logs/maketest` | Directory used for `maketest.log` |
| `TEST_JOBS` | No | `4` | Passed to make test runs |
| `TEST_RETRIES` | No | `3` | Used for the retry-enabled test flows |
| `MAKE_TEST_OS` | No | `ubuntu-24.04` | Standard make test runs only when the current OS string matches |
| `MAKE_TEST_MULTIWORKER_OS` | No | `debian-12` | Multiworker test runs only when the current OS string matches |
| `VPPAPIGEN_TEST_OS` | No | `ubuntu-24.04` | `test_vppapigen.py` runs only when the current OS string matches |
| `VPP_WORKER_COUNT` | No | `0` | Passed to the multiworker make invocation |
| `MAKE_TEST_SUITES` | No | empty string | Space-separated suites; switches to suite-by-suite mode |
| `VPP_TEARDOWN_TIMEOUT` | No | `30` | Accepted input; not used by the current script |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## Default Flow

When `MAKE_TEST_SUITES` is empty, the action runs:

```bash
make UNATTENDED=yes test-dep
src/tools/vppapigen/test_vppapigen.py
make COMPRESS_FAILED_TEST_LOGS=yes TEST="\"$MAKE_TEST_SUITES\"" TEST_JOBS="$TEST_JOBS" RETRIES="$TEST_RETRIES" $TEST_TARGET
make VPP_WORKER_COUNT="$VPP_WORKER_COUNT" COMPRESS_FAILED_TEST_LOGS=yes TEST_RETRIES="$TEST_RETRIES" TEST_JOBS="$TEST_JOBS" $TEST_TARGET
```

Each of the last three commands is gated by OS matching as defined by the corresponding inputs.

## Suite-By-Suite Flow

When `MAKE_TEST_SUITES` is non-empty, the action skips `test-dep`, skips the OS-gated flow, and for each suite runs the same make command twice:

```bash
make UNATTENDED=yes CCACHE_DISABLE=1 TESTS_GCOV=1 TEST_JOBS="$TEST_JOBS" TEST=$suite $TEST_TARGET
make UNATTENDED=yes CCACHE_DISABLE=1 TESTS_GCOV=1 TEST_JOBS="$TEST_JOBS" TEST=$suite $TEST_TARGET
```

## Usage

```yaml
- name: Run make test
  uses: ./.github/actions/vpp-make-test
  timeout-minutes: 120
  with:
    WORKSPACE: ${{ github.workspace }}
    BUILD_TYPE: release
    LOG_DIR: ${{ github.workspace }}/logs/maketest
    TEST_JOBS: '4'
    TEST_RETRIES: '3'
    MAKE_TEST_OS: ubuntu-24.04
    MAKE_TEST_MULTIWORKER_OS: debian-12
    VPPAPIGEN_TEST_OS: ubuntu-24.04
```