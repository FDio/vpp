# 🛠️ VPP Build Action

Builds VPP from a checked out workspace.

## What It Runs

- Standard debug build: `make UNATTENDED=yes MAKE_PARALLEL_JOBS=<n> build`
- Standard release build: `make UNATTENDED=yes MAKE_PARALLEL_JOBS=<n> pkg-verify`
- Standard GCC build: adds `CC=gcc`
- HST debug build: `make UNATTENDED=yes MAKE_PARALLEL_JOBS=<n> build`
- HST release build: `make UNATTENDED=yes MAKE_PARALLEL_JOBS=<n> build-release`
- Standard builds also run `extras/scripts/build_static_vppctl.sh` first when that script exists.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `BUILD_TYPE` | Yes | none | `debug` or `release` |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
| `LOG_DIR` | No | `/scratch/docker-build/vpp/logs/build` | Directory used for build logs |
| `MAKE_PARALLEL_JOBS` | No | `16` | Passed to `make` |
| `BUILD_HST` | No | `false` | Switches to HostStack build targets |
| `USE_GCC` | No | `false` | Adds `CC=gcc` to standard builds |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## Usage

```yaml
- name: Build VPP
  uses: ./.github/actions/vpp-build
  with:
    WORKSPACE: ${{ github.workspace }}
    BUILD_TYPE: release
    LOG_DIR: ${{ github.workspace }}/logs/build
    MAKE_PARALLEL_JOBS: '16'
```

## HST Usage

```yaml
- name: Build VPP for HST
  uses: ./.github/actions/vpp-build
  with:
    WORKSPACE: ${{ github.workspace }}
    BUILD_TYPE: debug
    BUILD_HST: 'true'
    LOG_DIR: ${{ github.workspace }}/logs/hst-build
```
