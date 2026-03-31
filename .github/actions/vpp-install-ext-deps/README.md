# 🛠️ VPP Install External Dependencies Action

Runs the external dependency install path used by the current CI workflows.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
| `LOG_DIR` | No | `/scratch/docker-build/vpp/logs/install-ext-deps.log` | Used as a directory even though the default name ends in `.log` |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## What It Does

1. Tries to install `vpp-ext-deps` from Packagecloud.
2. Derives the Packagecloud stream from `GERRIT_BRANCH` when that environment variable exists, otherwise uses `master`.
3. On Ubuntu or Debian, optionally installs a cached `.deb` from `/root/Downloads` or installs via `apt-get`.
4. Removes temporary `fdio_*.list` apt source files.
5. Always runs the repository fallback:

```bash
cd "$WORKSPACE"
make UNATTENDED=yes install-ext-deps
```

## Usage

```yaml
- name: Install VPP external dependencies
  uses: ./.github/actions/vpp-install-ext-deps
  with:
    WORKSPACE: ${{ github.workspace }}
    LOG_DIR: ${{ github.workspace }}/logs/install-ext-deps
```
