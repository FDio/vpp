# 🛠️ VPP Install Optional Dependencies Action

Runs the optional dependency install target from the VPP build system.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
| `LOG_DIR` | No | `/scratch/docker-build/vpp/logs/install-opt-deps.log` | Used as a directory even though the default name ends in `.log` |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## What It Runs

```bash
cd "$WORKSPACE"
make UNATTENDED=yes install-opt-deps
```

## Usage

```yaml
- name: Install VPP optional dependencies
  uses: ./.github/actions/vpp-install-opt-deps
  with:
    WORKSPACE: ${{ github.workspace }}
    LOG_DIR: ${{ github.workspace }}/logs/install-opt-deps
```
