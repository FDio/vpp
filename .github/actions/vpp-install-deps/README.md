# 🛠️ VPP Install Dependencies Action

Runs the repository-supported dependency bootstrap step.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
| `LOG_DIR` | No | `/scratch/docker-build/vpp/logs/install-deps` | Directory used for `install_deps.log` |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## What It Runs

```bash
cd "$WORKSPACE"
make UNATTENDED=yes install-deps
```

## Usage

```yaml
- name: Install VPP dependencies
  uses: ./.github/actions/vpp-install-deps
  with:
    WORKSPACE: ${{ github.workspace }}
    LOG_DIR: ${{ github.workspace }}/logs/install-deps
```