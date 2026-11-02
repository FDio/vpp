# 🛠️ VPP Install Optional Dependencies Action

Runs the optional dependency install target from the VPP build system.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
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
```
