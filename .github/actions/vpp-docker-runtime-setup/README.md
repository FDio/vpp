# 🛠️ VPP Docker Runtime Setup Action

Remounts `/dev/shm` with a caller-provided size before VPP test execution.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Accepted for interface consistency; not used by the script |
| `SHM_SIZE` | Yes | none | Passed to `mount -o remount /dev/shm -o size=<value>` |
| `LOG_DIR` | Yes | none | Directory used for `runtime_setup.log` |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## What It Runs

```bash
sudo mount -o remount /dev/shm -o size=$SHM_SIZE || true
```

## Usage

```yaml
- name: Prepare shared memory for make test
  uses: ./.github/actions/vpp-docker-runtime-setup
  with:
    WORKSPACE: ${{ github.workspace }}
    SHM_SIZE: 2048M
    LOG_DIR: ${{ github.workspace }}/logs/runtime
```
