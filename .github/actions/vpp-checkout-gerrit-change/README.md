# 🛠️ VPP Checkout Gerrit Change Action

Fetches a Gerrit patchset from `origin` and checks out `FETCH_HEAD` in an existing VPP workspace.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `WORKSPACE` | Yes | none | Absolute path to the checked out VPP tree |
| `GERRIT_BRANCH` | Yes | none | Branch to checkout before fetching the patchset |
| `GERRIT_REFSPEC` | Yes | none | Gerrit refspec to fetch from `origin` |
| `LOG_DIR` | No | `/scratch/docker-build/vpp/logs/checkout` | Directory used for `checkout.log` |
| `TUI_LINE` | No | `*******************************************************************` | Log separator |

## What It Runs

```bash
git checkout "$GERRIT_BRANCH" || echo "WARNING: Could not checkout $GERRIT_BRANCH!"
git fetch --tags origin "$GERRIT_REFSPEC"
git checkout FETCH_HEAD
git show --stat
```

## Usage

```yaml
- name: Checkout Gerrit change
  uses: ./.github/actions/vpp-checkout-gerrit-change
  with:
    WORKSPACE: ${{ github.workspace }}
    GERRIT_BRANCH: ${{ inputs.GERRIT_BRANCH }}
    GERRIT_REFSPEC: ${{ inputs.GERRIT_REFSPEC }}
    LOG_DIR: ${{ github.workspace }}/logs/checkout
```
