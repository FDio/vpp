# VPP Checkout Gerrit Change Action

This GitHub Action checks out a specific VPP Gerrit change for testing and verification purposes.

## Description

This action fetches and checks out a specific Gerrit change (patchset) in the VPP repository. It's designed to work with Gerrit code review workflow, allowing CI/CD pipelines to test changes before they are merged.

## Inputs

### `WORKSPACE`

**Description:** Workspace directory where VPP is located

**Required:** Yes

**Type:** string

### `GERRIT_BRANCH`

**Description:** Gerrit branch to checkout (e.g., `master`, `stable/2404`)

**Required:** Yes

**Type:** string

### `GERRIT_REFSPEC`

**Description:** Gerrit refspec to fetch (e.g., `refs/changes/12/34512/3`)

**Required:** Yes

**Type:** string

### `TUI_LINE`

**Description:** Delimiter line for TUI output

**Required:** No

**Default:** `*******************************************************************`

**Type:** string

## Usage

```yaml
- name: Checkout VPP Gerrit Change
  uses: fdio/vpp/.github/actions/vpp-checkout-gerrit-change@master
  with:
    WORKSPACE: ${{ env.WORKSPACE }}
    GERRIT_BRANCH: ${{ env.GERRIT_BRANCH }}
    GERRIT_REFSPEC: ${{ env.GERRIT_REFSPEC }}
    TUI_LINE: ${{ env.TUI_LINE }}
```

### Example with Specific Values

```yaml
- name: Checkout VPP Gerrit Change
  uses: fdio/vpp/.github/actions/vpp-checkout-gerrit-change@master
  with:
    WORKSPACE: /scratch/docker-build/vpp
    GERRIT_BRANCH: master
    GERRIT_REFSPEC: refs/changes/12/34512/3
```

## How It Works

1. Changes to the specified workspace directory
2. Checks out the target Gerrit branch
3. Fetches the specific Gerrit refspec from origin
4. Checks out the fetched change (FETCH_HEAD)
5. Displays the change statistics using `git show --stat`

## Prerequisites

- The workspace directory must exist and contain a valid Git repository
- Git must be configured with access to the Gerrit remote (origin)
- The specified branch must exist in the repository
- The Gerrit refspec must be valid and accessible

## Gerrit Refspec Format

Gerrit refspecs follow the format: `refs/changes/[last 2 digits]/[change number]/[patchset number]`

**Examples:**
- `refs/changes/12/34512/3` - Change 34512, patchset 3
- `refs/changes/45/12345/1` - Change 12345, patchset 1
- `refs/changes/99/99/5` - Change 99, patchset 5

## Example Workflow

```yaml
jobs:
  verify-gerrit-change:
    runs-on: self-hosted
    env:
      WORKSPACE: /scratch/docker-build/vpp
      GERRIT_BRANCH: master
      GERRIT_REFSPEC: refs/changes/12/34512/3

    steps:
      - name: Actions Checkout
        uses: actions/checkout@v5

      - name: Restore VPP Gerrit Environment Variables
        uses: fdio/.github/.github/actions/gerrit-env-vars-restore@main
        with:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Checkout VPP Gerrit Change
        uses: fdio/vpp/.github/actions/vpp-checkout-gerrit-change@master
        with:
          WORKSPACE: ${{ env.WORKSPACE }}
          GERRIT_BRANCH: ${{ env.GERRIT_BRANCH }}
          GERRIT_REFSPEC: ${{ env.GERRIT_REFSPEC }}

      - name: Build and Test
        run: |
          cd $WORKSPACE
          make build
          make test
```

## Integration with Gerrit Workflow

This action is typically used in conjunction with:
- `gerrit-env-vars-restore` - Restores Gerrit environment variables from artifact
- `gerrit-env-vars-save` - Saves Gerrit environment variables to artifact

The typical workflow:
1. Gerrit trigger creates a workflow run
2. Environment variables are saved by the trigger workflow
3. Downstream workflows restore the variables
4. This action checks out the specific change
5. Build and test steps verify the change

## Error Handling

The action will fail if:
- The workspace directory doesn't exist
- The Git repository is not properly initialized
- The specified branch doesn't exist
- The Gerrit refspec is invalid or not accessible
- Network connectivity to Gerrit is unavailable

The action uses `set -euxo pipefail` to ensure any command failure stops execution immediately.

## Notes

- The action checks out a detached HEAD state (FETCH_HEAD)
- After checkout, the working directory is at the specific patchset being tested
- The `git show --stat` output provides a summary of the changes for logging purposes
- This action modifies the Git state of the repository in the workspace
