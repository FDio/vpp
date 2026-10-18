# Restore HST Images and Caches

Loads baked HST container images and restores their BuildKit cache mounts by
calling the executor image's `hst_cache.sh restore BRANCH`. Only HST workflows should
call this action, after starting Docker and before building HST containers.

## Usage

```yaml
- name: Restore baked HST images and caches
  uses: ./.github/actions/vpp-hst-cache
  with:
    BRANCH: ${{ env.GERRIT_BRANCH }}
```

`BRANCH` defaults to `master`, as used by periodic workflows. Verify workflows
pass their target Gerrit branch. Only that branch's image archive and cache
mount snapshot are restored; registry and BuildKit images are shared.
Branches without a baked archive build images normally. Branches without
Dockerfile cache mounts load their image archive without restoring mount data.

Check out the VPP repository before using this local action. Docker must already
be running. The helper is located under
`${DOT_GITHUB_ROOT:-/scratch/docker-build/.github}/docker/scripts` in the executor.
Executors without the helper skip restoration and build HST images normally.
Errors loading available images or restoring caches fail the action.
