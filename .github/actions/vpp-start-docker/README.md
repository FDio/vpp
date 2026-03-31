# 🛠️ VPP Start Docker Action

Finds a startup script on `PATH`, prints it, and executes it.

## Inputs

| Input | Required | Default | Notes |
| --- | --- | --- | --- |
| `START_DOCKER_SCRIPT` | No | `start-docker.sh` | Script name resolved with `which` |
| `TUI_LINE` | No | `*******************************************************************` | Accepted for interface consistency; not used by the current script |

## What It Runs

```bash
if [ -n "$(which $START_DOCKER_SCRIPT)" ] ; then
  cat "$(which $START_DOCKER_SCRIPT)"
  $START_DOCKER_SCRIPT
else
  echo "Docker startup script not found on PATH: $START_DOCKER_SCRIPT"
  exit 1
fi
```

## Usage

```yaml
- name: Start docker daemon
  uses: ./.github/actions/vpp-start-docker
  with:
    START_DOCKER_SCRIPT: start-docker.sh
```

