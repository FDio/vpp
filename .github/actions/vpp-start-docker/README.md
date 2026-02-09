# VPP Start Docker Action

This GitHub Action starts the Docker daemon inside a docker-in-docker executor image.

## Description

This action locates and executes a Docker startup script to initialize the Docker daemon within a containerized environment. It's designed to work with docker-in-docker (d-in-d) executor images where Docker needs to be manually started.

## Inputs

### `START_DOCKER_SCRIPT`

**Description:** Name of the docker script file

**Required:** No

**Default:** `start-docker.sh`

**Type:** string

### `TUI_LINE`

**Description:** Delimiter line for TUI output

**Required:** No

**Default:** `*******************************************************************`

**Type:** string

## Usage

```yaml
- name: Start Docker Daemon
  uses: fdio/vpp/.github/actions/vpp-start-docker@master
  with:
    START_DOCKER_SCRIPT: start-docker.sh
    TUI_LINE: ${{ env.TUI_LINE }}
```

### Minimal Example

```yaml
- name: Start Docker Daemon
  uses: fdio/vpp/.github/actions/vpp-start-docker@master
```

## How It Works

1. The action checks if the specified script exists on the system PATH using `which`
2. If found, it displays the script content for debugging purposes
3. Executes the script to start the Docker daemon
4. If the script is not found, it exits with error code 1

## Prerequisites

- The Docker startup script must be available on the system PATH
- The executor environment must support docker-in-docker functionality
- Appropriate permissions to start the Docker daemon

## Error Handling

The action will fail if:
- The specified startup script is not found on PATH
- The startup script execution fails

## Example Workflow

```yaml
jobs:
  build:
    runs-on: self-hosted
    steps:
      - name: Setup Docker Runtime Environment
        uses: fdio/vpp/.github/actions/vpp-docker-runtime-setup@master
        with:
          WORKSPACE: ${{ env.WORKSPACE }}
          SHM_SIZE: 2048M

      - name: Start Docker Daemon
        uses: fdio/vpp/.github/actions/vpp-start-docker@master
        with:
          START_DOCKER_SCRIPT: start-docker.sh

      - name: Run Tests
        if: success()
        run: |
          docker ps
          # Your test commands here
```

## Notes

- This action is typically used in conjunction with `vpp-docker-runtime-setup` action
- The Docker daemon must be started before running any Docker commands in subsequent steps
- Use `if: success()` on subsequent steps to skip them if Docker startup fails
