#!/bin/bash
# Script to set up a local Docker registry

set -e

DOCKER_LOGIN_SCRIPT="/scratch/nomad/.docker-ro/dlogin.sh"
if [ -x "$DOCKER_LOGIN_SCRIPT" ] ; then
  $DOCKER_LOGIN_SCRIPT
fi

function wait_for_process () {
    local max_time_wait=30
    local process_name="$1"
    local waited_sec=0
    while ! pgrep "$process_name" >/dev/null && ((waited_sec < max_time_wait)); do
        echo "Process $process_name is not running yet. Retrying in 1 seconds"
        echo "Waited $waited_sec seconds of $max_time_wait seconds"
        sleep 1
        ((waited_sec=waited_sec+1))
        if ((waited_sec >= max_time_wait)); then
            return 1
        fi
    done
    return 0
}

# Check if Docker is running
START_DOCKER_SCRIPT="start-docker.sh"
if ! DOCKER_INFO=$(docker info 2>&1); then
    echo "dockerd is not running"
    echo "$DOCKER_INFO"
    # We can't use systemd in d-in-d executor image
    if [ -n "$(which "$START_DOCKER_SCRIPT")" ] ; then
        echo "Starting dockerd with '$START_DOCKER_SCRIPT'"
        $START_DOCKER_SCRIPT
    else
        echo "Starting dockerd with systemd"
        if ! sudo systemctl start docker; then
            echo "Error: failed to start dockerd."
            exit 1
        fi
    fi
    echo "Waiting for dockerd to be running"
    if ! wait_for_process dockerd; then
        echo "dockerd is not running after max time"
        exit 1
    else
        echo "dockerd is running"
        if ! DOCKER_INFO=$(docker info 2>&1); then
            echo "Error: docker info failed."
            echo "$DOCKER_INFO"
            ls -la /var/run/docker.sock
            exit 1
        fi
    fi
fi

# Registry container name
REGISTRY_NAME="local-registry"
REGISTRY_PORT=${1:-5001}

# Check if registry container is already running
if docker container inspect "$REGISTRY_NAME" &>/dev/null; then
    echo "=== Local registry '$REGISTRY_NAME' is already running ==="
    REGISTRY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$REGISTRY_NAME")
    echo "Registry is available at: localhost:$REGISTRY_PORT or $REGISTRY_IP:$REGISTRY_PORT"
else
    echo "=== Setting up local Docker registry ==="

    # Create a new registry container
    docker run -d \
        -e REGISTRY_STORAGE_DELETE_ENABLED=true \
        --name "$REGISTRY_NAME" \
        --restart=always \
        -p "$REGISTRY_PORT:5000" \
        -v /var/lib/registry:/var/lib/registry \
        registry:2

    REGISTRY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$REGISTRY_NAME")
    echo "Registry container created successfully!"
    echo "Registry is available at: localhost:$REGISTRY_PORT or $REGISTRY_IP:$REGISTRY_PORT"

    # Configure Docker to trust this insecure registry
    echo "=== Configuring Docker to trust insecure registry ==="
    if [ -f /etc/docker/daemon.json ]; then
        # Check if the file already has an insecure-registries entry
        if grep -q "insecure-registries" /etc/docker/daemon.json; then
            echo "Insecure registries already configured. Please make sure 'localhost:$REGISTRY_PORT' is included."
        else
            echo "Adding 'localhost:$REGISTRY_PORT' to insecure-registries in /etc/docker/daemon.json"
            echo "You may need to restart Docker for changes to take effect"
            echo "Please add the following to /etc/docker/daemon.json:"
            echo "{
  \"insecure-registries\": [\"localhost:$REGISTRY_PORT\"]
}"
        fi
    else
        echo "Creating /etc/docker/daemon.json with insecure-registries configuration"
        echo "You may need to restart Docker for changes to take effect"
        echo "Please create /etc/docker/daemon.json with the following content:"
        echo "{
  \"insecure-registries\": [\"localhost:$REGISTRY_PORT\"]
}"
    fi
fi

echo ""
echo "=== Local Registry Setup Complete ==="
echo "To use the local registry, prefix your image tags with 'localhost:$REGISTRY_PORT/'"
echo "For example: localhost:$REGISTRY_PORT/hs-test/vpp:latest"
