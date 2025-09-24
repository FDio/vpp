#!/bin/bash
# Script to set up a local Docker registry
NO_REGISTRY=${NO_REGISTRY:-"false"}
set -e

DOCKER_LOGIN_SCRIPT="/scratch/nomad/.docker-ro/dlogin.sh"
if [ -x "$DOCKER_LOGIN_SCRIPT" ] ; then
  $DOCKER_LOGIN_SCRIPT
fi

# Check if Docker is running
if ! docker info &>/dev/null; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Registry container name
REGISTRY_NAME="local-registry"
REGISTRY_PORT=${1:-5001}

if [ "$NO_REGISTRY" = "true" ]; then
    echo "NO_REGISTRY=true -> not setting up a registry."
    exit 0
fi
# Check if registry container is already running
if docker container inspect "$REGISTRY_NAME" &>/dev/null; then
    echo "=== Local registry '$REGISTRY_NAME' is already running ==="
    REGISTRY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$REGISTRY_NAME")
    echo "Registry is available at: localhost:$REGISTRY_PORT or $REGISTRY_IP:$REGISTRY_PORT"
else
    echo "=== Setting up local Docker registry ==="

    # Create a new registry container
    docker run -d \
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
