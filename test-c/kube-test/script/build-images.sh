#!/usr/bin/env bash
# Build script for all Docker images based on the common base image

set -e

# Get default architecture for multi-arch builds
ARCH=${OS_ARCH:-$(dpkg --print-architecture)}
CODENAME=$(lsb_release -cs)

# Set up buildx configuration
DOCKER_BUILD_DIR="/scratch/docker-build"
DOCKER_CACHE_DIR="${DOCKER_BUILD_DIR}/docker_cache"
DOCKER_HST_BUILDER="hst_builder"
DOCKER_LOGIN_SCRIPT="/scratch/nomad/.docker-ro/dlogin.sh"
NO_REGISTRY=${NO_REGISTRY:-"false"}

if [ -d "${DOCKER_BUILD_DIR}" ] ; then
  mkdir -p "${DOCKER_CACHE_DIR}"

  if [ -x "$DOCKER_LOGIN_SCRIPT" ] ; then
    $DOCKER_LOGIN_SCRIPT
  fi

  # Create buildx builder if it doesn't exist
  if ! docker buildx ls --format "{{.Name}}" | grep -q "${DOCKER_HST_BUILDER}"; then
    docker buildx create --use \
      --driver-opt env.http_proxy="$HTTP_PROXY" \
      --driver-opt env.https_proxy="$HTTP_PROXY" \
      --driver-opt '"env.no_proxy='"$NO_PROXY"'"' \
      --name=${DOCKER_HST_BUILDER} \
      --driver=docker-container \
      --use --bootstrap || true
  fi

  DOCKER_CACHE_ARGS="--builder=${DOCKER_HST_BUILDER} --load --cache-to type=local,dest=${DOCKER_CACHE_DIR},mode=max --cache-from type=local,src=${DOCKER_CACHE_DIR}"
fi

# Set the tag for the base image
BASE_TAG=${BASE_TAG:-"localhost:5001/vpp-kube-base:latest"}

echo "=== Building base image ==="
# shellcheck disable=2086
docker buildx build ${DOCKER_CACHE_ARGS} \
  --build-arg UBUNTU_VERSION="${UBUNTU_VERSION:-22.04}" \
  --build-arg http_proxy="$HTTP_PROXY" \
  --build-arg https_proxy="$HTTP_PROXY" \
  --build-arg HTTP_PROXY="$HTTP_PROXY" \
  --build-arg HTTPS_PROXY="$HTTP_PROXY" \
  -t $BASE_TAG -f docker/Dockerfile.base . || {
    echo "Error: Failed to build base image"
    exit 1
}

if [ "$NO_REGISTRY" = "true" ]; then
  set -x
  docker image tag $BASE_TAG kube-test/vpp:latest
  set +x
else
  # Push the base image to the local registry
  docker push $BASE_TAG || {
      echo "Error: Failed to push base image to local registry"
      exit 1
}
fi

# Function to build each image
build_image() {
    local dockerfile="docker/$1"
    local tag=$2
    local add_args="${3:-}"

    if [ ! -f "$dockerfile" ]; then
        echo "Warning: Dockerfile $dockerfile doesn't exist, skipping"
        return 0
    fi

    echo "=== Building $tag from $dockerfile ==="
    echo "Building with architecture: $ARCH"

    # Check if the necessary files for VPP-based images are available
    if [[ "$dockerfile" == *"vpp"* || "$dockerfile" == *"nginx"* || "$dockerfile" == *"vcl"* ]]; then
        # Check for essential VPP files
        for file in vpp-data/bin/vpp vpp-data/lib/*.so; do
            if [ ! -e "$file" ]; then
                echo "Warning: Required VPP file $file doesn't exist."
            fi
        done
    fi

    # Build the image
    # shellcheck disable=2086
    docker build \
        --build-arg UBUNTU_VERSION="${UBUNTU_VERSION:-22.04}" \
        --build-arg OS_ARCH="$ARCH" \
        --build-arg CODENAME="$CODENAME" \
        --build-arg http_proxy="$HTTP_PROXY" \
        --build-arg https_proxy="$HTTP_PROXY" \
        --build-arg HTTP_PROXY="$HTTP_PROXY" \
        --build-arg HTTPS_PROXY="$HTTP_PROXY" \
        $add_args \
        -t "$tag" \
        -f "$dockerfile" . || {
            echo "Error: Failed to build $tag"
            return 1
        }

    echo "=== Successfully built and pushed $tag ==="
}

# Build all standard images
echo "=== Building standard images ==="
build_image "Dockerfile.vpp" "kube-test/vpp"
build_image "Dockerfile.nginx" "kube-test/nginx-ldp"
build_image "Dockerfile.ab" "kube-test/ab"
build_image "Dockerfile.wrk" "kube-test/wrk"

# make cache directory multi-user friendly if it exists
if [ -d "${DOCKER_CACHE_DIR}" ] ; then
  chgrp -R docker "${DOCKER_CACHE_DIR}" 2>/dev/null || true
  chmod -R g+rwx "${DOCKER_CACHE_DIR}" 2>/dev/null || true
fi

# cleanup detached images
images=$(docker images --filter "dangling=true" -q --no-trunc)
if [ -n "$images" ]; then
    echo "=== Cleaning up dangling images ==="
    # shellcheck disable=SC2086
    docker rmi $images || true
fi

echo "=== All container images built successfully ==="
