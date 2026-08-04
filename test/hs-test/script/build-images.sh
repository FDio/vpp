#!/usr/bin/env bash
# Build script for all Docker images based on the common base image

set -e

# Get default architecture for multi-arch builds
ARCH=${OS_ARCH:-$(dpkg --print-architecture)}

# We can't use lsb_release becuse host can be on different Ubuntu version
case $UBUNTU_VERSION in
    22.04 )
        CODENAME="jammy"
        ;;
    24.04 )
        CODENAME="noble"
        ;;
    26.04 )
        CODENAME="resolute"
        ;;
    * )
        echo "Error: unsupported Ubuntu version $UBUNTU_VERSION"
        exit 1
        ;;
esac

# Set up buildx configuration
DOCKER_BUILD_DIR="/scratch/docker-build"
DOCKER_CACHE_DIR="${DOCKER_BUILD_DIR}/docker_cache"
DOCKER_HST_BUILDER="hst_builder"
DOCKER_LOGIN_SCRIPT="/scratch/nomad/.docker-ro/dlogin.sh"

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

# IMAGE_TAG scopes every image this script produces to one test run, so that two
# checkouts building different VPP versions do not overwrite each other's images.
# Identical layers are still stored once by docker, so tagging per run costs build
# time rather than disk.
IMAGE_TAG=${IMAGE_TAG:-latest}

# Set the tag for the base image
BASE_TAG=${BASE_TAG:-"localhost:5001/vpp-test-base:$IMAGE_TAG"}

# Label used to find images this script created; see the prune step at the end.
HST_IMAGE_LABEL="io.fd.hs-test.image"

echo "=== Building base image ==="
# shellcheck disable=2086
docker buildx build ${DOCKER_CACHE_ARGS} \
  --build-arg UBUNTU_VERSION="${UBUNTU_VERSION:-22.04}" \
  --build-arg CODENAME="$CODENAME" \
  --build-arg http_proxy="$HTTP_PROXY" \
  --build-arg https_proxy="$HTTP_PROXY" \
  --build-arg HTTP_PROXY="$HTTP_PROXY" \
  --build-arg HTTPS_PROXY="$HTTP_PROXY" \
  --label "$HST_IMAGE_LABEL=1" \
  -t $BASE_TAG -f docker/Dockerfile.base . || {
    echo "Error: Failed to build base image"
    exit 1
}

# Push the base image to the local registry
docker push "$BASE_TAG" || {
    echo "Error: Failed to push base image to local registry"
    exit 1
}

# Function to build each image. The second argument is the repository; the run's
# IMAGE_TAG is appended here so that no call site has to remember it.
build_image() {
    local dockerfile="docker/$1"
    local tag="$2:$IMAGE_TAG"
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
        --build-arg GO_VERSION="$GO_VERSION" \
        --build-arg UBUNTU_VERSION="${UBUNTU_VERSION:-22.04}" \
        --build-arg OS_ARCH="$ARCH" \
        --build-arg CODENAME="$CODENAME" \
        --build-arg BASE_TAG="$BASE_TAG" \
        --build-arg http_proxy="$HTTP_PROXY" \
        --build-arg https_proxy="$HTTP_PROXY" \
        --build-arg HTTP_PROXY="$HTTP_PROXY" \
        --build-arg HTTPS_PROXY="$HTTP_PROXY" \
        --label "$HST_IMAGE_LABEL=1" \
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
build_image "Dockerfile.vpp" "hs-test/vpp"
build_image "Dockerfile.nginx" "hs-test/nginx-ldp"
build_image "Dockerfile.nginx-server" "hs-test/nginx-server"
build_image "Dockerfile.h2load" "hs-test/h2load"
build_image "Dockerfile.curl" "hs-test/curl"
build_image "Dockerfile.ab" "hs-test/ab"
build_image "Dockerfile.wrk" "hs-test/wrk"
build_image "Dockerfile.ginkgo" "hs-test/ginkgo"

# Build HTTP/3 nginx if available
echo "=== Building HTTP/3 nginx image ==="
build_image "Dockerfile.nginx-http3" "hs-test/nginx-http3"

# Build envoy separately since it doesn't use our base image
echo "=== Building envoy-test ==="
build_image "Dockerfile.envoy" "hs-test/envoy"

# make cache directory multi-user friendly if it exists
if [ -d "${DOCKER_CACHE_DIR}" ] ; then
  chgrp -R docker "${DOCKER_CACHE_DIR}" 2>/dev/null || true
  chmod -R g+rwx "${DOCKER_CACHE_DIR}" 2>/dev/null || true
fi

# Clean up images this script replaced. Restricted to images carrying our label:
# an unrestricted 'dangling=true' sweep removes every untagged image on the host,
# including ones belonging to other users and to concurrently running builds.
# Since images are tagged per run, an hs-test image only becomes dangling when the
# same run rebuilds it, so this no longer competes with another run's build.
images=$(docker images --filter "dangling=true" --filter "label=$HST_IMAGE_LABEL=1" -q --no-trunc)
if [ -n "$images" ]; then
    echo "=== Cleaning up replaced hs-test images ==="
    # shellcheck disable=SC2086
    docker rmi $images || true
fi

echo "=== All container images built successfully ==="
