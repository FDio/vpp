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

# IMAGE_TAG scopes every image to one test run, so two checkouts building different
# VPP versions do not overwrite each other's. Docker stores identical layers once,
# so this costs build time rather than disk.
IMAGE_TAG=${IMAGE_TAG:-latest}

# Limit concurrent image builds to avoid overwhelming the host. Set
# HS_TEST_BUILD_JOBS to override this (for example, to 1 for serial builds).
BUILD_JOBS=${HS_TEST_BUILD_JOBS:-4}
if ! [[ "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: HS_TEST_BUILD_JOBS must be a positive integer"
    exit 1
fi

# Set the tag for the base image
BASE_TAG=${BASE_TAG:-"localhost:5001/vpp-test-base:$IMAGE_TAG"}

# marks the images this script created; used by the prune step below
HST_IMAGE_LABEL="io.fd.hs-test.image"

echo "=== Building base image ==="
# shellcheck disable=2086
DOCKER_BUILDKIT=1 docker buildx build ${DOCKER_CACHE_ARGS} \
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

# the run's IMAGE_TAG is appended here, so no call site has to remember it
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
    DOCKER_BUILDKIT=1 docker build \
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

# All remaining image builds are independent now that the base image is
# available. Run a bounded number at a time and wait for every build before
# cleanup, even when one of them fails.
echo "=== Building test images (up to $BUILD_JOBS in parallel) ==="
image_dockerfiles=(
    "Dockerfile.vpp"
    "Dockerfile.nginx"
    "Dockerfile.nginx-server"
    "Dockerfile.h2load"
    "Dockerfile.curl"
    "Dockerfile.ab"
    "Dockerfile.wrk"
    "Dockerfile.ginkgo"
    "Dockerfile.nginx-http3"
    "Dockerfile.envoy"
)
image_names=(
    "hs-test/vpp"
    "hs-test/nginx-ldp"
    "hs-test/nginx-server"
    "hs-test/h2load"
    "hs-test/curl"
    "hs-test/ab"
    "hs-test/wrk"
    "hs-test/ginkgo"
    "hs-test/nginx-http3"
    "hs-test/envoy"
)

active_builds=0
build_status=0
for i in "${!image_dockerfiles[@]}"; do
    build_image "${image_dockerfiles[$i]}" "${image_names[$i]}" &
    active_builds=$((active_builds + 1))

    if (( active_builds >= BUILD_JOBS )); then
        if ! wait -n; then
            build_status=1
        fi
        active_builds=$((active_builds - 1))
    fi
done

while (( active_builds > 0 )); do
    if ! wait -n; then
        build_status=1
    fi
    active_builds=$((active_builds - 1))
done

if (( build_status != 0 )); then
    echo "Error: One or more test image builds failed"
    exit 1
fi

# make cache directory multi-user friendly if it exists
if [ -d "${DOCKER_CACHE_DIR}" ] ; then
  chgrp -R docker "${DOCKER_CACHE_DIR}" 2>/dev/null || true
  chmod -R g+rwx "${DOCKER_CACHE_DIR}" 2>/dev/null || true
fi

# restricted to our label: an unrestricted 'dangling=true' sweep removes every
# untagged image on the host, including other users' and concurrent builds'
images=$(docker images --filter "dangling=true" --filter "label=$HST_IMAGE_LABEL=1" -q --no-trunc)
if [ -n "$images" ]; then
    echo "=== Cleaning up replaced hs-test images ==="
    # shellcheck disable=SC2086
    docker rmi $images || true
fi

echo "=== All container images built successfully ==="
