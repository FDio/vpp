#!/usr/bin/env bash
# Builds VPP for UBUNTU_VERSION. The test images are built FROM
# ubuntu:${UBUNTU_VERSION} and the VPP binaries are copied into them, so a
# version other than the host's has to be built in a container of that version.

set -e

target=$1
case "$target" in
	build)         build_dir=build-vpp_debug-native ;;
	build-release) build_dir=build-vpp-native ;;
	build-gcov)    build_dir=build-vpp_gcov-native ;;
	* )
		echo "usage: $0 <build|build-release|build-gcov>"
		exit 1
		;;
esac

HS_ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
VPP_WS=$(cd "$HS_ROOT/../.." && pwd -P)
HOST_UBUNTU_VERSION=$(. /etc/os-release && echo "$VERSION_ID")
UBUNTU_VERSION=${UBUNTU_VERSION:-$HOST_UBUNTU_VERSION}
build_path="$VPP_WS/build-root/$build_dir"
stamp="$build_path/.hst_ubuntu_version"

# build-root is not keyed by Ubuntu version, objects left there by a build for
# another one would end up linked into this one. Only container builds leave a
# stamp.
if [ -d "$build_path" ]; then
	recorded=$HOST_UBUNTU_VERSION
	if [ -f "$stamp" ]; then
		recorded=$(cat "$stamp")
	fi
	if [ "$recorded" != "$UBUNTU_VERSION" ]; then
		echo "$build_dir holds an Ubuntu $recorded build, $UBUNTU_VERSION was requested"
		echo "run 'rm -rf $build_path $VPP_WS/build-root/install-${build_dir#build-}' first"
		exit 1
	fi
fi

if [ "$UBUNTU_VERSION" = "$HOST_UBUNTU_VERSION" ]; then
	exec "${MAKE:-make}" -C "$VPP_WS" "$target"
fi

IMAGE="hs-test/vpp-build:$UBUNTU_VERSION"

# apt reads only the lowercase names, curl ignores HTTP_PROXY. As in
# build-images.sh, https goes through the http proxy when no https one is set.
export http_proxy=${http_proxy:-$HTTP_PROXY}
export https_proxy=${https_proxy:-${HTTPS_PROXY:-$http_proxy}}
export no_proxy=${no_proxy:-$NO_PROXY}

# only the Makefile is needed, it defines DEB_DEPENDS and has no includes
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
cp "$VPP_WS/Makefile" "$ctx/"

echo "=== Building $IMAGE ==="
docker build \
	--build-arg UBUNTU_VERSION="$UBUNTU_VERSION" \
	--build-arg http_proxy --build-arg https_proxy --build-arg no_proxy \
	--label io.fd.hs-test.image=1 \
	-t "$IMAGE" -f "$HS_ROOT/docker/Dockerfile.vpp-build" "$ctx"

mkdir -p "$build_path"
echo "$UBUNTU_VERSION" > "$stamp"

mounts=(-v "$VPP_WS:$VPP_WS")
# the build takes the VPP version from git, a worktree's git dir is outside the tree
if git_dir=$(git -C "$VPP_WS" rev-parse --git-common-dir 2>/dev/null); then
	git_dir=$(cd "$VPP_WS" && cd "$git_dir" && pwd -P)
	case "$git_dir" in
		"$VPP_WS"/*) ;;
		*) mounts+=(-v "$git_dir:$git_dir:ro") ;;
	esac
fi

echo "=== Building VPP ($target) on Ubuntu $UBUNTU_VERSION ==="
# with no vpp-ext-deps installed, the build compiles the external deps into
# build-root. docker signals only PID 1, tini passes ^C on to the whole build.
# whoami has no name for the uid in the image.
docker run --rm --pull never \
	--init -e TINI_KILL_PROCESS_GROUP=1 \
	--user "$(id -u):$(id -g)" \
	-e VPP_BUILD_USER="$(id -un)" -e VPP_BUILD_HOST="$(hostname)" \
	"${mounts[@]}" \
	-w "$VPP_WS" \
	-e http_proxy -e https_proxy -e no_proxy \
	"$IMAGE" \
	make "$target"
