#!/usr/bin/env bash

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

# build-root isn't per Ubuntu version, only container builds write a stamp
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

# apt reads only the lowercase names
export http_proxy=${http_proxy:-$HTTP_PROXY}
export https_proxy=${https_proxy:-${HTTPS_PROXY:-$http_proxy}}
export no_proxy=${no_proxy:-$NO_PROXY}

# install-dep needs only the Makefile
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
# a worktree's git dir is outside the tree
if git_dir=$(git -C "$VPP_WS" rev-parse --git-common-dir 2>/dev/null); then
	git_dir=$(cd "$VPP_WS" && cd "$git_dir" && pwd -P)
	case "$git_dir" in
		"$VPP_WS"/*) ;;
		*) mounts+=(-v "$git_dir:$git_dir:ro") ;;
	esac
fi

echo "=== Building VPP ($target) on Ubuntu $UBUNTU_VERSION ==="
# tini passes ^C on to the whole build, whoami can't name the uid
docker run --rm --pull never \
	--init -e TINI_KILL_PROCESS_GROUP=1 \
	--user "$(id -u):$(id -g)" \
	-e VPP_BUILD_USER="$(id -un)" -e VPP_BUILD_HOST="$(hostname)" \
	"${mounts[@]}" \
	-w "$VPP_WS" \
	-e http_proxy -e https_proxy -e no_proxy \
	"$IMAGE" \
	make "$target"
