#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

version=$1
arch=$2
package=$3
installed_version=$4

branch=${GERRIT_BRANCH:-master}
stream=${branch#stable/}
revision=$(git rev-parse HEAD)
stamp=$(git rev-parse --git-path vpp-ext-deps-ci-installed)

if [[ "$installed_version" == "$version" && -f "$stamp" ]] &&
    [[ $(cat "$stamp") == "$revision $version" ]]; then
    echo "vpp-ext-deps $version already built from this checkout"
    exit 0
fi

# Unmerged changes can have the same package version as a different change
# merged after their base. Reuse is safe when the recipes match the base.
matches_branch()
{
    local base changes

    base=$(git merge-base HEAD "$1") &&
        changes=$(git rev-list -1 "$base..HEAD" -- . ../build_common.mk ../packages_common.mk) &&
        [[ -z "$changes" ]]
}

if [[ ${GERRIT_REFSPEC:-} != "refs/heads/$branch" ]] &&
    ! matches_branch "refs/remotes/origin/$branch"; then
    if ! git fetch --quiet --no-tags origin "refs/heads/$branch" ||
        ! matches_branch FETCH_HEAD; then
        echo "Using local vpp-ext-deps build for this checkout"
        exit 1
    fi
fi

if [[ "$installed_version" == "$version" ]]; then
    echo "vpp-ext-deps $version already installed"
    exit 0
fi

# Use a job-local APT source and lists so older runner images can find newly
# published distributions and repository failures leave normal APT alone.
. /etc/os-release
case "$ID" in
    debian|ubuntu) ;;
    *) exit 1 ;;
esac
if [[ ! "$stream" =~ ^[a-zA-Z0-9._-]+$ || ! "$VERSION_CODENAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    exit 1
fi

apt_dir=$(mktemp -d)
trap 'rm -rf -- "$apt_dir"' EXIT
chmod 755 "$apt_dir"
repo="https://packagecloud.io/fdio/$stream"
keyring="$apt_dir/fdio.gpg"
curl --fail --silent --show-error --location --connect-timeout 5 --max-time 15 "$repo/gpgkey" |
    gpg --batch --dearmor -o "$keyring"
chmod 644 "$keyring"
printf 'deb [arch=%s signed-by=%s] %s/%s/ %s main\n' \
    "$arch" "$keyring" "$repo" "$ID" "$VERSION_CODENAME" > "$apt_dir/sources.list"

apt_options=(
    -o "Dir::Etc::sourcelist=$apt_dir/sources.list"
    -o 'Dir::Etc::sourceparts=-'
    -o "Dir::State::lists=$apt_dir/lists"
    -o 'Dir::Cache::pkgcache='
    -o 'Dir::Cache::srcpkgcache='
    -o 'APT::Update::Error-Mode=any'
    -o 'Acquire::Retries=1'
    -o 'Acquire::https::Timeout=10'
)
mkdir "$apt_dir/lists"
apt-get "${apt_options[@]}" update -qq
(
    cd "$apt_dir"
    apt-get "${apt_options[@]}" download "vpp-ext-deps:$arch=$version"
)
sudo dpkg -i "$apt_dir/$package"
