#!/bin/bash
set -eux
GO_TARBALL=go${GO_VERSION}.linux-${TARGETARCH}.tar.gz
GO_TARBALL_PATH=/var/cache/downloads/"$GO_TARBALL"
if [ ! -s "$GO_TARBALL_PATH" ] || ! tar -tzf "$GO_TARBALL_PATH" >/dev/null 2>&1; then
  GO_DOWNLOAD_TMP=$(mktemp "${GO_TARBALL_PATH}.tmp.XXXXXX")
  trap 'rm -f "$GO_DOWNLOAD_TMP"' EXIT
  wget -t 2 https://go.dev/dl/"$GO_TARBALL" -O "$GO_DOWNLOAD_TMP"
  tar -tzf "$GO_DOWNLOAD_TMP" >/dev/null
  mv "$GO_DOWNLOAD_TMP" "$GO_TARBALL_PATH"
  trap - EXIT
fi
tar -xzf "$GO_TARBALL_PATH" -C /usr/local
ln -s /usr/local/go/bin/go /usr/bin/go
