#!/bin/bash
set -eux
GO_TARBALL=go${GO_VERSION}.linux-${TARGETARCH}.tar.gz
GO_TARBALL_PATH=/var/cache/downloads/"$GO_TARBALL"
if [ ! -s "$GO_TARBALL_PATH" ] ; then
  wget -t 2 https://go.dev/dl/"$GO_TARBALL" -O "$GO_TARBALL_PATH"
fi
tar -xzf "$GO_TARBALL_PATH" -C /usr/local
ln -s /usr/local/go/bin/go /usr/bin/go
