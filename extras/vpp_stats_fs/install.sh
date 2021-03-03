#!/bin/bash

# A simple script that installs stats_fs, a Fuse file system
# for the stats segment

set -eo pipefail

OPT_ARG=${1:-}

STATS_FS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPP_DIR=$(pwd)/
BUILD_ROOT=${VPP_DIR}build-root/
BINARY_DIR=${BUILD_ROOT}install-vpp-native/vpp/bin/
RUN_DIR=/run/vpp/

GOROOT=${GOROOT:-}
GOPATH=${GOPATH:-}

[ -z "${GOROOT}" ] && GOROOT="${HOME}/.go" && PATH=$GOROOT/bin:$PATH
[ -z "${GOPATH}" ] && GOPATH="${HOME}/go"  && PATH=$GOPATH/bin:$PATH

function install_dep() {
  echo "Installing stats_fs dependencies"
  apt-get update
  apt-get install git wget curl -y
}

# Install latest GO version
function install_go() {
  local TMP="/tmp"

  echo "Installing latest GO"
  if [[ -x "$(command -v go)" ]]; then
    local installed_ver installed_ver_fmt
    installed_ver=$(go version)
    installed_ver_fmt=${installed_ver#"go version go"}
    echo "Found installed version ${installed_ver_fmt}"
    return
  fi

  mkdir -p "${GOROOT}"
  mkdir -p "${GOPATH}/"{src,pkg,bin}

  wget "https://dl.google.com/go/$(curl https://golang.org/VERSION?m=text).linux-amd64.tar.gz" -O "${TMP}/go.tar.gz"
  tar -C "$GOROOT" --strip-components=1 -xzf "${TMP}/go.tar.gz"

  rm -f "${TMP}/go.tar.gz"

  # export path for current session to install vpp_stast_fs
  export GOROOT=${GOROOT}
  export PATH=$GOROOT/bin:$PATH
  export GOPATH=$GOPATH
  export PATH=$GOPATH/bin:$PATH

  echo "Installed $(go version)"
}

function install_go_dep() {
  echo "Installing Go dependencies"
  if [[ ! -x "$(command -v go)" ]]; then
    echo "GO is not installed"
    exit 1
  fi

  if [ ! -e "go.mod" ]; then
    go mod init stats_fs
  fi
  # master required
  go get git.fd.io/govpp.git@master
  go get git.fd.io/govpp.git/adapter/statsclient@master
  go get github.com/hanwen/go-fuse/v2
}

# Resolve stats_fs dependencies and builds the binary
function build_statfs() {
  echo "Installing statfs"
  go build
  if [ -d "${BINARY_DIR}" ]; then
    mv stats_fs "${BINARY_DIR}"/stats_fs
  else
    echo "${BINARY_DIR} directory does not exist, the binary is installed at ${STATS_FS_DIR}/stats_fs instead"
  fi
}

function install_statfs() {
  if [[ ! -x "$(command -v go)" ]]; then
    install_dep
    install_go
  fi

  if [ ! -d "${STATS_FS_DIR}" ]; then
    echo "${STATS_FS_DIR} directory does not exist"
    exit 1
  fi
  cd "${STATS_FS_DIR}"

  if [[ ! -x "$(command -v $STATS_FS_DIR/stats_fs)" ]]; then
    install_go_dep
    build_statfs
  else
    echo "stats_fs already installed at path $STATS_FS_DIR/stats_fs"
  fi
}

# Starts the statfs binary
function start_statfs() {
  EXE_DIR=$BINARY_DIR
  if [ ! -d "${EXE_DIR}" ]; then
    echo "${EXE_DIR}"
    EXE_DIR=$STATS_FS_DIR
  fi

  mountpoint="${RUN_DIR}stats_fs_dir"

  if [[ -x "$(command -v ${EXE_DIR}/stats_fs)" ]] ; then
    if [ ! -d "$mountpoint" ] ; then
      mkdir "$mountpoint"
    fi
    "${EXE_DIR}"stats_fs $mountpoint
    return
  fi

  echo "stats_fs is not installed, use 'make stats-fs-install' first"
}

function unmount() {
  if (( $(mount | grep "${RUN_DIR}stats_fs_dir" | wc -l) == 1 )) ; then
    fusermount -uz "${RUN_DIR}stats_fs_dir"
  else
    echo "The default directory ${RUN_DIR}stats_fs_dir is not mounted."
  fi

  if [ -d "${RUN_DIR}stats_fs_dir" ] ; then
    rm -df "${RUN_DIR}stats_fs_dir"
  fi
}

# Remove stats_fs Go module
function cleanup() {
  echo "Cleaning up stats_fs"
  if [ ! -d "${STATS_FS_DIR}" ]; then
    echo "${STATS_FS_DIR} directory does not exist"
    exit 1
  fi

  cd "${STATS_FS_DIR}"

  if [ -e "go.mod" ]; then
    rm -f go.mod
  fi
  if [ -e "go.sum" ]; then
    rm -f go.sum
  fi
  if [ -e "stats_fs" ]; then
    rm -f stats_fs
  fi

  if [ -d "${BINARY_DIR}" ]; then
    if [ -e "${BINARY_DIR}stats_fs" ]; then
      rm -f ${BINARY_DIR}stats_fs
    fi
  fi

  if [ -d "${RUN_DIR}stats_fs_dir" ] ; then
    rm -df "${RUN_DIR}stats_fs_dir"
  fi
}

# Show available commands
function help() {
  cat <<__EOF__
  Stats_fs installer

  <install>:
  Installs stats_fs requirements (latest GO, GoVPP stats client, GoFuse),
  builds the stats_fs binary.

  <start>:
  Launches the stats_fs binary and creates a mountpoint.
  Requires privilege user rights.

  <cleanup>:
  Removes stats_fs binary and deletes go module.
  You still have to unmount the fs with the command `sudo fusermount -uz <mountpoint>`

  <unmount>:
  Unmount the file system if exists and removes the mountpoint directory.
  Requires privileged user rights.

__EOF__
}

# Resolve chosen option and call appropriate functions
function resolve_option() {
  local option=$1
  case ${option} in
  "start")
    start_statfs
    ;;
  "install")
    install_statfs
    ;;
  "cleanup")
    cleanup
    ;;
  "unmount")
    unmount
    ;;
  "help")
    help
    ;;
  *) echo invalid option ;;
  esac
}

if [[ -n ${OPT_ARG} ]]; then
  resolve_option "${OPT_ARG}"
else
  PS3="--> "
  options=("install" "cleanup" "help" "start" "unmount")
  select option in "${options[@]}"; do
    resolve_option "${option}"
    break
  done
fi
