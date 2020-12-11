#!/bin/bash

# A simple script that installs VPPTop utility including
# all requirements. The binary API is built from the local
# vpp data. 'make install-dep' is recommended to call first.

set -eo pipefail

OPT_ARG=${1:-}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"/../../
BUILD_ROOT=$(pwd)/build-root
VPPTOP_DIR=${BUILD_ROOT}/vpptop

GOROOT=${GOROOT:-}
GOPATH=${GOPATH:-}

[ -z "${GOROOT}" ] && GOROOT="${HOME}/.go"
[ -z "${GOPATH}" ] && GOPATH="${HOME}/go"

function dep_install() {
  echo "Installing VPPTop dependencies"
  apt-get update
  apt-get install git wget curl -y
}

# Install latest GO version
function go_install() {
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

  # export for current session so the VPPTop can be installed
  export GOROOT=${GOROOT}
  export PATH=$GOROOT/bin:$PATH
  export GOPATH=$GOPATH
  export PATH=$GOPATH/bin:$PATH

  echo "Installed $(go version)"
}

# Install GoVPP binary API generator. GoLang required
# to be installed in version 1.13 or higher
function install_binapi_gen() {
  echo "Installing GoVPP binary API generator"
  if [[ ! -x "$(command -v go)" ]]; then
    echo "GO is not installed"
    exit 1
  fi

  # master required for latest VPPTop
  export GO111MODULE=on
  go get git.fd.io/govpp.git/cmd/binapi-generator@master

  local installed_ver installed_ver_fmt
  installed_ver=$(binapi-generator -version)
  installed_ver_fmt=${installed_ver#"govpp "}
  echo "Binary API generator ${installed_ver_fmt} installed"
}

# Generate binary API files in the VPPTop directory using
# the local VPP sources
function generate_binary_api() {
  local api_dir=${BUILD_ROOT}/install-vpp-native/vpp/share/vpp/api
  local out_dir=${VPPTOP_DIR}/stats/local/binapi

  if [[ ! -x "$(command -v binapi-generator)" ]]; then
    install_binapi_gen
  fi
  if [ ! -d "${VPPTOP_DIR}" ]; then
    echo "VPPTop directory does not exist"
    exit 1
  elif [ ! -d "${out_dir}" ]; then
    mkdir -p "${out_dir}"
  fi
  if [ ! -d "${api_dir}" ]; then
    echo "JSON API files missing, call 'make json-api-files' first"
    exit 1
  fi

  echo "Generating API"
  binapi-generator --output-dir="${out_dir}" -input-dir="${api_dir}" \
    "${api_dir}"/plugins/dhcp.api.json \
    "${api_dir}"/core/interface.api.json \
    "${api_dir}"/core/ip.api.json \
    "${api_dir}"/core/vpe.api.json
}

# Retrieve VPPTop repository
function get_vpptop() {
  echo "Fetching VPPTop"
  if [ ! -d "${VPPTOP_DIR}" ]; then
    cd "${BUILD_ROOT}" && git clone https://github.com/PANTHEONtech/vpptop.git
  else
    echo "VPPTop directory already exists"
  fi
}

# Resolve VPPTop dependencies and install the binary
function vpptop_install() {
  get_vpptop
  generate_binary_api

  echo "Installing VPPTop"
  if [ ! -d "${VPPTOP_DIR}" ]; then
    echo "VPPTop directory does not exist"
    exit 1
  fi
  cd "${VPPTOP_DIR}" && go mod download
  cd "${VPPTOP_DIR}" && make install

  if [[ ! -x "$(command -v vpptop)" ]] && [[ ! -f "${GOPATH}/bin/vpptop" ]] ; then
    echo "VPPTop was not successfully installed"
    exit 1
  fi
  if [[ ! -x "$(command -v vpptop)" ]] ; then
    echo "VPPTop was installed to ${GOPATH}/bin/vpptop"
  fi

  echo "------"
  vpptop --help

  echo "NOTE: if GOPATH is not set, the VPPTop can be started from directly the default one (HOME/go)"
  echo "Done"
}

# Starts the vpptop binary
function vpptop_start() {
  if [[ -x "$(command -v vpptop)" ]] ; then
    vpptop ${args}
    return
  fi
  if [[ -f "${GOPATH}/bin/vpptop"  ]] ; then
    cd ${GOPATH}/bin && ./vpptop
    return
  fi

  echo "VPPTop is not installed, use 'make vpptop-install' first"
}

# Remove VPPTop repository brom build-root
function cleanup() {
  echo "Cleaning up VPPTop"
  rm -rf "${VPPTOP_DIR}"
}

# Show available commands
function help() {
  cat <<__EOF__
  VPPTop installer

  Run 'make install-dep' before the installation

  <install>:
  Installs VPPTop requirements (latest GO, GoVPP binary API generator),
  retrieves VPPTop repository, generates binary API and installs the
  VPPTop binary.

  <cleanup>:
  Removes VPPTop repository

__EOF__
}

# Resolve chosen option and call appropriate functions
function resolve_option() {
  local option=$1
  case ${option} in
  "start")
    vpptop_start
    ;;
  "install")
    dep_install
    go_install
    vpptop_install
    ;;
  "cleanup")
    cleanup
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
  options=("install" "cleanup" "help")
  select option in "${options[@]}"; do
    resolve_option "${option}"
    break
  done
fi
