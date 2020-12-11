#!/bin/bash

# wget, git

BUILD_ROOT=$(pwd)/build-root
VPPTOP_DIR=${BUILD_ROOT}/vpptop
GO_VERSION="1.15.6"
GO_PLATFORM="linux-amd64"

# directory check (if there is not extras/scripts in the vpptop dir, so the makefile was used)

function go_install() {
  local GO_TMP_PKG="go${GO_VERSION}.${GO_PLATFORM}.tar.gz"
  local TMP="/tmp"

  echo "Installing GO v${GO_VERSION}"

  if [[ -x "$(command -v go)" ]]; then
    local installed_ver=$(go version)
    local installed_ver_fmt=${installed_ver#"go version go"}
    echo "Found installed version ${installed_ver_fmt}"
    return
  fi

  [ -z "$GOROOT" ] && GOROOT="$HOME/.go"
  [ -z "$GOPATH" ] && GOPATH="$HOME/go"

  wget https://storage.googleapis.com/golang/${GO_TMP_PKG} -O "${TMP}/go.tar.gz"
  tar -C "$GOROOT" --strip-components=1 -xzf "${TMP}/go.tar.gz"

  mkdir -p "${GOROOT}"
  mkdir -p "${GOPATH}/"{src,pkg,bin}

  rm -f "${TMP}/go.tar.gz"
}

function install_binapi_gen() {
  echo "Installing GoVPP binary API generator"
  if [[ ! -x "$(command -v go)" ]]; then
    echo "GO is not installed"
    exit 1
  fi

  # master required for latest vpptop
  go get git.fd.io/govpp.git/cmd/binapi-generator@master

  local installed_ver=$(binapi-generator -version)
  local installed_ver_fmt=${installed_ver#"govpp "}
  echo "Binary API generator ${installed_ver_fmt} installed"
}

function generate_binary_api() {
    local api_dir=${BUILD_ROOT}/install-vpp-native/vpp/share/vpp/api
    local out_dir=${VPPTOP_DIR}/stats/local/binapi

    if [[ ! -x "$(command -v binapi-generator)" ]]; then
        install_binapi_gen
    fi
    if [ ! -d ${VPPTOP_DIR} ]; then
        echo "VPPTop directory does not exist"
        exit 1
    elif [ ! -d ${out_dir} ]; then
        mkdir -p {out_dir}
    fi
    if [ ! -d ${api_dir} ]; then
        echo "JSON API files missing, call 'make json-api-files' first"
        exit 1
    fi

    echo "Generating API"
    binapi-generator --output-dir=${out_dir} -input-dir=${api_dir} \
    ${api_dir}/plugins/dhcp.api.json \
    ${api_dir}/core/interface.api.json \
    ${api_dir}/core/ip.api.json \
    ${api_dir}/core/vpe.api.json
}

function get_vpptop() {
    echo "Fetching VPPTop"
    if [ ! -d ${VPPTOP_DIR} ]; then
        cd ${BUILD_ROOT} && git clone https://github.com/PANTHEONtech/vpptop.git
    else
      echo "VPPTop directory already exists"
    fi
}

function vpptop_install() {
    get_vpptop
    echo "Installing VPPTop"
    if [ ! -d ${VPPTOP_DIR} ]; then
        echo "VPPTop directory does not exist"
        exit 1
    fi
    cd ${VPPTOP_DIR} && go mod download
    cd ${VPPTOP_DIR} && make install

    if [[ ! -x "$(command -v vpptop)" ]]; then
        echo "VPPTop was not successfully installed"
        exit 1
    fi

    echo "------"
    vpptop --help
    echo "Done"
}

go_install
vpptop_install