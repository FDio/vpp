#!/bin/env bash

mkdeb_log() {
  echo -e "\033[1;33mmkdeb: $1\033[0m"
}

mkdeb_err() {
  echo -e "\033[1;31mmkdeb: $1\033[0m"
}

mkdeb_cleanup()
{
  trap '' INT TERM EXIT ERR
  mkdeb_log "cleaning up ${tmp_dir}"
  rm -rf ${tmp_dir}
  exit
}

mkdeb_check_deps() {
for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: '$cmd' is not installed or not in PATH." >&2
        exit 1
    fi
done
}

mkdeb_init() {
  mkdeb_check_deps
  export MAKE_JOBS=$(nproc)
  pkg_arch=$(dpkg --print-architecture)
  tmp_dir=$(mktemp -d -p $PWD)
  mkdeb_log "created tmp directory ${tmp_dir}"

  set -eEuo pipefail
  trap "mkdeb_cleanup" INT TERM EXIT ERR

  src_dir=${tmp_dir}/src
  build_dir=${tmp_dir}/build
  staging_dir=${tmp_dir}/stage
  install_dir=${staging_dir}/opt/vpp/external/$(uname -m)
  mkdir -p ${src_dir} ${build_dir} ${install_dir}

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --name)
        pkg_name="$2"
        shift 2
        ;;
      --description)
        pkg_desc="$2"
        shift 2
        ;;
      *)
        echo "Unknown option for mkdeb init: $1"
        return 1
        ;;
    esac
  done
}

mkdeb_fetch_github() {

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --repo)
        github_repo="$2"
        shift 2
        ;;
      *)
        echo "Unknown option for mkdeb init: $1"
        return 1
        ;;
    esac
  done

  github_repo_name="${github_repo#*/}"
  github_tag=$(curl -s https://api.github.com/repos/${github_repo}/releases/latest | jq -r .tag_name)
  pkg_ver="${github_tag#v}"

  github_url="https://github.com/${github_repo}/archive/refs/tags/${github_tag}.tar.gz"

  mkdeb_log "fetching ${github_url}..."
  curl \
    -o ${tmp_dir}/tarball.tar.gz \
    -L \
    ${github_url}
  mkdeb_log "extracting tarball..."
  tar \
    --directory ${src_dir} \
    --extract \
    --strip-components=1 \
    --file ${tmp_dir}/tarball.tar.gz
}

mkdeb_finalize() {

  mkdeb log "generating debian/control ..."
  mkdir -p ${staging_dir}/DEBIAN

  cat > ${staging_dir}/DEBIAN/control << __EOF__
Package: ${pkg_name}
Version: ${pkg_ver}
Architecture: ${pkg_arch}
Maintainer: vpp-dev <vpp-dev@fd.io>
Installed-Size: $(du -ks ${staging_dir}|cut -f 1)
Section: devel
Priority: extra
Description: ${pkg_desc}
__EOF__

  pkg_filename=${pkg_name}_${pkg_ver}_${pkg_arch}.deb
  mkdeb log "creating ${pkg_filename} ..."
  dpkg-deb --root-owner-group -b ${staging_dir} ${pkg_filename}
}

mkdeb() {
  local cmd="$1"
  shift

  case "$cmd" in
    init)
      mkdeb_init "$@"
      ;;
    log)
      mkdeb_log "$@"
      ;;
    fetch-github)
      mkdeb_fetch_github "$@"
      ;;
    finalize)
      mkdeb_finalize "$@"
      ;;
  esac
}

