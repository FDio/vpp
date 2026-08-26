#!/bin/sh

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

set -eu

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <readelf> <libvnet> <consumer>..." >&2
  exit 2
fi

readelf_bin=$1
libvnet=$2
shift 2

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/vnet-exports.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

symbols()
{
  "$readelf_bin" --syms --wide "$1" |
    awk '$7 != "UND" && ($4 == "FUNC" || $4 == "OBJECT" || $4 == "TLS") {
      sub(/@.*/, "", $8);
      print $8;
    }'
}

dynamic_symbols()
{
  "$readelf_bin" --dyn-syms --wide "$1" |
    awk '$7 != "UND" && ($4 == "FUNC" || $4 == "OBJECT" || $4 == "TLS") {
      sub(/@.*/, "", $8);
      print $8;
    }'
}

undefined_symbols()
{
  "$readelf_bin" --dyn-syms --wide "$1" |
    awk '$7 == "UND" && ($4 == "FUNC" || $4 == "OBJECT" || $4 == "TLS" || $4 == "NOTYPE") {
      sub(/@.*/, "", $8);
      print $8;
    }'
}

symbols "$libvnet" | sort -u >"$work_dir/defined"
dynamic_symbols "$libvnet" | sort -u >"$work_dir/exported"

for consumer in "$@"; do
  undefined_symbols "$consumer"
done | sort -u >"$work_dir/undefined"

comm -12 "$work_dir/defined" "$work_dir/undefined" >"$work_dir/required"
comm -23 "$work_dir/required" "$work_dir/exported" >"$work_dir/missing"

if [ -s "$work_dir/missing" ]; then
  echo "libvnet symbols used by in-tree consumers are not exported:" >&2
  sed 's/^/  /' "$work_dir/missing" >&2
  exit 1
fi

required_count=$(wc -l <"$work_dir/required" | tr -d ' ')
exported_count=$(wc -l <"$work_dir/exported" | tr -d ' ')
echo "libvnet export check passed: $required_count required, $exported_count exported"
