#!/bin/bash
# Copyright (c) 2021 Netease and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

tag=v2.0
ws_root=$(dirname $(readlink -f "$0"))
pd_root=$ws_root/packetdrill
pd_path=$pd_root/gtests/net/packetdrill
so_path=$ws_root/vpp_adapter
patch_path=$ws_root/packetdrill-patches/$tag

download_pd(){
	if [ -d "$pd_root" ]; then
		echo "Packetdrill is already download"
		exit 1
	fi

	pushd $ws_root
	git clone https://github.com/google/packetdrill.git packetdrill
	cd packetdrill
	git checkout -b $tag packetdrill-$tag
	# Patch
	git am $patch_path/*
	popd
}

build_pd(){
	if [ ! -d "$pd_root" ]; then
		echo "Please download packetdrill code first"
		exit 1
	fi
	pushd $pd_path
	make -f Makefile.Linux
	popd
	pushd $so_path
	make
	popd
}

clean_pd(){
	if [ ! -d "$pd_root" ]; then
		echo "Packetdrill code is not exist"
		exit 1
	fi
	pushd $pd_path
	make clean
	popd
	pushd $so_path
	make clean
	popd
}

case $1 in
	download)
		download_pd
		;;
	build)
		build_pd
		;;
	clean)
		clean_pd
		;;
	*)

	echo "Usage: $0 {download | build | clean}"
	exit 1
    ;;
esac

exit 0
