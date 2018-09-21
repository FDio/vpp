# Copyright (c) 2018 Cisco and/or its affiliates.
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

nasm_version            := 2.13.03
nasm_tarball            := nasm-$(nasm_version).tar.xz
nasm_tarball_md5sum     := d5ca2ad7121ccbae69dd606b1038532c
nasm_tarball_strip_dirs := 1
nasm_url                := http://www.nasm.us/pub/nasm/releasebuilds/$(nasm_version)/$(nasm_tarball)
nasm_cflags             := -Wno-implicit-fallthrough -std=c11

$(eval $(call package,nasm))
