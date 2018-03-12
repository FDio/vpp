# Copyright (c) 2015 Cisco and/or its affiliates.
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

gmod_configure_depend = vpp-install

gmod_configure_args = --libdir=$(PACKAGE_INSTALL_DIR)/$(arch_lib_dir)/ganglia

gmod_CPPFLAGS = $(call installed_includes_fn, vpp)
gmod_CPPFLAGS += -I/usr/include/apr-1.0 -I/usr/include/apr-1 -I/usr/include
gmod_LDFLAGS = $(call installed_libs_fn, vpp)

gmod_image_include = echo $(arch_lib_dir)/ganglia/libgmodvpp.so etc
