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

sample-plugin_source = src
sample-plugin_configure_subdir = examples/sample-plugin
sample-plugin_configure_depend = vpp-install
sample-plugin_CPPFLAGS = $(call installed_includes_fn, vpp)
sample-plugin_LDFLAGS = $(call installed_libs_fn, vpp)
