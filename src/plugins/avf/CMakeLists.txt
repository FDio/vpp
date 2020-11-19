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

add_vpp_plugin(avf
  SOURCES
  cli.c
  device.c
  format.c
  input.c
  output.c
  plugin.c
  avf_api.c
  flow.c
  iavf_fdir_lib.c

  MULTIARCH_SOURCES
  input.c
  output.c

  API_FILES
  avf.api

  API_TEST_SOURCES
  avf_test.c
)
