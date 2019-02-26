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

add_vpp_plugin(nsh
  SOURCES
  nsh.c
  nsh_node.c
  nsh_output.c
  nsh_pop.c
  nsh_cli.c
  nsh_api.c
  nsh-md2-ioam/nsh_md2_ioam.c
  nsh-md2-ioam/nsh_md2_ioam_api.c
  nsh-md2-ioam/md2_ioam_transit.c
  nsh-md2-ioam/nsh_md2_ioam_trace.c
  nsh-md2-ioam/export-nsh-md2-ioam/nsh_md2_ioam_export.c
  nsh-md2-ioam/export-nsh-md2-ioam/nsh_md2_ioam_export_thread.c
  nsh-md2-ioam/export-nsh-md2-ioam/nsh_md2_ioam_node.c

  MULTIARCH_SOURCES
  nsh_node.c
  nsh_output.c
  nsh_pop.c

  API_FILES
  nsh.api

  API_TEST_SOURCES
  nsh_test.c
)

