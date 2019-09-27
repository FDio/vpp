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

add_vpp_plugin(lacp
  SOURCES
  lacp.c
  lacp_api.c
  selection.c
  rx_machine.c
  tx_machine.c
  mux_machine.c
  ptx_machine.c
  cli.c
  input.c
  node.c

  API_FILES
  lacp.api

  INSTALL_HEADERS
  protocol.h
  machine.h
  rx_machine.h
  tx_machine.h
  mux_machine.h
  ptx_machine.h
  node.h

  API_TEST_SOURCES
  lacp_test.c
)

