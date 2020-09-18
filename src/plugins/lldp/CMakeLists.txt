# Copyright (c) 2020 Cisco and/or its affiliates.
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


add_vpp_plugin(lldp
  SOURCES
  lldp_input.c
  lldp_node.c
  lldp_output.c
  lldp_cli.c
  lldp_api.c

  API_FILES
  lldp.api

  INSTALL_HEADERS
  lldp_protocol.h
  lldp.h

  API_TEST_SOURCES
  lldp_test.c
)
