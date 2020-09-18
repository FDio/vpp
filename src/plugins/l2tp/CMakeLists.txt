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

##############################################################################
# Tunnel protocol: l2tpv3
##############################################################################
add_vpp_plugin(l2tp
  SOURCES
  l2tp.c
  encap.c
  decap.c
  pg.c
  l2tp_api.c

  MULTIARCH_SOURCES
  encap.c
  decap.c

  INSTALL_HEADERS
  l2tp.h
  packet.h

  API_FILES
  l2tp.api

  API_TEST_SOURCES
  l2tp_test.c
)
