# Copyright (c) 2024 Cisco and/or its affiliates
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

add_vpp_plugin(srmpls
  SOURCES
  sr_mpls_policy.c
  sr_mpls_steering.c
  sr_mpls_api.c
  plugin.c

  INSTALL_HEADERS
  sr_mpls.h

  API_FILES
  sr_mpls.api

  # This might need to be VAT_AUTO_TEST? Not documented
  API_TEST_SOURCES
  sr_mpls_test.c
)
