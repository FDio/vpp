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

add_definitions (-DWITH_LIBSSL=1)
include_directories(${OPENSSL_INCLUDE_DIR})

add_vpp_plugin(ipsec
  SOURCES
  ipsec.c
  ipsec_cli.c
  ipsec_format.c
  ipsec_handoff.c
  ipsec_input.c
  ipsec_itf.c
  ipsec_punt.c
  ipsec_sa.c
  ipsec_spd.c
  ipsec_spd_policy.c
  ipsec_tun.c
  ipsec_tun_in.c
  esp_format.c
  esp_encrypt.c
  esp_decrypt.c
  ah_decrypt.c
  ah_encrypt.c
  ipsec_api.c
  ipsec_types_api.c
  ipsec_output.c
  ipsec_input.c
  ipsec_tun_in.c
  ipsec_test.c
  plugin.c

  MULTIARCH_SOURCES
  esp_encrypt.c
  esp_decrypt.c
  ah_decrypt.c
  ah_encrypt.c
  ipsec_handoff.c
  ipsec_output.c
  ipsec_input.c
  ipsec_tun_in.c

  API_FILES
  ipsec_types.api
  ipsec.api

  INSTALL_HEADERS
  ipsec.h
  ipsec_spd.h
  ipsec_spd_policy.h
  ipsec_sa.h
  ipsec_tun.h
  ipsec_types_api.h
  ipsec_punt.h
  esp.h
  ah.h
)
