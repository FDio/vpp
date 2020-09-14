
# Copyright (c) 2020 Doc.ai and/or its affiliates.
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

if (OPENSSL_VERSION VERSION_LESS 1.1.0)
  return()
endif()

list(APPEND WG_BLAKE_SOURCES
  blake/blake2s.h
  blake/blake2s.c
)

add_vpp_plugin(wireguard
  SOURCES
  ${WG_BLAKE_SOURCES}
  wireguard.c
  wireguard.h
  wireguard_if.c
  wireguard_if.h
  wireguard_input.c
  wireguard_output_tun.c
  wireguard_handoff.c
  wireguard_key.c
  wireguard_key.h
  wireguard_cli.c
  wireguard_messages.h
  wireguard_noise.c
  wireguard_noise.h
  wireguard_send.c
  wireguard_send.h
  wireguard_cookie.c
  wireguard_cookie.h
  wireguard_peer.c
  wireguard_peer.h
  wireguard_timer.c
  wireguard_timer.h
  wireguard_index_table.c
  wireguard_index_table.h
  wireguard_api.c

  API_FILES
  wireguard.api

)
