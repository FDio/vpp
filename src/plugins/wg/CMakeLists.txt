
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

unset(WG_CRYPTO_SOURCES)
list(APPEND WG_CRYPTO_SOURCES
    crypto/include/blake2s.h
    crypto/include/chacha20.h
    crypto/include/chacha20poly1305.h
    crypto/include/curve25519.h
    crypto/include/poly1305.h

    crypto/blake2s.c
    crypto/curve25519.c
    crypto/chacha20.c
    crypto/poly1305.c
    crypto/chacha20poly1305.c
    crypto/random.h
    crypto/random.c
)

add_vpp_plugin(wg
  SOURCES
  ${WG_CRYPTO_SOURCES}
  wg.c
  wg_input.c
  wg_output_tun.c
  wg_convert.c
  wg_convert.h
  wg.h
  wg_cli.c
  wg_messages.h
  wg_noise.c
  wg_noise.h
  wg_send.c
  wg_send.h
  wg_cookie.c
  wg_cookie.h
  wg_peer.c
  wg_peer.h
  wg_timer.c
  wg_timer.h
  wg_index_table.c
  wg_index_table.h
  wg_api.c

  API_FILES
  wg.api

)
