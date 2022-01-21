
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

include_directories(${OPENSSL_INCLUDE_DIR})

list(APPEND WG_BLAKE_SOURCES
  blake/blake2s.h
  blake/blake2s.c
  blake/blake3.c
  blake/blake3_dispatch.c
  blake/blake3.h
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

  LINK_LIBRARIES ${OPENSSL_LIBRARIES}

  API_FILES
  wireguard.api

)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  set (COMPILE_OPTS -Wall -fno-common -maes)
  add_library(blake3_x86 OBJECT blake/blake3_portable.c)
  set_target_properties(blake3_x86 PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_compile_options(blake3_x86 PUBLIC ${COMPILE_OPTS})
  target_sources(wireguard_plugin PRIVATE $<TARGET_OBJECTS:blake3_x86>)
  if(compiler_flag_march_skylake_avx512)
  add_library(blake3_avx512 OBJECT blake/blake3_avx512.c)
  set_target_properties(blake3_avx512 PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_compile_options(blake3_avx512 PUBLIC -march=skylake-avx512 -mtune=skylake-avx512 ${COMPILE_OPTS})
  target_sources(wireguard_plugin PRIVATE $<TARGET_OBJECTS:blake3_avx512>)
  endif()
endif()

foreach(VARIANT ${VARIANTS})
  list(GET VARIANT 0 v)
  list(GET VARIANT 1 f)
  set(l crypto_native_${v})
  add_library(${l} OBJECT ${COMPILE_FILES})
  set_target_properties(${l} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  separate_arguments(f)
  target_compile_options(${l} PUBLIC ${f} ${COMPILE_OPTS})
  target_sources(crypto_native_plugin PRIVATE $<TARGET_OBJECTS:${l}>)
endforeach()
