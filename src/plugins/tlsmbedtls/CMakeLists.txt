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

vpp_find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/ssl.h)

if (NOT MBEDTLS_INCLUDE_DIR)
  message(WARNING "-- mbedtls headers not found - tlsmbedtls plugin disabled")
  return()
endif()

file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" MBEDTLS_VERSION_H)
string(REGEX MATCH "#define MBEDTLS_VERSION_MAJOR +([0-9]+)" _ "${MBEDTLS_VERSION_H}")
set(MBEDTLS_VERSION_MAJOR "${CMAKE_MATCH_1}")
if (MBEDTLS_VERSION_MAJOR GREATER_EQUAL 3)
  message(WARNING "-- mbedtls version ${MBEDTLS_VERSION_MAJOR}.x is not supported - tlsmbedtls plugin disabled")
  return()
endif()

vpp_plugin_find_library(tlsmbedtls MBEDTLS_LIB1 mbedtls)
vpp_plugin_find_library(tlsmbedtls MBEDTLS_LIB2 mbedx509)
vpp_plugin_find_library(tlsmbedtls MBEDTLS_LIB3 mbedcrypto)

if (NOT MBEDTLS_LIB1 AND NOT MBEDTLS_LIB2 AND NOT MBEDTLS_LIB3)
  message(WARNING "-- mbedtls libraries not found - tlsmbedtls plugin disabled")
  return()
endif ()

set (MBEDTLS_LIB ${MBEDTLS_LIB1} ${MBEDTLS_LIB2} ${MBEDTLS_LIB3})

include_directories(${MBEDTLS_INCLUDE_DIR})
add_vpp_plugin(tlsmbedtls
  SOURCES
  tls_mbedtls.c

  LINK_LIBRARIES
  ${MBEDTLS_LIB}
)
