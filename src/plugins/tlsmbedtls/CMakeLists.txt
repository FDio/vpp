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

message(STATUS "Looking for mbedTLS")
find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/ssl.h)
find_library(MBEDTLS_LIB1 NAMES mbedtls)
find_library(MBEDTLS_LIB2 NAMES mbedx509)
find_library(MBEDTLS_LIB3 NAMES mbedcrypto)

set (MBEDTLS_LIB ${MBEDTLS_LIB1} ${MBEDTLS_LIB2} ${MBEDTLS_LIB3})

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIB)
  include_directories(${MBEDTLS_INCLUDE_DIR})
  add_vpp_plugin(tlsmbedtls_plugin tls_mbedtls.c)
  target_link_libraries(tlsmbedtls_plugin ${MBEDTLS_LIB})
  message(STATUS "Found mbedTLS in ${MBEDTLS_INCLUDE_DIR}")
else()
  message(WARNING "-- mbedTLS not found - tlsmbedtls_plugin disabled")
endif()

