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

include (CheckFunctionExists)
if(OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIR})
  add_vpp_plugin(tlsopenssl
    SOURCES
    tls_openssl.c
    tls_openssl_api.c
    tls_async.c
    dtls_bio.c

    API_FILES
    tls_openssl.api

    API_TEST_SOURCES
    tls_openssl_test.c

    LINK_LIBRARIES
    ${OPENSSL_LIBRARIES}
  )

  set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
  set(CMAKE_REQUIRED_LIBRARIES "${OPENSSL_LIBRARIES}")
  check_function_exists(SSL_set_async_callback HAVE_OPENSSL_ASYNC)

  if (HAVE_OPENSSL_ASYNC)
    add_definitions(-DHAVE_OPENSSL_ASYNC)
  endif()


endif()

