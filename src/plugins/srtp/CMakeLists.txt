# Copyright (c) 2021 Cisco and/or its affiliates.
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

vpp_plugin_find_library(srtp SRTP_LIB libsrtp2.a)

if (NOT SRTP_LIB)
  message(WARNING "srtp plugin - srtp2 lib not found - plugin disabled")
  return()
endif()

vpp_find_path(SRTP_INCLUDE_DIR NAMES srtp2/srtp.h)

if (NOT SRTP_INCLUDE_DIR)
  message(WARNING "srtp plugin - srtp.h not found - plugin disabled")
  return()
endif()

include_directories (${SRTP_INCLUDE_DIR})

set(CMAKE_REQUIRED_FLAGS "-fPIC -shared -pthread -Wno-unused-command-line-argument ${SRTP_LIB}")
set(CMAKE_REQUIRED_INCLUDES "${SRTP_INCLUDE_DIR}")

add_vpp_plugin(srtp
  SOURCES
  srtp.c

  LINK_LIBRARIES
  ${SRTP_LIB}
)
