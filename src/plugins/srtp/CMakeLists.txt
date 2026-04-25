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


find_package(PkgConfig QUIET)
if (NOT PKG_CONFIG_FOUND)
  message(WARNING "srtp plugin - pkg-config not found - plugin disabled")
  return()
endif()

pkg_check_modules(SRTP QUIET libsrtp2)
if (NOT SRTP_FOUND)
  message(WARNING "srtp plugin - libsrtp2 not found - plugin disabled")
  return()
endif()

set(SRTP_PLUGIN_LINK_LIBRARIES ${SRTP_STATIC_LINK_LIBRARIES})
if (NOT SRTP_PLUGIN_LINK_LIBRARIES)
  set(SRTP_PLUGIN_LINK_LIBRARIES ${SRTP_LINK_LIBRARIES})
endif()

vpp_find_path(SRTP_INCLUDE_DIR NAMES srtp2/srtp.h HINTS ${SRTP_INCLUDE_DIRS})

if (NOT SRTP_INCLUDE_DIR)
  message(WARNING "srtp plugin - srtp.h not found - plugin disabled")
  return()
endif()

include_directories (${SRTP_INCLUDE_DIR})

add_vpp_plugin(srtp
  SOURCES
  srtp.c

  LINK_LIBRARIES
  ${SRTP_PLUGIN_LINK_LIBRARIES}
)
