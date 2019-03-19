
# Copyright (c) 2019 Cisco
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

message(STATUS "Looking for quicly")
unset(QUIC_LINK_LIBRARIES)

find_path(QUICLY_INCLUDE_DIR NAMES quicly.h)
find_library (QUICLY_LIBRARY NAMES "libquicly.a")
find_library (PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
find_library (PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

list(APPEND QUIC_LINK_LIBRARIES
  ${QUICLY_LIBRARY}
  ${PICOTLS_CORE_LIBRARY}
  ${PICOTLS_OPENSSL_LIBRARY}
)

if(QUICLY_INCLUDE_DIR AND QUIC_LINK_LIBRARIES)
  include_directories (${QUICLY_INCLUDE_DIR})
  add_vpp_plugin(quic
    SOURCES
    quic.c

    INSTALL_HEADERS
    quic.h

    LINK_LIBRARIES ${QUIC_LINK_LIBRARIES}
  )
  message(STATUS "Found quicly in ${QUICLY_INCLUDE_DIR}")
else()
  message(WARNING "-- quicly not found - quic_plugin disabled")
endif()
