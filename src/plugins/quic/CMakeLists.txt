
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

unset(QUIC_LINK_LIBRARIES)
set(EXPECTED_QUICLY_VERSION "0.1.2-vpp")

find_path(QUICLY_INCLUDE_DIR NAMES quicly.h)
find_path(PICOTLS_INCLUDE_DIR NAMES picotls.h)
find_library (QUICLY_LIBRARY NAMES "libquicly.a")
find_library (PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
find_library (PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

list(APPEND QUIC_LINK_LIBRARIES
  ${QUICLY_LIBRARY}
  ${PICOTLS_CORE_LIBRARY}
  ${PICOTLS_OPENSSL_LIBRARY}
)

if(QUICLY_INCLUDE_DIR AND QUIC_LINK_LIBRARIES)
  if(EXISTS "${QUICLY_INCLUDE_DIR}/quicly/version.h")
    file(STRINGS "${QUICLY_INCLUDE_DIR}/quicly/version.h" quicly_version_str REGEX "^#define[\t ]+LIBQUICLY_VERSION[\t ]+\".*\"")
    string(REGEX REPLACE "^#define[\t ]+LIBQUICLY_VERSION[\t ]+\"([^\"]*)\".*" "\\1" QUICLY_VERSION_STRING "${quicly_version_str}")
    unset(quicly_version_str)
  endif()

  if (${QUICLY_VERSION_STRING} MATCHES "${EXPECTED_QUICLY_VERSION}")
    include_directories (${QUICLY_INCLUDE_DIR})

    if(PICOTLS_INCLUDE_DIR)
      include_directories (${PICOTLS_INCLUDE_DIR})
    endif()

    add_vpp_plugin(quic
      SOURCES
      certs.c
      error.c
      quic.c
      quic_crypto.c

      LINK_LIBRARIES ${QUIC_LINK_LIBRARIES}
    )
    message(STATUS "Found quicly ${EXPECTED_QUICLY_VERSION} in ${QUICLY_INCLUDE_DIR}")
  else()
    message(STATUS "-- quicly ${EXPECTED_QUICLY_VERSION} not found - QUIC plugin disabled")
  endif()
else()
  message(WARNING "-- quicly headers not found - QUIC plugin disabled")
endif()
