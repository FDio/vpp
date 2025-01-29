# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco

if(NOT OPENSSL_FOUND)
  message(WARNING "OpenSSL not found - quic_quicly plugin disabled")
  return()
endif()

# TODO: Remove quicly files/libraries when all quicly references moved to quic_quicly plugin
unset(QUIC_LINK_LIBRARIES)
set(EXPECTED_QUICLY_VERSION "0.1.5-vpp")

vpp_find_path(QUICLY_INCLUDE_DIR NAMES quicly.h)
vpp_find_path(PICOTLS_INCLUDE_DIR NAMES picotls.h)
vpp_find_library(QUICLY_LIBRARY NAMES "libquicly.a")
vpp_find_library(PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
vpp_find_library(PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

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

    add_vpp_plugin(quic_quicly
      SOURCES
      quic_quicly.c
      quic_quicly_error.c
      quic_quicly_crypto.c
      ptls_certs.c

      LINK_LIBRARIES ${QUIC_LINK_LIBRARIES} ${OPENSSL_LIBRARIES}
    )
    message(STATUS "Found quicly ${EXPECTED_QUICLY_VERSION} in ${QUICLY_INCLUDE_DIR}")
  else()
    message(STATUS "-- quicly ${EXPECTED_QUICLY_VERSION} not found - quic_quicly plugin disabled")
  endif()
else()
  message(WARNING "-- quicly headers not found - quic_quicly plugin disabled")
endif()
