# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco

if(NOT OPENSSL_FOUND)
  message(WARNING "OpenSSL not found - quic_openssl plugin disabled")
  return()
endif()

set(EXPECTED_OPENSSL_VERSION "3.5.0")

if(OPENSSL_FOUND AND OPENSSL_VERSION VERSION_GREATER_EQUAL ${EXPECTED_OPENSSL_VERSION})
  include_directories (${OPENSSL_INCLUDE_DIR})

  add_vpp_plugin(quic_openssl
    SOURCES
    quic_openssl.c

    LINK_LIBRARIES ${OPENSSL_LIBRARIES}
  )
  message(STATUS "DAW: Found openssl ${EXPECTED_OPENSSL_VERSION} in ${OPENSSL_INCLUDE_DIR}")
else()
  message(STATUS "DAW: Found openssl ${OPENSSL_VERSION} instead of ${EXPECTED_OPENSSL_VERSION} - quic_openssl plugin disabled")
endif()
