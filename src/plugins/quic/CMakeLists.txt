# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco

if(NOT OPENSSL_FOUND)
  message(WARNING "OpenSSL not found - quic plugin disabled")
  return()
endif()

add_vpp_plugin(quic
  SOURCES
  quic.c

  LINK_LIBRARIES ${OPENSSL_LIBRARIES}
)
