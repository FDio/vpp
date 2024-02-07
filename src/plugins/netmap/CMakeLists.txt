# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Tom Jones <thj@freebsd.org>
#
# This software was developed by Tom Jones <thj@freebsd.org> under sponsorship
# from the FreeBSD Foundation.
#

if (NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  message(WARNING "Netmap is only currently support on FreeBSD  - netmap plugin disabled")
  return()
endif()

add_vpp_plugin(netmap
  SOURCES
  plugin.c
  netmap.c
  node.c
  device.c
  cli.c
  netmap_api.c

  MULTIARCH_SOURCES
  node.c
  device.c

  INSTALL_HEADERS
  netmap.h
  net_netmap.h

  API_FILES
  netmap.api
)
