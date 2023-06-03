# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2021 Cisco Systems, Inc.

add_vpp_plugin(usbnet
  SOURCES
  cli.c
  device.c
  format.c
  mbim.c
  plugin.c

  LINK_LIBRARIES
)
