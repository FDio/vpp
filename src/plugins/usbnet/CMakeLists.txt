# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2021 Cisco Systems, Inc.

vpp_find_path(LIBUSB_1_INCLUDE_DIR NAMES libusb-1.0/libusb.h)

if (NOT LIBUSB_1_INCLUDE_DIR)
  message(WARNING "libusb-1.0 headers not found - usbnet plugin disabled")
  return()
endif()

vpp_plugin_find_library(usbnet LIBUSB_1_LIBRARY usb-1.0)
if (NOT LIBUSB_1_LIBRARY)
  message(WARNING "libusb-1.0 library not found - usbnet plugin disabled")
  return()
endif()

include_directories (${LIBUSB_1_INCLUDE_DIR})

add_vpp_plugin(usbnet
  SOURCES
  cli.c
  device.c
  format.c
  plugin.c

  LINK_LIBRARIES
  ${LIBUSB_1_LIBRARY}
)
