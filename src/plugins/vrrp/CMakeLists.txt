#
# Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
#
# SPDX-License-Identifier: Apache-2.0
#

add_vpp_plugin(vrrp
  SOURCES
  vrrp.c 
  vrrp_api.c
  vrrp_cli.c
  vrrp_format.c
  node.c 
  vrrp_packet.c
  vrrp_periodic.c

  MULTIARCH_SOURCES
  node.c 

  API_FILES
  vrrp.api

  INSTALL_HEADERS
  vrrp.h

  API_TEST_SOURCES
  vrrp_test.c
)
