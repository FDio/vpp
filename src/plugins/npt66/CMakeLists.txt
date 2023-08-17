# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2023 Cisco Systems, Inc.

add_vpp_plugin(npt66
  SOURCES
  npt66.c
  npt66_api.c
  npt66_cli.c
  npt66_node.c


  MULTIARCH_SOURCES
  npt66_node.c

  API_FILES
  npt66.api
)
