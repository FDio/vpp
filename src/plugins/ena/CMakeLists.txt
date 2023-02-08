# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2023 Cisco Systems, Inc.

add_vpp_plugin(ena
  SOURCES
  cli.c
  device.c
  format.c
  input.c
  output.c
  plugin.c

  MULTIARCH_SOURCES
  input.c
  output.c
)
