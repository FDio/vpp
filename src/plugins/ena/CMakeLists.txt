# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2023 Cisco Systems, Inc.

add_vpp_plugin(ena
  SOURCES
  admin.c
  cli.c
  device.c
  format.c
  format_admin.c
  input.c
  output.c
  plugin.c
  process.c
  reg.c
  queue.c

  MULTIARCH_SOURCES
  input.c
  output.c
)
