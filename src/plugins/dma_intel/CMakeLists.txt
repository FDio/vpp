# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_plugin(dma_intel
  SOURCES
  dsa.c
  format.c
  main.c

  SUPPORTED_OS_LIST Linux
)
