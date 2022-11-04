# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_plugin(dma_intel
  SOURCES
  dsa.c
  dsa_pci.c
  format.c
  main.c
)
