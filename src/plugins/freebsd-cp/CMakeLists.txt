# SPDX-License-Identifier: Apache-2.0

add_vpp_plugin(freebsd_cp
  SOURCES
  fcp.c
  fcp_route.c
  SUPPORTED_OS_LIST FreeBSD
)
