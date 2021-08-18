# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

add_vpp_plugin(npol
  SOURCES
  npol.c
  npol_api.c
  npol_policy.c
  npol_rule.c
  npol_ipset.c
  npol_interface.c
  npol_format.c
  npol_match.c

  MULTIARCH_SOURCES
  npol_match.c

  API_FILES
  npol.api
)
