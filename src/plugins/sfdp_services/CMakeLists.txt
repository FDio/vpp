# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco Systems, Inc.
#

#include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_vpp_plugin(sfdp_services
  SOURCES
  plugin.c
  base/tcp-check/node.c
  base/tcp-check/tcp_check.c
  base/tcp-check/format.c
  base/tcp-check/cli.c
  base/tcp-check/api.c

  base/l4-lifecycle/node.c

  base/nat/nat.c
  base/nat/cli.c
  base/nat/api.c
  base/nat/format.c
  base/nat/fastpath_node.c
  base/nat/slowpath_node.c
  base/nat/external_input_node.c

  base/interface_input/interface_input.c
  base/interface_input/cli.c
  base/interface_input/api.c
  base/interface_input/node.c

  base/classifier_input/classifier_input.c
  base/classifier_input/cli.c
  base/classifier_input/api.c
  base/classifier_input/node.c

  acl/acl_sample.c
  acl/cli.c
  acl/node.c

  dot1q/dot1q.c

  geneve/gateway.c
  geneve/cli.c
  geneve/api.c
  geneve/geneve_input/node.c
  geneve/geneve_output/node.c

  reass/reass.c
  reass/sv_reass_node.c
  #reass/full_reass_node.c

  snort/snort.c
  snort/snort_input.c
  snort/snort_output.c

  MULTIARCH_SOURCES
  base/tcp-check/node.c
  base/l4-lifecycle/node.c
  base/interface_input/node.c
  base/classifier_input/node.c
  acl/node.c
  geneve/geneve_input/node.c
  geneve/geneve_output/node.c
  dot1q/dot1q.c
  reass/sv_reass_node.c
  snort/snort_input.c
  snort/snort_output.c
  #reass/full_reass_node.c

  API_FILES
  base/nat/nat.api
  base/tcp-check/tcp_check.api
  base/interface_input/interface_input.api
  base/classifier_input/classifier_input.api
  geneve/gateway.api
)
