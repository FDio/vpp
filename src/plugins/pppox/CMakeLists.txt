# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Cisco and/or its affiliates.

add_vpp_plugin(pppox
  SOURCES
    cli.c
    node.c
    pppox.c
    pppox_api.c
    pppd/auth.c
    pppd/ccp.c
    pppd/chap-md5.c
    pppd/chap-new.c
    pppd/ecp.c
    pppd/fsm.c
    pppd/ipcp.c
    pppd/ipv6cp.c
    pppd/lcp.c
    pppd/magic.c
    pppd/md5.c
    pppd/options.c
    pppd/sys-vpp.c
    pppd/upap.c
    pppd/utils.c

  API_FILES
    pppox.api
)

# Add compile flags for pppox to suppress C23 warnings
set_target_properties(pppox_plugin PROPERTIES
    COMPILE_FLAGS "-Wno-error -w -Wno-deprecated-non-prototype -Wno-self-assign"
)
