# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Cisco and/or its affiliates.

# pppox/ lives as a subdirectory so its sources compile into
# pppoeclient_plugin.so directly. pppd/ retains its own subtree to
# preserve the third-party import provenance captured in
# pppox/pppd/README.import.
add_vpp_plugin(pppoeclient
  SOURCES
    node.c
    pppoeclient.c
    pppoeclient_api.c
    pppox/cli.c
    pppox/node.c
    pppox/pppox.c
    pppox/pppox_api.c
    pppox/pppd/auth.c
    pppox/pppd/ccp.c
    pppox/pppd/chap-md5.c
    pppox/pppd/chap-new.c
    pppox/pppd/ecp.c
    pppox/pppd/fsm.c
    pppox/pppd/ipcp.c
    pppox/pppd/ipv6cp.c
    pppox/pppd/lcp.c
    pppox/pppd/magic.c
    pppox/pppd/md5.c
    pppox/pppd/options.c
    pppox/pppd/sys-vpp.c
    pppox/pppd/upap.c
    pppox/pppd/utils.c

  API_FILES
    pppoeclient.api
    pppox/pppox.api

  INSTALL_HEADERS
    pppoeclient.h
    pppoeclient_error.def
)
