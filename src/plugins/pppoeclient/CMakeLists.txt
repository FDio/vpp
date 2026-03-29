# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Cisco and/or its affiliates.

add_vpp_plugin(pppoeclient
  SOURCES
    node.c
    pppoeclient.c
    pppoeclient_api.c

  API_FILES
    pppoeclient.api

  INSTALL_HEADERS
    pppoeclient.h
    pppoeclient_error.def
)
