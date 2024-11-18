# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2024 Cisco Systems, Inc.

add_vpp_plugin(auto_sdl
  SOURCES
  auto_sdl.c
  auto_sdl.h
  plugin.c
  auto_sdl_api.c

  API_FILES
  auto_sdl.api
)

add_vpp_plugin(auto_sdl_unittest
  SOURCES
  test/auto_sdl_test.c
)
