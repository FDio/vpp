# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

vpp_find_path(LIBSSH_INCLUDE_DIR NAMES libssh/libssh.h libssh/server.h libssh/callbacks.h)

if (NOT LIBSSH_INCLUDE_DIR)
  message(WARNING "-- libssh headers not found - ssh plugin disabled")
  return()
endif()

vpp_plugin_find_library(ssh LIBSSH_LIB ssh)

include_directories(${LIBSSH_INCLUDE_DIR})

add_vpp_plugin(ssh
  SOURCES
  ssh.c
  config.c
  cli.c

  LINK_LIBRARIES
  ${LIBSSH_LIB}
)
