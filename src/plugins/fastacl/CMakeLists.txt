# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 FastNetMon (fastnetmon.com)

add_vpp_plugin(fastacl
  SOURCES
  fastacl.c
  fastacl_api.c
  fastacl_cli.c
  fastacl_counters.c
  fastacl_psample.c
  fastacl_format.c
  fastacl_rule.c
  fastacl_tss.c
  fastacl_node.c

  MULTIARCH_SOURCES
  fastacl_node.c

  API_FILES
  fastacl.api

  INSTALL_HEADERS
  fastacl.h
  fastacl_format.h
  fastacl_types.h
  fastacl_tss.h
  fastacl_match_inline.h
  fastacl_flowspec.h
)

vpp_find_path(LIBNL3_INCLUDE_DIR NAMES libnl3/netlink/genl/ctrl.h)
if(NOT LIBNL3_INCLUDE_DIR)
  message(WARNING "libnl-3 headers not found - fastacl plugin disabled")
  return()
endif()
vpp_plugin_find_library(fastacl LIBNL3_LIB libnl-3.so)
vpp_plugin_find_library(fastacl LIBNL3_GENL_LIB libnl-genl-3.so)
include_directories(${LIBNL3_INCLUDE_DIR}/libnl3)
target_link_libraries(fastacl_plugin ${LIBNL3_LIB} ${LIBNL3_GENL_LIB})

target_compile_options(fastacl_plugin PRIVATE -O2 -fomit-frame-pointer -Werror)
