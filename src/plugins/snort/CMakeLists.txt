# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2021 Cisco Systems, Inc.

add_vpp_plugin(snort
  SOURCES
  enqueue.c
  dequeue.c
  main.c
  cli.c

  MULTIARCH_SOURCES
  enqueue.c
  dequeue.c
)

# DAQ

add_library(daq_vpp SHARED daq_vpp.c)
set_target_properties(daq_vpp PROPERTIES SOVERSION ${VPP_LIB_VERSION})
target_compile_options (daq_vpp PRIVATE "-fvisibility=hidden")
target_compile_options (daq_vpp PRIVATE "-DHAVE_VISIBILITY")
target_compile_options (daq_vpp PRIVATE "-I/opt/vpp/external/x86_64/include/")
install(TARGETS daq_vpp DESTINATION ${VPP_LIBRARY_DIR}/daq COMPONENT vpp-plugin-core)

