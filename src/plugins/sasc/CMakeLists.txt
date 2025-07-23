# Copyright (c) 2025 Cisco and/or its affiliates.

vpp_find_path(LIBCBOR_INCLUDE_DIR PATH_SUFFIXES libcbor NAMES cbor.h)
vpp_plugin_find_library(libcbor LIBCBOR_LIB "libcbor.a")

if (NOT LIBCBOR_INCLUDE_DIR)
  message(WARNING "-- LIBCBOR headers not found - sasc plugin disabled")
  return()
endif()

if (NOT LIBCBOR_LIB)
  message(WARNING "-- LIBCBOR library not found - sasc plugin disabled")
  return()
endif()

include_directories (${LIBCBOR_INCLUDE_DIR})

# First define the test sources separately
set(TEST_SOURCES
  tests/sasc_packet_factory.c
  tests/sasc_test_framework.c
  tests/sasc_scenarios_icmp.c
  tests/sasc_scenarios_tcp.c
  tests/sasc_test_wire.c
  )

add_vpp_plugin(sasc
  VAT_AUTO_TEST OFF

  SOURCES
  plugin.c
  api.c
  format.c
  service.c
  session.c
  cli.c
  sasc.c
  lookup/node.c
  create.c
  icmp_error.c
  export.c
  counter.c
  $<$<CONFIG:Debug>:${TEST_SOURCES}>

  services/l4-lifecycle/node.c

  services/pcap/node.c
  services/pcap/cli.c
  services/pcap/pcap.c

  services/flow-quality/flow_quality_tcp.c
  services/flow-quality/format.c
  services/flow-quality/counter.c
  services/flow-quality/packet_stats.c
  services/flow-quality/node.c

  ingress/cli.c
  ingress/interface.c
  ingress/ingress.c


  API_FILES
  sasc.api

  LINK_LIBRARIES
  ${LIBCBOR_LIB}
)