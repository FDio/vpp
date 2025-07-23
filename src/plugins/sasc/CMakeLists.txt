# Copyright (c) 2025 Cisco and/or its affiliates.

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

  LINK_LIBRARIES cbor
)
