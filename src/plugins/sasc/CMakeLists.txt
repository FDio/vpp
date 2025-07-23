# Copyright (c) 2025 Cisco and/or its affiliates.

# First define the test sources separately
set(TEST_SOURCES
  tests/test_sasc.c
  tests/scapy.c
  tests/test.c
  )

# Find Python and Scapy only in Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "debug")
  find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
  # Check if scapy is installed
  execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import scapy"
    RESULT_VARIABLE SCAPY_FOUND
    OUTPUT_QUIET
    ERROR_QUIET
  )
  if(NOT SCAPY_FOUND EQUAL 0)
    message(FATAL_ERROR "Scapy Python package is required for tests. Please install it with: pip3 install scapy")
  endif()

  # Debug output for Python paths
  message(STATUS "Python3_EXECUTABLE: ${Python3_EXECUTABLE}")
  message(STATUS "Python3_INCLUDE_DIRS: ${Python3_INCLUDE_DIRS}")
  message(STATUS "Python3_LIBRARIES: ${Python3_LIBRARIES}")
  message(STATUS "Python3_VERSION: ${Python3_VERSION}")
  message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
  include_directories(${Python3_INCLUDE_DIRS})
  link_libraries(${Python3_LIBRARIES})
  endif()

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
  export.c
  counter.c
  $<$<CONFIG:Debug>:${TEST_SOURCES}>

  services/l4-lifecycle/node.c
  services/tcp-check/node.c
  services/tcp-check/tcp_check.c
  services/tcp-check/format.c
  services/tcp-check/api.c
  services/tcp-check/counter.c
  services/pcap/node.c
  services/pcap/cli.c
  services/pcap/pcap.c
  services/packet-stats/node.c
  services/packet-stats/packet_stats.c
  services/packet-stats/counter.c
  services/packet-stats/format.c
  ingress/cli.c
  ingress/interface.c
  ingress/ingress.c


  API_FILES
  sasc.api
  services/tcp-check/tcp_check.api

  LINK_LIBRARIES cbor
)

# Add Python dependencies to the plugin target
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_include_directories(sasc_plugin PRIVATE ${Python3_INCLUDE_DIRS})
  target_link_libraries(sasc_plugin PRIVATE ${Python3_LIBRARIES})
endif()