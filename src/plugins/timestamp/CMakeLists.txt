include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_BINARY_DIR})

add_vpp_plugin(timestamp
  SOURCES
  node.c
  timestamp.c

  MULTIARCH_SOURCES
  node.c

  API_FILES
  timestamp.api

  API_TEST_SOURCES
  timestamp_test.c

  COMPONENT vpp-plugin-timestamp
)
