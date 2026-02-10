add_vpp_library(selog_client
  SOURCES
  selog_client.c

  LINK_LIBRARIES
  vppinfra svm vlibmemoryclient rt pthread

  DEPENDS
  selog_plugin_api_headers

  INSTALL_HEADERS
  selog_client.h
)

add_vpp_test(selog_client_example
  SOURCES
  selog_client_example.c
  LINK_LIBRARIES
  selog_client
)