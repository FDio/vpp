add_vpp_plugin(soft_rss
  SOURCES
  main.c
  format.c
  cli.c
  node.c
  api.c

  API_FILES
  soft_rss.api

  INSTALL_HEADERS
  export.h

  MULTIARCH_SOURCES
  node.c
)
