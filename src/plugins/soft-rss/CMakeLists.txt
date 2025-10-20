add_vpp_plugin(soft_rss
  SOURCES
  main.c
  cli.c
  node.c
  soft_rss.h

  INSTALL_HEADERS
  export.h

  MULTIARCH_SOURCES
  node.c
)
