add_vpp_plugin(soft_rss
  SOURCES
  main.c
  format.c
  cli.c
  node.c

  INSTALL_HEADERS
  export.h

  LUA_SOURCES
  lua.c

  MULTIARCH_SOURCES
  node.c
)
