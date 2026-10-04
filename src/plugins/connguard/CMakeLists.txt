# mighty_xddos: Application Filter (Slow Connection Guard + Server Health
# Detection), VPP mode. See node.c's package doc comment for the design.
# CLI-only (no .api), same convention as the floodguard plugin — virtserver
# drives every VPP feature of this project through vppctl.

add_vpp_plugin(connguard
  SOURCES
  connguard.c
  node.c

  INSTALL_HEADERS
  connguard.h
)
