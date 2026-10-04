# mighty_xddos: ETA (Encrypted Traffic Analysis) ClientHello extraction, VPP
# mode. See node.c's package doc comment for the design. CLI-only (no .api),
# same convention as the connguard plugin — virtserver drives every VPP
# feature of this project through vppctl.

add_vpp_plugin(eta
  SOURCES
  eta.c
  node.c

  INSTALL_HEADERS
  eta.h
)
