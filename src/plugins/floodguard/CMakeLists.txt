# mighty_xddos: Flood Guard, VPP mode — Broadcast Filter storm policing and
# SYN/UDP/ICMP-flood victim policing in one node, replacing the policer
# classify chain. See node.c's package doc comment for the design. CLI-only
# (no .api), same convention as the connguard and eta plugins — virtserver
# drives every VPP feature of this project through vppctl.

add_vpp_plugin(floodguard
  SOURCES
  floodguard.c
  node.c

  INSTALL_HEADERS
  floodguard.h
)
