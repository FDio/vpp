#include <vnet/bfd/bfd_protocol.h>

u8 bfd_pkt_get_version (const bfd_pkt_t *pkt)
{
  return pkt->head.vers_diag >> 5;
}

void bfd_pkt_set_version (bfd_pkt_t *pkt, int version)
{
  pkt->head.vers_diag =
      (version << 5) | (pkt->head.vers_diag & ((1 << 5) - 1));
}

u8 bfd_pkt_get_diag_code (const bfd_pkt_t *pkt)
{
  return pkt->head.vers_diag & ((1 << 5) - 1);
}

void bfd_pkt_set_diag_code (bfd_pkt_t *pkt, int value)
{
  pkt->head.vers_diag =
      (pkt->head.vers_diag & ~((1 << 5) - 1)) | (value & ((1 << 5) - 1));
}

u8 bfd_pkt_get_state (const bfd_pkt_t *pkt)
{
  return pkt->head.sta_flags >> 6;
}

void bfd_pkt_set_state (bfd_pkt_t *pkt, int value)
{
  pkt->head.sta_flags = (value << 6) | (pkt->head.sta_flags & ((1 << 6) - 1));
}

u8 bfd_pkt_get_poll (const bfd_pkt_t *pkt)
{
  return (pkt->head.sta_flags >> 5) & 1;
}

void bfd_pkt_set_final (bfd_pkt_t *pkt) { pkt->head.sta_flags |= 1 << 5; }

u8 bfd_pkt_get_final (const bfd_pkt_t *pkt)
{
  return (pkt->head.sta_flags >> 4) & 1;
}

void bfd_pkt_set_poll (bfd_pkt_t *pkt);
u8 bfd_pkt_get_control_plane_independent (const bfd_pkt_t *pkt)
{
  return (pkt->head.sta_flags >> 3) & 1;
}

void bfd_pkt_set_control_plane_independent (bfd_pkt_t *pkt);

u8 bfd_pkt_get_auth_present (const bfd_pkt_t *pkt)
{
  return (pkt->head.sta_flags >> 2) & 1;
}

void bfd_pkt_set_auth_present (bfd_pkt_t *pkt);

u8 bfd_pkt_get_demand (const bfd_pkt_t *pkt)
{
  return (pkt->head.sta_flags >> 1) & 1;
}

void bfd_pkt_set_demand (bfd_pkt_t *pkt) { pkt->head.sta_flags |= 1 << 1; }

u8 bfd_pkt_get_multipoint (const bfd_pkt_t *pkt)
{
  return pkt->head.sta_flags & 1;
}

void bfd_pkt_set_multipoint (bfd_pkt_t *pkt);
