/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/dev/counters.h>
#include <ice.h>

#define foreach_ice_port_counter                                                                   \
  _ (RX_BYTES, RX_BYTES, 0)                                                                        \
  _ (RX_PACKETS, RX_PACKETS, 0)                                                                    \
  _ (RX_DROPS, RX_DROPS, 0)                                                                        \
  _ (RX_UNICAST, VENDOR, RX, PACKETS, "unicast")                                                   \
  _ (RX_MULTICAST, VENDOR, RX, PACKETS, "multicast")                                               \
  _ (RX_BROADCAST, VENDOR, RX, PACKETS, "broadcast")                                               \
  _ (RX_UNKNOWN_PROTOCOL, VENDOR, RX, PACKETS, "unknown protocol")                                 \
  _ (TX_BYTES, TX_BYTES, 0)                                                                        \
  _ (TX_PACKETS, TX_PACKETS, 0)                                                                    \
  _ (TX_DROPS, TX_DROPS, 0)                                                                        \
  _ (TX_UNICAST, VENDOR, TX, PACKETS, "unicast")                                                   \
  _ (TX_MULTICAST, VENDOR, TX, PACKETS, "multicast")                                               \
  _ (TX_BROADCAST, VENDOR, TX, PACKETS, "broadcast")                                               \
  _ (TX_ERRORS, VENDOR, TX, PACKETS, "errors")

#define foreach_ice_mac_counter                                                                    \
  _ (MAC_RX_BYTES, mac_rx_bytes, RX, BYTES, "MAC total")                                           \
  _ (MAC_RX_UNICAST, mac_rx_unicast, RX, PACKETS, "MAC unicast")                                   \
  _ (MAC_RX_MULTICAST, mac_rx_multicast, RX, PACKETS, "MAC multicast")                             \
  _ (MAC_RX_BROADCAST, mac_rx_broadcast, RX, PACKETS, "MAC broadcast")                             \
  _ (MAC_RX_DISCARDS, mac_rx_discards, RX, PACKETS, "MAC discarded")                               \
  _ (MAC_RX_UNKNOWN_PROTOCOL, mac_rx_unknown_protocol, RX, PACKETS, "MAC unknown protocol")        \
  _ (MAC_TX_BYTES, mac_tx_bytes, TX, BYTES, "MAC total")                                           \
  _ (MAC_TX_UNICAST, mac_tx_unicast, TX, PACKETS, "MAC unicast")                                   \
  _ (MAC_TX_MULTICAST, mac_tx_multicast, TX, PACKETS, "MAC multicast")                             \
  _ (MAC_TX_BROADCAST, mac_tx_broadcast, TX, PACKETS, "MAC broadcast")                             \
  _ (MAC_TX_DROPPED_LINK_DOWN, mac_tx_dropped_link_down, TX, PACKETS, "MAC link down dropped")     \
  _ (CRC_ERRORS, crc_errors, RX, PACKETS, "CRC errors")                                            \
  _ (ILLEGAL_BYTES, illegal_bytes, RX, BYTES, "illegal")                                           \
  _ (MAC_LOCAL_FAULTS, mac_local_faults, RX, PACKETS, "MAC local faults")                          \
  _ (MAC_REMOTE_FAULTS, mac_remote_faults, RX, PACKETS, "MAC remote faults")                       \
  _ (RX_LEN_ERRORS, rx_len_errors, RX, PACKETS, "length errors")                                   \
  _ (LINK_XON_RX, link_xon_rx, RX, PACKETS, "link XON")                                            \
  _ (LINK_XOFF_RX, link_xoff_rx, RX, PACKETS, "link XOFF")                                         \
  _ (LINK_XON_TX, link_xon_tx, TX, PACKETS, "link XON")                                            \
  _ (LINK_XOFF_TX, link_xoff_tx, TX, PACKETS, "link XOFF")                                         \
  _ (RX_SIZE_64, rx_size_64, RX, PACKETS, "64 byte")                                               \
  _ (RX_SIZE_127, rx_size_127, RX, PACKETS, "65-127 byte")                                         \
  _ (RX_SIZE_255, rx_size_255, RX, PACKETS, "128-255 byte")                                        \
  _ (RX_SIZE_511, rx_size_511, RX, PACKETS, "256-511 byte")                                        \
  _ (RX_SIZE_1023, rx_size_1023, RX, PACKETS, "512-1023 byte")                                     \
  _ (RX_SIZE_1522, rx_size_1522, RX, PACKETS, "1024-1522 byte")                                    \
  _ (RX_SIZE_BIG, rx_size_big, RX, PACKETS, "1523-max byte")                                       \
  _ (RX_UNDERSIZE, rx_undersize, RX, PACKETS, "undersize errors")                                  \
  _ (RX_FRAGMENTS, rx_fragments, RX, PACKETS, "fragment errors")                                   \
  _ (RX_OVERSIZE, rx_oversize, RX, PACKETS, "oversize errors")                                     \
  _ (RX_JABBER, rx_jabber, RX, PACKETS, "jabber errors")                                           \
  _ (TX_SIZE_64, tx_size_64, TX, PACKETS, "64 byte")                                               \
  _ (TX_SIZE_127, tx_size_127, TX, PACKETS, "65-127 byte")                                         \
  _ (TX_SIZE_255, tx_size_255, TX, PACKETS, "128-255 byte")                                        \
  _ (TX_SIZE_511, tx_size_511, TX, PACKETS, "256-511 byte")                                        \
  _ (TX_SIZE_1023, tx_size_1023, TX, PACKETS, "512-1023 byte")                                     \
  _ (TX_SIZE_1522, tx_size_1522, TX, PACKETS, "1024-1522 byte")                                    \
  _ (TX_SIZE_BIG, tx_size_big, TX, PACKETS, "1523-max byte")

#define foreach_ice_priority_counter                                                               \
  _ (PRIO_0_XON_RX, priority_xon_rx[0], RX, "priority 0 XON")                                      \
  _ (PRIO_1_XON_RX, priority_xon_rx[1], RX, "priority 1 XON")                                      \
  _ (PRIO_2_XON_RX, priority_xon_rx[2], RX, "priority 2 XON")                                      \
  _ (PRIO_3_XON_RX, priority_xon_rx[3], RX, "priority 3 XON")                                      \
  _ (PRIO_4_XON_RX, priority_xon_rx[4], RX, "priority 4 XON")                                      \
  _ (PRIO_5_XON_RX, priority_xon_rx[5], RX, "priority 5 XON")                                      \
  _ (PRIO_6_XON_RX, priority_xon_rx[6], RX, "priority 6 XON")                                      \
  _ (PRIO_7_XON_RX, priority_xon_rx[7], RX, "priority 7 XON")                                      \
  _ (PRIO_0_XOFF_RX, priority_xoff_rx[0], RX, "priority 0 XOFF")                                   \
  _ (PRIO_1_XOFF_RX, priority_xoff_rx[1], RX, "priority 1 XOFF")                                   \
  _ (PRIO_2_XOFF_RX, priority_xoff_rx[2], RX, "priority 2 XOFF")                                   \
  _ (PRIO_3_XOFF_RX, priority_xoff_rx[3], RX, "priority 3 XOFF")                                   \
  _ (PRIO_4_XOFF_RX, priority_xoff_rx[4], RX, "priority 4 XOFF")                                   \
  _ (PRIO_5_XOFF_RX, priority_xoff_rx[5], RX, "priority 5 XOFF")                                   \
  _ (PRIO_6_XOFF_RX, priority_xoff_rx[6], RX, "priority 6 XOFF")                                   \
  _ (PRIO_7_XOFF_RX, priority_xoff_rx[7], RX, "priority 7 XOFF")                                   \
  _ (PRIO_0_XON_TX, priority_xon_tx[0], TX, "priority 0 XON")                                      \
  _ (PRIO_1_XON_TX, priority_xon_tx[1], TX, "priority 1 XON")                                      \
  _ (PRIO_2_XON_TX, priority_xon_tx[2], TX, "priority 2 XON")                                      \
  _ (PRIO_3_XON_TX, priority_xon_tx[3], TX, "priority 3 XON")                                      \
  _ (PRIO_4_XON_TX, priority_xon_tx[4], TX, "priority 4 XON")                                      \
  _ (PRIO_5_XON_TX, priority_xon_tx[5], TX, "priority 5 XON")                                      \
  _ (PRIO_6_XON_TX, priority_xon_tx[6], TX, "priority 6 XON")                                      \
  _ (PRIO_7_XON_TX, priority_xon_tx[7], TX, "priority 7 XON")                                      \
  _ (PRIO_0_XOFF_TX, priority_xoff_tx[0], TX, "priority 0 XOFF")                                   \
  _ (PRIO_1_XOFF_TX, priority_xoff_tx[1], TX, "priority 1 XOFF")                                   \
  _ (PRIO_2_XOFF_TX, priority_xoff_tx[2], TX, "priority 2 XOFF")                                   \
  _ (PRIO_3_XOFF_TX, priority_xoff_tx[3], TX, "priority 3 XOFF")                                   \
  _ (PRIO_4_XOFF_TX, priority_xoff_tx[4], TX, "priority 4 XOFF")                                   \
  _ (PRIO_5_XOFF_TX, priority_xoff_tx[5], TX, "priority 5 XOFF")                                   \
  _ (PRIO_6_XOFF_TX, priority_xoff_tx[6], TX, "priority 6 XOFF")                                   \
  _ (PRIO_7_XOFF_TX, priority_xoff_tx[7], TX, "priority 7 XOFF")                                   \
  _ (PRIO_0_XON_TO_XOFF, priority_xon_2_xoff[0], RX, "priority 0 XON to XOFF")                     \
  _ (PRIO_1_XON_TO_XOFF, priority_xon_2_xoff[1], RX, "priority 1 XON to XOFF")                     \
  _ (PRIO_2_XON_TO_XOFF, priority_xon_2_xoff[2], RX, "priority 2 XON to XOFF")                     \
  _ (PRIO_3_XON_TO_XOFF, priority_xon_2_xoff[3], RX, "priority 3 XON to XOFF")                     \
  _ (PRIO_4_XON_TO_XOFF, priority_xon_2_xoff[4], RX, "priority 4 XON to XOFF")                     \
  _ (PRIO_5_XON_TO_XOFF, priority_xon_2_xoff[5], RX, "priority 5 XON to XOFF")                     \
  _ (PRIO_6_XON_TO_XOFF, priority_xon_2_xoff[6], RX, "priority 6 XON to XOFF")                     \
  _ (PRIO_7_XON_TO_XOFF, priority_xon_2_xoff[7], RX, "priority 7 XON to XOFF")

typedef enum
{
#define _(n, m, ...) ICE_PORT_CTR_##n,
  foreach_ice_port_counter
#undef _
#define _(n, f, d, u, s) ICE_PORT_CTR_##n,
    foreach_ice_mac_counter
#undef _
#define _(n, f, d, s) ICE_PORT_CTR_##n,
      foreach_ice_priority_counter
#undef _
} ice_port_counter_id_t;

#define ICE_COUNTER_INIT_RX_BYTES(id, unused)	     VNET_DEV_CTR_RX_BYTES (id)
#define ICE_COUNTER_INIT_RX_PACKETS(id, unused)	     VNET_DEV_CTR_RX_PACKETS (id)
#define ICE_COUNTER_INIT_RX_DROPS(id, unused)	     VNET_DEV_CTR_RX_DROPS (id)
#define ICE_COUNTER_INIT_TX_BYTES(id, unused)	     VNET_DEV_CTR_TX_BYTES (id)
#define ICE_COUNTER_INIT_TX_PACKETS(id, unused)	     VNET_DEV_CTR_TX_PACKETS (id)
#define ICE_COUNTER_INIT_TX_DROPS(id, unused)	     VNET_DEV_CTR_TX_DROPS (id)
#define ICE_COUNTER_INIT_VENDOR(id, dir, unit, name) VNET_DEV_CTR_VENDOR (id, dir, unit, name)

static vnet_dev_counter_t ice_port_counters[] = {
#define _(n, m, ...) ICE_COUNTER_INIT_##m (ICE_PORT_CTR_##n, __VA_ARGS__),
  foreach_ice_port_counter
#undef _
#define _(n, f, d, u, s) VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_##n, d, u, s),
    foreach_ice_mac_counter
#undef _
#define _(n, f, d, s) VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_##n, d, PACKETS, s),
      foreach_ice_priority_counter
#undef _
};

static_always_inline u64
ice_counter_read_40 (vnet_dev_t *dev, u32 lo_reg, u32 hi_reg)
{
  u32 lo_before, lo_after, hi;

  do
    {
      lo_before = ice_reg_read (dev, lo_reg);
      hi = ice_reg_read (dev, hi_reg);
      lo_after = ice_reg_read (dev, lo_reg);
    }
  while (lo_before > lo_after);

  return (u64) lo_after | (u64) (hi & 0xff) << 32;
}

static_always_inline void
ice_counter_extend (u64 *prev, u64 *total, u64 value, u8 width, u8 valid)
{
  u64 mask = width == 32 ? 0xffffffff : 0xffffffffffULL;

  if (valid)
    *total += (value - *prev) & mask;
  *prev = value;
}

static void
ice_port_stats_update (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_port_stats_t *p = &ip->stats_prev;
  ice_port_stats_t *t = &ip->stats_total;
  u16 vsi = id->vsi_num;
  u8 lport = id->lport;
  u8 valid = ip->stats_valid;

#define ICE_EXTEND_32(field, reg, index)                                                           \
  ice_counter_extend (&p->field, &t->field, ice_reg_read (dev, reg (index)), 32, valid)
#define ICE_EXTEND_40(field, lo, hi, index)                                                        \
  ice_counter_extend (&p->field, &t->field, ice_counter_read_40 (dev, lo (index), hi (index)), 40, \
		      valid)
  ICE_EXTEND_32 (rx_discards, ICE_GLV_RDPC, vsi);
  ICE_EXTEND_40 (rx_bytes, ICE_GLV_GORCL, ICE_GLV_GORCH, vsi);
  ICE_EXTEND_40 (rx_unicast, ICE_GLV_UPRCL, ICE_GLV_UPRCH, vsi);
  ICE_EXTEND_40 (rx_multicast, ICE_GLV_MPRCL, ICE_GLV_MPRCH, vsi);
  ICE_EXTEND_40 (rx_broadcast, ICE_GLV_BPRCL, ICE_GLV_BPRCH, vsi);
  ICE_EXTEND_32 (rx_unknown_protocol, ICE_GLSWID_RUPP, vsi);
  ICE_EXTEND_40 (tx_bytes, ICE_GLV_GOTCL, ICE_GLV_GOTCH, vsi);
  ICE_EXTEND_40 (tx_unicast, ICE_GLV_UPTCL, ICE_GLV_UPTCH, vsi);
  ICE_EXTEND_40 (tx_multicast, ICE_GLV_MPTCL, ICE_GLV_MPTCH, vsi);
  ICE_EXTEND_40 (tx_broadcast, ICE_GLV_BPTCL, ICE_GLV_BPTCH, vsi);
  ICE_EXTEND_32 (tx_errors, ICE_GLV_TEPC, vsi);

  ICE_EXTEND_40 (mac_rx_bytes, ICE_GLPRT_GORCL, ICE_GLPRT_GORCH, lport);
  ICE_EXTEND_40 (mac_rx_unicast, ICE_GLPRT_UPRCL, ICE_GLPRT_UPRCH, lport);
  ICE_EXTEND_40 (mac_rx_multicast, ICE_GLPRT_MPRCL, ICE_GLPRT_MPRCH, lport);
  ICE_EXTEND_40 (mac_rx_broadcast, ICE_GLPRT_BPRCL, ICE_GLPRT_BPRCH, lport);
  ice_counter_extend (&p->mac_rx_discards, &t->mac_rx_discards, ice_reg_read (dev, ICE_PRTRPB_RDPC),
		      32, valid);
  ICE_EXTEND_32 (mac_rx_unknown_protocol, ICE_GLSWID_RUPP, lport);
  ICE_EXTEND_40 (mac_tx_bytes, ICE_GLPRT_GOTCL, ICE_GLPRT_GOTCH, lport);
  ICE_EXTEND_40 (mac_tx_unicast, ICE_GLPRT_UPTCL, ICE_GLPRT_UPTCH, lport);
  ICE_EXTEND_40 (mac_tx_multicast, ICE_GLPRT_MPTCL, ICE_GLPRT_MPTCH, lport);
  ICE_EXTEND_40 (mac_tx_broadcast, ICE_GLPRT_BPTCL, ICE_GLPRT_BPTCH, lport);
  ICE_EXTEND_32 (mac_tx_dropped_link_down, ICE_GLPRT_TDOLD, lport);
  ICE_EXTEND_32 (crc_errors, ICE_GLPRT_CRCERRS, lport);
  ICE_EXTEND_32 (illegal_bytes, ICE_GLPRT_ILLERRC, lport);
  ICE_EXTEND_32 (mac_local_faults, ICE_GLPRT_MLFC, lport);
  ICE_EXTEND_32 (mac_remote_faults, ICE_GLPRT_MRFC, lport);
  ICE_EXTEND_32 (rx_len_errors, ICE_GLPRT_RLEC, lport);
  ICE_EXTEND_32 (link_xon_rx, ICE_GLPRT_LXONRXC, lport);
  ICE_EXTEND_32 (link_xoff_rx, ICE_GLPRT_LXOFFRXC, lport);
  ICE_EXTEND_32 (link_xon_tx, ICE_GLPRT_LXONTXC, lport);
  ICE_EXTEND_32 (link_xoff_tx, ICE_GLPRT_LXOFFTXC, lport);
  ICE_EXTEND_40 (rx_size_64, ICE_GLPRT_PRC64L, ICE_GLPRT_PRC64H, lport);
  ICE_EXTEND_40 (rx_size_127, ICE_GLPRT_PRC127L, ICE_GLPRT_PRC127H, lport);
  ICE_EXTEND_40 (rx_size_255, ICE_GLPRT_PRC255L, ICE_GLPRT_PRC255H, lport);
  ICE_EXTEND_40 (rx_size_511, ICE_GLPRT_PRC511L, ICE_GLPRT_PRC511H, lport);
  ICE_EXTEND_40 (rx_size_1023, ICE_GLPRT_PRC1023L, ICE_GLPRT_PRC1023H, lport);
  ICE_EXTEND_40 (rx_size_1522, ICE_GLPRT_PRC1522L, ICE_GLPRT_PRC1522H, lport);
  ICE_EXTEND_40 (rx_size_big, ICE_GLPRT_PRC9522L, ICE_GLPRT_PRC9522H, lport);
  ICE_EXTEND_32 (rx_undersize, ICE_GLPRT_RUC, lport);
  ICE_EXTEND_32 (rx_fragments, ICE_GLPRT_RFC, lport);
  ICE_EXTEND_32 (rx_oversize, ICE_GLPRT_ROC, lport);
  ICE_EXTEND_32 (rx_jabber, ICE_GLPRT_RJC, lport);
  ICE_EXTEND_40 (tx_size_64, ICE_GLPRT_PTC64L, ICE_GLPRT_PTC64H, lport);
  ICE_EXTEND_40 (tx_size_127, ICE_GLPRT_PTC127L, ICE_GLPRT_PTC127H, lport);
  ICE_EXTEND_40 (tx_size_255, ICE_GLPRT_PTC255L, ICE_GLPRT_PTC255H, lport);
  ICE_EXTEND_40 (tx_size_511, ICE_GLPRT_PTC511L, ICE_GLPRT_PTC511H, lport);
  ICE_EXTEND_40 (tx_size_1023, ICE_GLPRT_PTC1023L, ICE_GLPRT_PTC1023H, lport);
  ICE_EXTEND_40 (tx_size_1522, ICE_GLPRT_PTC1522L, ICE_GLPRT_PTC1522H, lport);
  ICE_EXTEND_40 (tx_size_big, ICE_GLPRT_PTC9522L, ICE_GLPRT_PTC9522H, lport);
#undef ICE_EXTEND_32
#undef ICE_EXTEND_40

  for (u8 tc = 0; tc < 8; tc++)
    {
#define ICE_EXTEND_PFC(field, lo, hi)                                                              \
  ice_counter_extend (&p->field[tc], &t->field[tc],                                                \
		      ice_counter_read_40 (dev, lo (lport, tc), hi (lport, tc)), 40, valid)
      ICE_EXTEND_PFC (priority_xon_rx, ICE_GLPRT_PXONRXC, ICE_GLPRT_PXONRXC_H);
      ICE_EXTEND_PFC (priority_xoff_rx, ICE_GLPRT_PXOFFRXC, ICE_GLPRT_PXOFFRXC_H);
      ICE_EXTEND_PFC (priority_xon_tx, ICE_GLPRT_PXONTXC, ICE_GLPRT_PXONTXC_H);
      ICE_EXTEND_PFC (priority_xoff_tx, ICE_GLPRT_PXOFFTXC, ICE_GLPRT_PXOFFTXC_H);
      ICE_EXTEND_PFC (priority_xon_2_xoff, ICE_GLPRT_RXON2OFFCNT, ICE_GLPRT_RXON2OFFCNT_H);
#undef ICE_EXTEND_PFC
    }

  ip->stats_valid = 1;
}

static u64
ice_port_counter_value (vnet_dev_port_t *port, ice_port_counter_id_t id)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_port_stats_t *s = &ip->stats_total;
  u64 rx_packets = s->rx_unicast + s->rx_multicast + s->rx_broadcast;
  u64 tx_packets = s->tx_unicast + s->tx_multicast + s->tx_broadcast;

  switch (id)
    {
    case ICE_PORT_CTR_RX_BYTES:
      return s->rx_bytes >= rx_packets * 4 ? s->rx_bytes - rx_packets * 4 : 0;
    case ICE_PORT_CTR_RX_PACKETS:
      return rx_packets >= s->rx_discards ? rx_packets - s->rx_discards : 0;
    case ICE_PORT_CTR_RX_DROPS:
      return s->rx_discards;
    case ICE_PORT_CTR_RX_UNICAST:
      return s->rx_unicast;
    case ICE_PORT_CTR_RX_MULTICAST:
      return s->rx_multicast;
    case ICE_PORT_CTR_RX_BROADCAST:
      return s->rx_broadcast;
    case ICE_PORT_CTR_RX_UNKNOWN_PROTOCOL:
      return s->rx_unknown_protocol;
    case ICE_PORT_CTR_TX_BYTES:
      return s->tx_bytes;
    case ICE_PORT_CTR_TX_PACKETS:
      return tx_packets;
    case ICE_PORT_CTR_TX_DROPS:
      return s->mac_tx_dropped_link_down;
    case ICE_PORT_CTR_TX_UNICAST:
      return s->tx_unicast;
    case ICE_PORT_CTR_TX_MULTICAST:
      return s->tx_multicast;
    case ICE_PORT_CTR_TX_BROADCAST:
      return s->tx_broadcast;
    case ICE_PORT_CTR_TX_ERRORS:
      return s->tx_errors;
#define _(n, f, d, u, name)                                                                        \
  case ICE_PORT_CTR_##n:                                                                           \
    return s->f;
      foreach_ice_mac_counter
#undef _
#define _(n, f, d, name)                                                                           \
  case ICE_PORT_CTR_##n:                                                                           \
    return s->f;
	foreach_ice_priority_counter
#undef _
    }

  ASSERT (0);
  return 0;
}

vnet_dev_rv_t
ice_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, ice_port_counters, ARRAY_LEN (ice_port_counters));
  ice_port_stats_update (port);
  return VNET_DEV_OK;
}

void
ice_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_stats_update (port);

  foreach_vnet_dev_counter (c, port->counter_main)
    vnet_dev_counter_value_update (vm, c, ice_port_counter_value (port, c->user_data));
}
