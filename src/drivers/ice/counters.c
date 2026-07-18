/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/dev/counters.h>
#include <ice.h>

#define foreach_ice_std_counter                                                                    \
  _ (RX_BYTES)                                                                                     \
  _ (RX_PACKETS)                                                                                   \
  _ (RX_DROPS)                                                                                     \
  _ (TX_BYTES)                                                                                     \
  _ (TX_PACKETS)                                                                                   \
  _ (TX_DROPS)

#define foreach_ice_vsi_counter_32                                                                 \
  _ (RX_UNKNOWN_PROTOCOL, RX, PACKETS, "unknown protocol", GLSWID_RUPP)                            \
  _ (TX_ERRORS, TX, PACKETS, "errors", GLV_TEPC)

#define foreach_ice_vsi_counter_40                                                                 \
  _ (RX_UNICAST, RX, PACKETS, "unicast", UPRC)                                                     \
  _ (RX_MULTICAST, RX, PACKETS, "multicast", MPRC)                                                 \
  _ (RX_BROADCAST, RX, PACKETS, "broadcast", BPRC)                                                 \
  _ (TX_UNICAST, TX, PACKETS, "unicast", UPTC)                                                     \
  _ (TX_MULTICAST, TX, PACKETS, "multicast", MPTC)                                                 \
  _ (TX_BROADCAST, TX, PACKETS, "broadcast", BPTC)

#define foreach_ice_port_counter_32                                                                \
  _ (MAC_RX_DISCARDS, RX, PACKETS, "MAC discarded", PRTRPB_RDPC, 0)                                \
  _ (MAC_RX_UNKNOWN_PROTOCOL, RX, PACKETS, "MAC unknown protocol", GLSWID_RUPP (0), 4)

#define foreach_ice_mac_counter_32                                                                 \
  _ (MAC_TX_DROPPED_LINK_DOWN, TX, PACKETS, "MAC link down dropped", TDOLD)                        \
  _ (CRC_ERRORS, RX, PACKETS, "CRC errors", CRCERRS)                                               \
  _ (ILLEGAL_BYTES, RX, BYTES, "illegal", ILLERRC)                                                 \
  _ (MAC_LOCAL_FAULTS, RX, PACKETS, "MAC local faults", MLFC)                                      \
  _ (MAC_REMOTE_FAULTS, RX, PACKETS, "MAC remote faults", MRFC)                                    \
  _ (RX_LEN_ERRORS, RX, PACKETS, "length errors", RLEC)                                            \
  _ (LINK_XON_RX, RX, PACKETS, "link XON", LXONRXC)                                                \
  _ (LINK_XOFF_RX, RX, PACKETS, "link XOFF", LXOFFRXC)                                             \
  _ (LINK_XON_TX, TX, PACKETS, "link XON", LXONTXC)                                                \
  _ (LINK_XOFF_TX, TX, PACKETS, "link XOFF", LXOFFTXC)                                             \
  _ (RX_UNDERSIZE, RX, PACKETS, "undersize errors", RUC)                                           \
  _ (RX_FRAGMENTS, RX, PACKETS, "fragment errors", RFC)                                            \
  _ (RX_OVERSIZE, RX, PACKETS, "oversize errors", ROC)                                             \
  _ (RX_JABBER, RX, PACKETS, "jabber errors", RJC)

#define foreach_ice_mac_counter_40                                                                 \
  _ (MAC_RX_BYTES, RX, BYTES, "MAC total", GORC)                                                   \
  _ (MAC_RX_UNICAST, RX, PACKETS, "MAC unicast", UPRC)                                             \
  _ (MAC_RX_MULTICAST, RX, PACKETS, "MAC multicast", MPRC)                                         \
  _ (MAC_RX_BROADCAST, RX, PACKETS, "MAC broadcast", BPRC)                                         \
  _ (MAC_TX_BYTES, TX, BYTES, "MAC total", GOTC)                                                   \
  _ (MAC_TX_UNICAST, TX, PACKETS, "MAC unicast", UPTC)                                             \
  _ (MAC_TX_MULTICAST, TX, PACKETS, "MAC multicast", MPTC)                                         \
  _ (MAC_TX_BROADCAST, TX, PACKETS, "MAC broadcast", BPTC)                                         \
  _ (RX_SIZE_64, RX, PACKETS, "64 byte", PRC64)                                                    \
  _ (RX_SIZE_127, RX, PACKETS, "65-127 byte", PRC127)                                              \
  _ (RX_SIZE_255, RX, PACKETS, "128-255 byte", PRC255)                                             \
  _ (RX_SIZE_511, RX, PACKETS, "256-511 byte", PRC511)                                             \
  _ (RX_SIZE_1023, RX, PACKETS, "512-1023 byte", PRC1023)                                          \
  _ (RX_SIZE_1522, RX, PACKETS, "1024-1522 byte", PRC1522)                                         \
  _ (RX_SIZE_BIG, RX, PACKETS, "1523-max byte", PRC9522)                                           \
  _ (TX_SIZE_64, TX, PACKETS, "64 byte", PTC64)                                                    \
  _ (TX_SIZE_127, TX, PACKETS, "65-127 byte", PTC127)                                              \
  _ (TX_SIZE_255, TX, PACKETS, "128-255 byte", PTC255)                                             \
  _ (TX_SIZE_511, TX, PACKETS, "256-511 byte", PTC511)                                             \
  _ (TX_SIZE_1023, TX, PACKETS, "512-1023 byte", PTC1023)                                          \
  _ (TX_SIZE_1522, TX, PACKETS, "1024-1522 byte", PTC1522)                                         \
  _ (TX_SIZE_BIG, TX, PACKETS, "1523-max byte", PTC9522)

#define foreach_ice_priority_counter                                                               \
  _ (XON, 0, RX, "priority 0 XON", PXONRXC)                                                        \
  _ (XON, 1, RX, "priority 1 XON", PXONRXC)                                                        \
  _ (XON, 2, RX, "priority 2 XON", PXONRXC)                                                        \
  _ (XON, 3, RX, "priority 3 XON", PXONRXC)                                                        \
  _ (XON, 4, RX, "priority 4 XON", PXONRXC)                                                        \
  _ (XON, 5, RX, "priority 5 XON", PXONRXC)                                                        \
  _ (XON, 6, RX, "priority 6 XON", PXONRXC)                                                        \
  _ (XON, 7, RX, "priority 7 XON", PXONRXC)                                                        \
  _ (XOFF, 0, RX, "priority 0 XOFF", PXOFFRXC)                                                     \
  _ (XOFF, 1, RX, "priority 1 XOFF", PXOFFRXC)                                                     \
  _ (XOFF, 2, RX, "priority 2 XOFF", PXOFFRXC)                                                     \
  _ (XOFF, 3, RX, "priority 3 XOFF", PXOFFRXC)                                                     \
  _ (XOFF, 4, RX, "priority 4 XOFF", PXOFFRXC)                                                     \
  _ (XOFF, 5, RX, "priority 5 XOFF", PXOFFRXC)                                                     \
  _ (XOFF, 6, RX, "priority 6 XOFF", PXOFFRXC)                                                     \
  _ (XOFF, 7, RX, "priority 7 XOFF", PXOFFRXC)                                                     \
  _ (XON, 0, TX, "priority 0 XON", PXONTXC)                                                        \
  _ (XON, 1, TX, "priority 1 XON", PXONTXC)                                                        \
  _ (XON, 2, TX, "priority 2 XON", PXONTXC)                                                        \
  _ (XON, 3, TX, "priority 3 XON", PXONTXC)                                                        \
  _ (XON, 4, TX, "priority 4 XON", PXONTXC)                                                        \
  _ (XON, 5, TX, "priority 5 XON", PXONTXC)                                                        \
  _ (XON, 6, TX, "priority 6 XON", PXONTXC)                                                        \
  _ (XON, 7, TX, "priority 7 XON", PXONTXC)                                                        \
  _ (XOFF, 0, TX, "priority 0 XOFF", PXOFFTXC)                                                     \
  _ (XOFF, 1, TX, "priority 1 XOFF", PXOFFTXC)                                                     \
  _ (XOFF, 2, TX, "priority 2 XOFF", PXOFFTXC)                                                     \
  _ (XOFF, 3, TX, "priority 3 XOFF", PXOFFTXC)                                                     \
  _ (XOFF, 4, TX, "priority 4 XOFF", PXOFFTXC)                                                     \
  _ (XOFF, 5, TX, "priority 5 XOFF", PXOFFTXC)                                                     \
  _ (XOFF, 6, TX, "priority 6 XOFF", PXOFFTXC)                                                     \
  _ (XOFF, 7, TX, "priority 7 XOFF", PXOFFTXC)                                                     \
  _ (XON_TO_XOFF, 0, RX, "priority 0 XON to XOFF", RXON2OFFCNT)                                    \
  _ (XON_TO_XOFF, 1, RX, "priority 1 XON to XOFF", RXON2OFFCNT)                                    \
  _ (XON_TO_XOFF, 2, RX, "priority 2 XON to XOFF", RXON2OFFCNT)                                    \
  _ (XON_TO_XOFF, 3, RX, "priority 3 XON to XOFF", RXON2OFFCNT)                                    \
  _ (XON_TO_XOFF, 4, RX, "priority 4 XON to XOFF", RXON2OFFCNT)                                    \
  _ (XON_TO_XOFF, 5, RX, "priority 5 XON to XOFF", RXON2OFFCNT)                                    \
  _ (XON_TO_XOFF, 6, RX, "priority 6 XON to XOFF", RXON2OFFCNT)                                    \
  _ (XON_TO_XOFF, 7, RX, "priority 7 XON to XOFF", RXON2OFFCNT)

typedef enum
{
#define _(n) ICE_PORT_CTR_##n,
  foreach_ice_std_counter
#undef _
#define _(n, d, u, s, reg) ICE_PORT_CTR_##n,
    foreach_ice_vsi_counter_32
#undef _
#define _(n, d, u, s, reg) ICE_PORT_CTR_##n,
      foreach_ice_vsi_counter_40
#undef _
#define _(n, d, u, s, reg, st) ICE_PORT_CTR_##n,
	foreach_ice_port_counter_32
#undef _
#define _(n, d, u, s, reg) ICE_PORT_CTR_##n,
	  foreach_ice_mac_counter_32
#undef _
#define _(n, d, u, s, reg) ICE_PORT_CTR_##n,
	    foreach_ice_mac_counter_40
#undef _
#define _(n, prio, d, s, reg) ICE_PORT_CTR_PRIO_##prio##_##n##_##d,
	      foreach_ice_priority_counter
#undef _
		ICE_PORT_CTR_N_COUNTERS,
} ice_port_counter_id_t;

static vnet_dev_counter_t ice_port_counters[ICE_PORT_CTR_N_COUNTERS] = {
#define _(n) [ICE_PORT_CTR_##n] = VNET_DEV_CTR_##n (ICE_PORT_CTR_##n),
  foreach_ice_std_counter
#undef _
#define _(n, d, u, s, reg) [ICE_PORT_CTR_##n] = VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_##n, d, u, s),
    foreach_ice_vsi_counter_32
#undef _
#define _(n, d, u, s, reg) [ICE_PORT_CTR_##n] = VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_##n, d, u, s),
      foreach_ice_vsi_counter_40
#undef _
#define _(n, d, u, s, reg, st) [ICE_PORT_CTR_##n] = VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_##n, d, u, s),
	foreach_ice_port_counter_32
#undef _
#define _(n, d, u, s, reg) [ICE_PORT_CTR_##n] = VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_##n, d, u, s),
	  foreach_ice_mac_counter_32
#undef _
#define _(n, d, u, s, reg) [ICE_PORT_CTR_##n] = VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_##n, d, u, s),
	    foreach_ice_mac_counter_40
#undef _
#define _(n, prio, d, s, reg)                                                                      \
  [ICE_PORT_CTR_PRIO_##prio##_##n##_##d] =                                                         \
    VNET_DEV_CTR_VENDOR (ICE_PORT_CTR_PRIO_##prio##_##n##_##d, d, PACKETS, s),
	      foreach_ice_priority_counter
#undef _
};

static_always_inline u64
ice_ctr_rd40 (vnet_dev_t *dev, u32 lo_reg, u32 hi_reg)
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

typedef struct
{
  u32 lo_reg;
  u32 hi_reg;
  u8 stride;
  u8 vsi : 1;
} ice_counter_reg_t;

static ice_counter_reg_t ice_vendor_counter_regs[] = {
#define _(n, d, u, s, reg) [ICE_PORT_CTR_##n] = { .lo_reg = ICE_##reg (0), .stride = 4, .vsi = 1 },
  foreach_ice_vsi_counter_32
#undef _
#define _(n, d, u, s, reg)                                                                         \
  [ICE_PORT_CTR_##n] = {                                                                           \
    .lo_reg = ICE_GLV_##reg##L (0),                                                                \
    .hi_reg = ICE_GLV_##reg##H (0),                                                                \
    .stride = 8,                                                                                   \
    .vsi = 1,                                                                                      \
  },
    foreach_ice_vsi_counter_40
#undef _
#define _(n, d, u, s, reg, st) [ICE_PORT_CTR_##n] = { .lo_reg = ICE_##reg, .stride = st },
      foreach_ice_port_counter_32
#undef _
#define _(n, d, u, s, reg) [ICE_PORT_CTR_##n] = { .lo_reg = ICE_GLPRT_##reg (0), .stride = 8 },
	foreach_ice_mac_counter_32
#undef _
#define _(n, d, u, s, reg)                                                                         \
  [ICE_PORT_CTR_##n] = {                                                                           \
    .lo_reg = ICE_GLPRT_##reg##L (0),                                                              \
    .hi_reg = ICE_GLPRT_##reg##H (0),                                                              \
    .stride = 8,                                                                                   \
  },
	  foreach_ice_mac_counter_40
#undef _
#define _(n, prio, d, s, reg)                                                                      \
  [ICE_PORT_CTR_PRIO_##prio##_##n##_##d] = {                                                       \
    .lo_reg = ICE_GLPRT_##reg (0, prio),                                                           \
    .hi_reg = ICE_GLPRT_##reg##_H (0, prio),                                                       \
    .stride = 8,                                                                                   \
  },
	    foreach_ice_priority_counter
#undef _
};

vnet_dev_rv_t
ice_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_add_counters (vm, port, ice_port_counters, ARRAY_LEN (ice_port_counters));
  ice_port_counter_poll (vm, port);
  vnet_dev_counters_clear (vm, port->counter_main);
  return VNET_DEV_OK;
}

void
ice_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_counter_t *counter;
  u64 rx_bytes, rx_packets, rx_drops, tx_bytes, tx_packets, tx_drops, value;
  u32 counter_id, index, lo_reg, hi_reg;

  rx_packets = ice_ctr_rd40 (dev, ICE_GLV_UPRCL (id->vsi_num), ICE_GLV_UPRCH (id->vsi_num));
  rx_packets += ice_ctr_rd40 (dev, ICE_GLV_MPRCL (id->vsi_num), ICE_GLV_MPRCH (id->vsi_num));
  rx_packets += ice_ctr_rd40 (dev, ICE_GLV_BPRCL (id->vsi_num), ICE_GLV_BPRCH (id->vsi_num));
  rx_drops = ice_reg_read (dev, ICE_GLV_RDPC (id->vsi_num));
  rx_bytes = ice_ctr_rd40 (dev, ICE_GLV_GORCL (id->vsi_num), ICE_GLV_GORCH (id->vsi_num));
  rx_bytes = rx_bytes >= rx_packets * 4 ? rx_bytes - rx_packets * 4 : 0;
  rx_packets = rx_packets >= rx_drops ? rx_packets - rx_drops : 0;
  tx_bytes = ice_ctr_rd40 (dev, ICE_GLV_GOTCL (id->vsi_num), ICE_GLV_GOTCH (id->vsi_num));
  tx_packets = ice_ctr_rd40 (dev, ICE_GLV_UPTCL (id->vsi_num), ICE_GLV_UPTCH (id->vsi_num));
  tx_packets += ice_ctr_rd40 (dev, ICE_GLV_MPTCL (id->vsi_num), ICE_GLV_MPTCH (id->vsi_num));
  tx_packets += ice_ctr_rd40 (dev, ICE_GLV_BPTCL (id->vsi_num), ICE_GLV_BPTCH (id->vsi_num));
  tx_drops = ice_reg_read (dev, ICE_GLPRT_TDOLD (id->lport));

  counter = vnet_dev_port_get_counter_by_index (vm, port, ICE_PORT_CTR_RX_BYTES);
  vnet_dev_counter_value_update (vm, counter, rx_bytes);
  counter = vnet_dev_port_get_counter_by_index (vm, port, ICE_PORT_CTR_RX_PACKETS);
  vnet_dev_counter_value_update (vm, counter, rx_packets);
  counter = vnet_dev_port_get_counter_by_index (vm, port, ICE_PORT_CTR_RX_DROPS);
  vnet_dev_counter_value_update (vm, counter, rx_drops);
  counter = vnet_dev_port_get_counter_by_index (vm, port, ICE_PORT_CTR_TX_BYTES);
  vnet_dev_counter_value_update (vm, counter, tx_bytes);
  counter = vnet_dev_port_get_counter_by_index (vm, port, ICE_PORT_CTR_TX_PACKETS);
  vnet_dev_counter_value_update (vm, counter, tx_packets);
  counter = vnet_dev_port_get_counter_by_index (vm, port, ICE_PORT_CTR_TX_DROPS);
  vnet_dev_counter_value_update (vm, counter, tx_drops);

  FOREACH_ARRAY_ELT (r, ice_vendor_counter_regs)
    {
      if (r->lo_reg == 0)
	continue;

      counter_id = r - ice_vendor_counter_regs;
      counter = vnet_dev_port_get_counter_by_index (vm, port, counter_id);
      index = r->vsi ? id->vsi_num : id->lport;
      lo_reg = r->lo_reg + index * r->stride;
      hi_reg = r->hi_reg ? r->hi_reg + index * r->stride : 0;
      value = hi_reg ? ice_ctr_rd40 (dev, lo_reg, hi_reg) : ice_reg_read (dev, lo_reg);
      vnet_dev_counter_value_update (vm, counter, value);
    }
}
