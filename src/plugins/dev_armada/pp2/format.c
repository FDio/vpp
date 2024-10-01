/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <dev_armada/musdk.h>
#include <dev_armada/pp2/pp2.h>

static inline u32
mrvl_get_u32_bits (void *start, int offset, int first, int last)
{
  u32 value = *(u32 *) (((u8 *) start) + offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

u8 *
format_pp2_ppio_link_info (u8 *s, va_list *args)
{
  struct pp2_ppio_link_info *li = va_arg (*args, struct pp2_ppio_link_info *);

  char *port_duplex[] = {
    [MV_NET_LINK_DUPLEX_HALF] = "half",
    [MV_NET_LINK_DUPLEX_FULL] = "full",
  };

  u32 port_speeds[] = {
    [MV_NET_LINK_SPEED_10] = 10,       [MV_NET_LINK_SPEED_100] = 100,
    [MV_NET_LINK_SPEED_1000] = 1000,   [MV_NET_LINK_SPEED_2500] = 2500,
    [MV_NET_LINK_SPEED_10000] = 10000,
  };

  char *port_phy_modes[] = {
    [MV_NET_PHY_MODE_NONE] = "NONE",
    [MV_NET_PHY_MODE_MII] = "MII",
    [MV_NET_PHY_MODE_GMII] = "GMII",
    [MV_NET_PHY_MODE_SGMII] = "SGMII",
    [MV_NET_PHY_MODE_TBI] = "TBI",
    [MV_NET_PHY_MODE_REVMII] = "REVMII",
    [MV_NET_PHY_MODE_RMII] = "RMII",
    [MV_NET_PHY_MODE_RGMII] = "RGMII",
    [MV_NET_PHY_MODE_RGMII_ID] = "RGMII_ID",
    [MV_NET_PHY_MODE_RGMII_RXID] = "RGMII_RXID",
    [MV_NET_PHY_MODE_RGMII_TXID] = "RGMII_TXID",
    [MV_NET_PHY_MODE_RTBI] = "RTBI",
    [MV_NET_PHY_MODE_SMII] = "SMII",
    [MV_NET_PHY_MODE_XGMII] = "XGMII",
    [MV_NET_PHY_MODE_MOCA] = "MOCA",
    [MV_NET_PHY_MODE_QSGMII] = "QSGMII",
    [MV_NET_PHY_MODE_XAUI] = "XAUI",
    [MV_NET_PHY_MODE_RXAUI] = "RXAUI",
    [MV_NET_PHY_MODE_KR] = "KR",
  };

  s =
    format (s, "duplex %s speed %d up %d phy_mode %s", port_duplex[li->duplex],
	    port_speeds[li->speed], li->up, port_phy_modes[li->phy_mode]);

  return s;
}

u8 *
format_mvpp2_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio_link_info li = {};

  if (mp->ppio == 0 || pp2_ppio_get_link_info (mp->ppio, &li))
    return format (s, "link info not available");

  return format (s, "%U", format_pp2_ppio_link_info, &li);
}

u8 *
format_mvpp2_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  format (s, "pp_id is %u", md->pp_id);
  return s;
}

#define foreach_pp2_rx_desc_field                                             \
  _ (0x00, 6, 0, l3_offset)                                                   \
  _ (0x00, 12, 8, ip_hdlen)                                                   \
  _ (0x00, 14, 13, ec)                                                        \
  _ (0x00, 15, 15, es)                                                        \
  _ (0x00, 19, 16, pool_id)                                                   \
  _ (0x00, 21, 21, hwf_sync)                                                  \
  _ (0x00, 22, 22, l4_chk_ok)                                                 \
  _ (0x00, 23, 23, ip_frg)                                                    \
  _ (0x00, 24, 24, ipv4_hdr_err)                                              \
  _ (0x00, 27, 25, l4_info)                                                   \
  _ (0x00, 30, 28, l3_info)                                                   \
  _ (0x00, 31, 31, buf_header)                                                \
  _ (0x04, 5, 0, lookup_id)                                                   \
  _ (0x04, 8, 6, cpu_code)                                                    \
  _ (0x04, 9, 9, pppoe)                                                       \
  _ (0x04, 11, 10, l3_cast_info)                                              \
  _ (0x04, 13, 12, l2_cast_info)                                              \
  _ (0x04, 15, 14, vlan_info)                                                 \
  _ (0x04, 31, 16, byte_count)                                                \
  _ (0x08, 11, 0, gem_port_id)                                                \
  _ (0x08, 13, 12, color)                                                     \
  _ (0x08, 14, 14, gop_sop_u)                                                 \
  _ (0x08, 15, 15, key_hash_enable)                                           \
  _ (0x08, 31, 16, l4chk)                                                     \
  _ (0x0c, 31, 0, timestamp)                                                  \
  _ (0x10, 31, 0, buf_phys_ptr_lo)                                            \
  _ (0x14, 7, 0, buf_phys_ptr_hi)                                             \
  _ (0x14, 31, 8, key_hash)                                                   \
  _ (0x18, 31, 0, buf_virt_ptr_lo)                                            \
  _ (0x1c, 7, 0, buf_virt_ptr_hi)                                             \
  _ (0x1c, 14, 8, buf_qset_no)                                                \
  _ (0x1c, 15, 15, buf_type)                                                  \
  _ (0x1c, 21, 16, mod_dscp)                                                  \
  _ (0x1c, 24, 22, mod_pri)                                                   \
  _ (0x1c, 25, 25, mdscp)                                                     \
  _ (0x1c, 26, 26, mpri)                                                      \
  _ (0x1c, 27, 27, mgpid)                                                     \
  _ (0x1c, 31, 29, port_num)

u8 *
format_mvpp2_rx_desc (u8 *s, va_list *args)

{
  struct pp2_ppio_desc *d = va_arg (*args, struct pp2_ppio_desc *);
  u32 indent = format_get_indent (s);
  u32 r32;

#define _(a, b, c, n)                                                         \
  r32 = mrvl_get_u32_bits (d, a, b, c);                                       \
  if (r32 > 9)                                                                \
    s = format (s, "%s %u (0x%x)", #n, r32, r32);                             \
  else                                                                        \
    s = format (s, "%s %u", #n, r32);                                         \
  if (format_get_indent (s) > 72)                                             \
    s = format (s, "\n%U", format_white_space, indent + 2);                   \
  else                                                                        \
    s = format (s, " ");

  foreach_pp2_rx_desc_field;
#undef _
  return s;
}

u8 *
format_mv_dsa_tag (u8 *s, va_list *args)
{
  mv_dsa_tag_t *tag = va_arg (*args, mv_dsa_tag_t *);

#define _(b, n)                                                               \
  if (#n[0] != '_')                                                           \
    s = format (s, " " #n " %u", tag->n);
  foreach_mv_dsa_tag_field
#undef _
    return s;
}

u8 *
format_mvpp2_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  mvpp2_rx_trace_t *t = va_arg (*args, mvpp2_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = vnet_dev_port_get_intf_hw_if_index (t->rxq->port);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  u32 indent = format_get_indent (s);
  struct pp2_ppio_desc *d = &t->desc;

  s = format (s, "pp2: %v (%d) next-node %U", hi->name, hw_if_index,
	      format_vlib_next_node_name, vm, node->index, t->rxq->next_index);
  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_mvpp2_rx_desc, d);

  return s;
}
