/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <ige.h>
#include <ige_regs.h>

static u8 *
_format_ige_reg (u8 *s, u32 offset, u32 val, int no_zero, u32 mask)
{
  u32 indent = format_get_indent (s);
  u32 rv = 0, f, v;
  u8 *s2 = 0;
  int line = 0;

#define _(o, rn, m)                                                           \
  if (offset == o)                                                            \
    {                                                                         \
      if (line++)                                                             \
	s = format (s, "\n%U", format_white_space, indent);                   \
      vec_reset_length (s2);                                                  \
      s2 = format (s2, "[0x%05x] %s:", o, #rn);                               \
      rv = val;                                                               \
      s = format (s, "%-32v = 0x%08x", s2, rv);                               \
      f = 0;                                                                  \
      m                                                                       \
    }

#define __(l, fn)                                                             \
  v = (rv >> f) & pow2_mask (l);                                              \
  if ((pow2_mask (l) << f) & mask)                                            \
    if (v || (!no_zero && #fn[0] != '_'))                                     \
      {                                                                       \
	vec_reset_length (s2);                                                \
	s = format (s, "\n%U", format_white_space, indent + 2);               \
	s2 = format (s2, "[%2u:%2u] %s", f + l - 1, f, #fn);                  \
	s = format (s, "%-30v = ", s2);                                       \
	if (l < 3)                                                            \
	  s = format (s, "%u", v);                                            \
	else if (l <= 8)                                                      \
	  s = format (s, "0x%02x (%u)", v, v);                                \
	else if (l <= 16)                                                     \
	  s = format (s, "0x%04x", v);                                        \
	else                                                                  \
	  s = format (s, "0x%08x", v);                                        \
      }                                                                       \
  f += l;

  foreach_ige_reg;
#undef _

  vec_free (s2);

  return s;
}

u8 *
format_ige_reg_read (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_ige_reg (s, offset, val, 0, 0xffffffff);
}

u8 *
format_ige_reg_write (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_ige_reg (s, offset, val, 1, 0xffffffff);
}

u8 *
format_ige_reg_diff (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 old = va_arg (*args, u32);
  u32 new = va_arg (*args, u32);
  return _format_ige_reg (s, offset, new, 0, old ^ new);
}

static u8 *
format_ige_rss_type (u8 *s, va_list *args)
{
  static const char *rss_type_names[] = {
    [0x0] = "none",
    [0x1] = "HASH_TCP_IPV4",
    [0x2] = "HASH_IPV4",
    [0x3] = "HASH_TCP_IPV6",
    [0x4] = "HASH_IPV6_EX",
    [0x5] = "HASH_IPV6",
    [0x6] = "HASH_TCP_IPV6_EX",
    [0x7] = "HASH_UDP_IPV4",
    [0x8] = "HASH_UDP_IPV6",
    [0x9] = "HASH_UDP_IPV6_EX",
  };

  u32 rss_type = va_arg (*args, u32);

  if (rss_type < ARRAY_LEN (rss_type_names) && rss_type_names[rss_type])
    return format (s, "%s", rss_type_names[rss_type]);

  return format (s, "0x%x", rss_type);
}

u8 *
format_ige_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ige_port_t *ip = vnet_dev_get_port_data (port);
  ige_device_t *id = vnet_dev_get_data (port->dev);
  u32 speed = 0;
  if (id->config.supports_2_5g && ip->last_status.speed_2p5)
    speed = 2500;
  else if (ip->last_status.speed < 3)
    speed = (u32[]){ 10, 100, 1000 }[ip->last_status.speed];

  if (ip->last_status.link_up)
    s = format (s, "Link up, speed %u Mbps, duplex %s", speed,
		ip->last_status.full_duplex ? "full" : "half");
  else
    s = format (s, "Link down");
  return s;
}

u8 *
format_ige_rx_desc (u8 *s, va_list *args)
{
  const ige_rx_desc_t *d = va_arg (*args, const ige_rx_desc_t *);
  u32 indent = format_get_indent (s) + 2;
  u32 hdr_len = (d->hdr_len_hi << 10) | d->hdr_len_lo;

#define _(b) ((b) ? '+' : '-')

  s = format (
    s, "pkt_len %u vlan 0x%u hdr_len %u sph%c rss_type %U rss_hash 0x%08x",
    d->pkt_len, d->vlan_tag, hdr_len, _ (d->sph), format_ige_rss_type,
    d->rss_type, d->rss_hash);
  s = format (s,
	      "\n%Upacket_type: ip4%c ip4e%c ip6%c ip6e%c tcp%c udp%c sctp%c "
	      "nfs%c etqf %u l2pkt%c vpkt%c",
	      format_white_space, indent, _ (d->ipv4), _ (d->ipv4e),
	      _ (d->ipv6), _ (d->ipv6e), _ (d->tcp), _ (d->udp), _ (d->sctp),
	      _ (d->nfs), d->etqf, _ (d->l2pkt), _ (d->vpkt));

  s = format (s, "\n%Uext_status: dd%c eop%c", format_white_space, indent,
	      _ (d->dd), _ (d->eop));

  if (d->eop)
    {
      s = format (s, " vp%c udpcs%c l4i%c ipcs%c pif%c", _ (d->vp),
		  _ (d->udpcs), _ (d->l4i), _ (d->ipcs), _ (d->pif));
      s = format (s,
		  " vext%c udpv%c llint%c strip_crc%c smd_type %u tsip%c mc%c",
		  _ (d->vext), _ (d->udpv), _ (d->llint), _ (d->strip_crc),
		  (u32) d->smd_type, _ (d->tsip), _ (d->mc));
    }

  s = format (s, "\n%Uext_error: l4e%c ipe%c rxe%c", format_white_space,
	      indent, _ (d->l4e), _ (d->ipe), _ (d->rxe));
  if (d->sph)
    s = format (s, " hbo%c", _ (d->hbo));

#undef _

  return s;
}

u8 *
format_ige_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ige_rx_trace_t *t = va_arg (*args, ige_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);

  s = format (s, "ige: %v (%u) qid %u next-node %U buffer %u", hi->name,
	      t->hw_if_index, t->queue_id, format_vlib_next_node_name, vm,
	      node->index, t->next_index, t->buffer_index);

  s = format (s, "\n%Udesc: %U", format_white_space, indent + 2,
	      format_ige_rx_desc, &t->desc);

  return s;
}

u8 *
format_ige_tx_desc (u8 *s, va_list *args)
{
  const ige_tx_desc_t *d = va_arg (*args, const ige_tx_desc_t *);
  u32 indent = format_get_indent (s) + 2;

#define _(b) ((b) ? '+' : '-')

  s = format (
    s,
    "addr 0x%016llx dtalen %u paylen %u dtyp 0x%x ptp1 %u ptp2 %u popts 0x%x",
    d->addr, d->dtalen, d->paylen, d->dtyp, d->ptp1, d->ptp2, d->popts);

  s = format (s, "\n%Uflags: eop%c ifcs%c rs%c dext%c vle%c tse%c idx%c",
	      format_white_space, indent, _ (d->eop), _ (d->ifcs), _ (d->rs),
	      _ (d->dext), _ (d->vle), _ (d->tse), _ (d->idx));

  s = format (s, "\n%Ustatus: dd%c ts_stat%c sta 0x%x", format_white_space,
	      indent, _ (d->dd), _ (d->ts_stat), d->sta);

#undef _

  return s;
}

u8 *
format_ige_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  ige_tx_trace_t *t = va_arg (*args, ige_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);

  s = format (s, "ige-tx: %v (%u) qid %u buffer %u", hi->name, t->hw_if_index,
	      t->queue_id, t->buffer_index);

  s = format (s, "\n%Udesc: %U", format_white_space, indent + 2,
	      format_ige_tx_desc, &t->desc);

  return s;
}
u8 *
format_ige_receive_addr_table (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  u32 indent = format_get_indent (s);

  for (int i = 0; i < 16; i++)
    {
      ige_receive_addr_t ra;
      ige_reg_rd (dev, IGE_REG_RAH (i), &ra.rah);
      ige_reg_rd (dev, IGE_REG_RAL (i), &ra.ral);
      if (ra.av)
	{
	  if (i)
	    s = format (s, "\n%U", format_white_space, indent);
	  s = format (s, "[%u] %U asel %u qsel %u qsel_enable %u av %u", i,
		      format_ethernet_address, ra.hw_addr, ra.asel, ra.qsel,
		      ra.qsel_enable, ra.av);
	}
    }

  return s;
}
