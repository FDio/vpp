/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <pp2/pp2.h>

u8 *
format_mvpp2_port_link_info (u8 *s, va_list *args)
{
  mvpp2_port_link_info_t *li = va_arg (*args, mvpp2_port_link_info_t *);
  mvpp2_port_t *mp = va_arg (*args, mvpp2_port_t *);

  s = format (s, "duplex %s speed %u up %d phy_mode %s", li->full_duplex ? "full" : "half",
	      li->speed / 1000, li->up, mp->phy_mode);

  return s;
}

u8 *
format_mvpp2_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_port_link_info_t li = {};

  if (!mp->is_open)
    return format (s, "link info not available");

  mvpp2_gop_get_link_info (port, &li);
  return format (s, "%U", format_mvpp2_port_link_info, &li, mp);
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

u8 *
format_mvpp2_rx_desc (u8 *s, va_list *args)

{
  mvpp2_rx_desc_t *d = va_arg (*args, mvpp2_rx_desc_t *);
  u32 indent = format_get_indent (s);
  u32 r32;

#define _(n, w)                                                                                    \
  r32 = d->n;                                                                                      \
  if (r32 > 9)                                                                                     \
    s = format (s, "%s %u (0x%x)", #n, r32, r32);                                                  \
  else                                                                                             \
    s = format (s, "%s %u", #n, r32);                                                              \
  if (format_get_indent (s) > 72)                                                                  \
    s = format (s, "\n%U", format_white_space, indent + 2);                                        \
  else                                                                                             \
    s = format (s, " ");

#define R(w)
  foreach_mvpp2_rx_desc_field;
#undef R
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
  u32 indent = format_get_indent (s);
  mvpp2_rx_desc_t *d = &t->desc;

  if (t->sw_if_index != CLIB_U32_MAX)
    s = format (s, "pp2: %U (%d) next-node %U", format_vnet_sw_if_index_name,
		vnm, t->sw_if_index, t->sw_if_index,
		format_vlib_next_node_name, vm, node->index, t->next_index);
  else
    s = format (s, "pp2: next-node %U", format_vlib_next_node_name, vm,
		node->index, t->next_index);

  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_mvpp2_rx_desc, d);

  return s;
}
