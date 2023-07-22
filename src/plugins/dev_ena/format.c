/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vlib/pci/pci.h"
#include "vnet/error.h"
#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_ena/ena.h>
#include <dev_ena/ena_defs.h>

u8 *
format_ena_dev_info (u8 *s, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  ena_device_t *ed = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  format (s, "Elastic Network Adapter:");
  format (s, "\n%UDevice version is %u, implementation id is %u",
	  format_white_space, indent + 2, ed->dev_attr.device_version,
	  ed->dev_attr.impl_id);
  format (s, "\n%Urx drops %lu, tx drops %lu", format_white_space, indent + 2,
	  ed->aenq.rx_drops, ed->aenq.tx_drops);
  format (s, "\n%ULast keepalive arrived ", format_white_space, indent + 2);
  if (ed->aenq.last_keepalive != 0.0)
    format (s, "%.2f seconds ago",
	    vlib_time_now (vm) - ed->aenq.last_keepalive);
  else
    format (s, "never");
  return s;
}

u8 *
format_ena_mem_addr (u8 *s, va_list *args)
{
  ena_mem_addr_t *ema = va_arg (*args, ena_mem_addr_t *);
  return format (s, "0x%lx", (u64) ema->addr_hi << 32 | ema->addr_lo);
}

u8 *
format_ena_tx_desc (u8 *s, va_list *args)
{
  ena_tx_desc_t *d = va_arg (*args, ena_tx_desc_t *);
  s =
    format (s, "addr 0x%012lx", (u64) d->buff_addr_hi << 32 | d->buff_addr_lo);
  s = format (s, " len %u", d->length);
  s = format (s, " req_id 0x%x", d->req_id_lo | d->req_id_hi << 10);
  if (d->header_length)
    s = format (s, " hdr_len %u", d->header_length);
#define _(v, n)                                                               \
  if ((v) < 6 && #n[0] != '_' && d->n)                                        \
    s = format (s, " " #n " %u", d->n);
  foreach_ena_tx_desc
#undef _
    return s;
}

u8 *
format_ena_rx_desc_status (u8 *s, va_list *args)
{
  ena_rx_cdesc_status_t st = va_arg (*args, ena_rx_cdesc_status_t);
  s = format (s, "0x%x", st.as_u32);
  if (st.as_u32 != 0)
    {
      int not_first_line = 0;
      s = format (s, " -> ");
#define _(b, n)                                                               \
  if (st.n)                                                                   \
    s = format (s, "%s%s %u", not_first_line++ ? ", " : "", #n, st.n);
      foreach_ena_rx_cdesc_status
#undef _
    }
  return s;
}

u8 *
format_ena_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ena_rx_trace_t *t = va_arg (*args, ena_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);

  s = format (
    s, "ena: %v (%d) qid %u next-node %U length %u req-id 0x%x n-desc %u",
    hi->name, t->hw_if_index, t->qid, format_vlib_next_node_name, vm,
    node->index, t->next_index, t->length, t->req_id, t->n_desc);
  s = format (s, "\n%Ustatus: %U", format_white_space, indent + 2,
	      format_ena_rx_desc_status, t->status);
  return s;
}

u8 *
format_ena_regs (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  int offset = va_arg (*args, int);
  u32 indent = format_get_indent (s);
  u32 rv = 0, f, v;
  u8 *s2 = 0;

#define _(o, r, rn, m)                                                        \
  if ((offset == -1 || offset == o) && r == 1)                                \
    {                                                                         \
      s = format (s, "\n%U", format_white_space, indent);                     \
      vec_reset_length (s2);                                                  \
      s2 = format (s2, "[0x%02x] %s:", o, #rn);                               \
      ena_reg_read (dev, o, &rv);                                             \
      s = format (s, "%-34v = 0x%08x", s2, rv);                               \
      f = 0;                                                                  \
      m                                                                       \
    }

#define __(l, fn)                                                             \
  if (#fn[0] != '_')                                                          \
    {                                                                         \
      vec_reset_length (s2);                                                  \
      s2 = format (s2, "\n%U", format_white_space, indent);                   \
      s2 = format (s2, "  [%2u:%2u] %s", f + l - 1, f, #fn);                  \
      s = format (s, "  %-35v = ", s2);                                       \
      v = (rv >> f) & pow2_mask (l);                                          \
      if (l < 3)                                                              \
	s = format (s, "%u", v);                                              \
      else if (l <= 8)                                                        \
	s = format (s, "0x%02x (%u)", v, v);                                  \
      else if (l <= 16)                                                       \
	s = format (s, "0x%04x", v);                                          \
      else                                                                    \
	s = format (s, "0x%08x", v);                                          \
    }                                                                         \
  f += l;

  foreach_ena_reg;
#undef _

  vec_free (s2);

  return s;
}
