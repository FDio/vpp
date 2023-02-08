/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <ena/ena.h>
#include <ena/ena_defs.h>
#include <ena/ena_inlines.h>

ena_admin_feature_info_t ena_admin_feature_info[] = {
#define _(v, ver, n, s)                                                       \
  [v] = { .name = #n, .version = (ver), .data_sz = sizeof (s) },
  foreach_ena_aq_feat_id
#undef _
};

u8 *
format_ena_device_name (u8 *s, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 i = va_arg (*args, u32);
  ena_device_t *ed = ena_get_device (i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, ed->pci_dev_handle);

  if (ed->name)
    return format (s, "%s", ed->name);

  s = format (s, "ena-%x/%x/%x/%x", addr->domain, addr->bus, addr->slot,
	      addr->function);
  return s;
}

u8 *
format_ena_device_flags (u8 *s, va_list *args)
{
  ena_device_t *ed = va_arg (*args, ena_device_t *);
  u8 *t = 0;

#define _(f)                                                                  \
  if (ed->f)                                                                  \
    t = format (t, "%s%s", t ? " " : "", #f);
  foreach_ena_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_ena_device (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  ena_device_t *ed = ena_get_device (i);
  u32 indent = format_get_indent (s);
  u8 *a = 0;
  ena_rxq_t *rxq = vec_elt_at_index (ed->rxqs, 0);
  ena_txq_t *txq = vec_elt_at_index (ed->txqs, 0);

  s = format (s, "rx: queues %u, desc %u (min %u max %u)", ed->n_rx_queues,
	      rxq->n_desc, 0, 0);
  s = format (s, "\n%Utx: queues %u, desc %u (min %u max %u)",
	      format_white_space, indent, ed->n_tx_queues, txq->n_desc, 0, 0);
  s = format (s, "\n%Uflags: %U", format_white_space, indent,
	      format_ena_device_flags, ed);
  if (ed->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, ed->error);

  if (a)
    s = format (s, "\n%Ustats:%v", format_white_space, indent, a);

  vec_free (a);
  return s;
}

u8 *
format_ena_input_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ena_input_trace_t *t = va_arg (*args, ena_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "ena: %v (%d) qid %u next-node %U", hi->name, t->hw_if_index,
	      t->qid, format_vlib_next_node_name, vm, node->index,
	      t->next_index);

  return s;
}

u8 *
format_ena_regs (u8 *s, va_list *args)
{
  ena_device_t *ed = va_arg (*args, ena_device_t *);
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
      ena_reg_read (ed, o, &rv);                                              \
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

u8 *
format_ena_mem_addr (u8 *s, va_list *args)
{
  ena_mem_addr_t *ema = va_arg (*args, ena_mem_addr_t *);
  return format (s, "0x%lx", (u64) ema->addr_hi << 32 | ema->addr_lo);
}

u8 *
format_ena_aq_feat_id_bitmap (u8 *s, va_list *args)
{
  u32 bmp = va_arg (*args, u32);
  int i, not_first = 0;

  foreach_set_bit_index (i, bmp)
    {
      if (i >= ARRAY_LEN (ena_admin_feature_info) ||
	  ena_admin_feature_info[i].name == 0)
	s = format (s, "%sunknown-%u", not_first++ ? ", " : "", i);
      else
	s = format (s, "%s%s", not_first++ ? ", " : "",
		    ena_admin_feature_info[i].name);
    }

  return s;
}
