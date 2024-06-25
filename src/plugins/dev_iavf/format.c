/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <dev_iavf/iavf.h>
#include <dev_iavf/virtchnl.h>

u8 *
format_iavf_vf_cap_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  int not_first = 0;

  char *strs[32] = {
#define _(a, b, c) [a] = c,
    foreach_iavf_vf_cap_flag
#undef _
  };

  for (int i = 0; i < 32; i++)
    {
      if ((flags & (1 << i)) == 0)
	continue;
      if (not_first)
	s = format (s, " ");
      if (strs[i])
	s = format (s, "%s", strs[i]);
      else
	s = format (s, "unknown(%u)", i);
      not_first = 1;
    }
  return s;
}

u8 *
format_iavf_rx_desc_qw1 (u8 *s, va_list *args)
{
  iavf_rx_desc_qw1_t *qw1 = va_arg (*args, iavf_rx_desc_qw1_t *);
  s = format (s, "len %u ptype %u ubmcast %u fltstat %u flags", qw1->length,
	      qw1->ptype, qw1->ubmcast, qw1->fltstat);

#define _(f)                                                                  \
  if (qw1->f)                                                                 \
  s = format (s, " " #f)

  _ (dd);
  _ (eop);
  _ (l2tag1p);
  _ (l3l4p);
  _ (crcp);
  _ (flm);
  _ (lpbk);
  _ (ipv6exadd);
  _ (int_udp_0);
  _ (ipe);
  _ (l4e);
  _ (oversize);
#undef _
  return s;
}

u8 *
format_iavf_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  iavf_rx_trace_t *t = va_arg (*args, iavf_rx_trace_t *);
  iavf_rx_desc_qw1_t *qw1;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);
  int i = 0;

  s = format (s, "avf: %v (%d) qid %u next-node %U flow-id %u", hi->name,
	      t->hw_if_index, t->qid, format_vlib_next_node_name, vm,
	      node->index, t->next_index, t->flow_id);

  qw1 = (iavf_rx_desc_qw1_t *) t->qw1s;

  do
    s = format (s, "\n%Udesc %u: %U", format_white_space, indent + 2, i,
		format_iavf_rx_desc_qw1, qw1 + i);
  while ((qw1[i++].eop) == 0 && i < IAVF_RX_MAX_DESC_IN_CHAIN);

  return s;
}

u8 *
format_iavf_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  s = format (s, "caps: %U", format_iavf_vf_cap_flags, ap->vf_cap_flags);
  s = format (s, "\n%Uvsi is %u, RSS key size is %u, RSS lut size is %u",
	      format_white_space, indent, ap->vsi_id, ap->rss_key_size,
	      ap->rss_lut_size);
  s = format (s, "\n%Uflow offload ", format_white_space, indent);
  if (ap->flow_offload)
    s = format (s, "enabled, %u flows configured",
		vec_len (ap->flow_lookup_entries));
  else
    s = format (s, "disabled");
  return s;
}
