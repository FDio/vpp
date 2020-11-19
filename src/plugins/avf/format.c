/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>

u8 *
format_avf_device_name (u8 * s, va_list * args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 i = va_arg (*args, u32);
  avf_device_t *ad = avf_get_device (i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, ad->pci_dev_handle);

  if (ad->name)
    return format (s, "%s", ad->name);

  s = format (s, "avf-%x/%x/%x/%x",
	      addr->domain, addr->bus, addr->slot, addr->function);
  return s;
}

u8 *
format_avf_device_flags (u8 * s, va_list * args)
{
  avf_device_t *ad = va_arg (*args, avf_device_t *);
  u8 *t = 0;

#define _(a, b, c) if (ad->flags & (1 << a)) \
t = format (t, "%s%s", t ? " ":"", c);
  foreach_avf_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_avf_vf_cap_flags (u8 * s, va_list * args)
{
  u32 flags = va_arg (*args, u32);
  u8 *t = 0;

#define _(a, b, c) if (flags & (1 << a)) \
  t = format (t, "%s%s", t ? " ":"", c);
  foreach_avf_vf_cap_flag;
#undef _
  s = format (s, "%v", t);
  vec_free (t);
  return s;
}

static u8 *
format_virtchnl_link_speed (u8 * s, va_list * args)
{
  virtchnl_link_speed_t speed = va_arg (*args, virtchnl_link_speed_t);

  if (speed == 0)
    return format (s, "unknown");
#define _(a, b, c) \
  else if (speed == VIRTCHNL_LINK_SPEED_##b) \
    return format (s, c);
  foreach_virtchnl_link_speed;
#undef _
  return s;
}

u8 *
format_avf_device (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  avf_device_t *ad = avf_get_device (i);
  u32 indent = format_get_indent (s);
  u8 *a = 0;
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, 0);
  avf_txq_t *txq = vec_elt_at_index (ad->txqs, 0);

  s = format (s, "rx: queues %u, desc %u (min %u max %u)", ad->n_rx_queues,
	      rxq->size, AVF_QUEUE_SZ_MIN, AVF_QUEUE_SZ_MAX);
  s = format (s, "\n%Utx: queues %u, desc %u (min %u max %u)",
	      format_white_space, indent, ad->n_tx_queues, txq->size,
	      AVF_QUEUE_SZ_MIN, AVF_QUEUE_SZ_MAX);
  s = format (s, "\n%Uflags: %U", format_white_space, indent,
	      format_avf_device_flags, ad);
  s = format (s, "\n%Uoffload features: %U", format_white_space, indent,
	      format_avf_vf_cap_flags, ad->feature_bitmap);

  s = format (s, "\n%Unum-queue-pairs %d max-vectors %u max-mtu %u "
	      "rss-key-size %u rss-lut-size %u", format_white_space, indent,
	      ad->num_queue_pairs, ad->max_vectors, ad->max_mtu,
	      ad->rss_key_size, ad->rss_lut_size);
  s = format (s, "\n%Uspeed %U", format_white_space, indent,
	      format_virtchnl_link_speed, ad->link_speed);
  if (ad->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, ad->error);

#define _(c) if (ad->eth_stats.c - ad->last_cleared_eth_stats.c) \
  a = format (a, "\n%U%-20U %u", format_white_space, indent + 2, \
	      format_c_identifier, #c,                           \
              ad->eth_stats.c - ad->last_cleared_eth_stats.c);
  foreach_virtchnl_eth_stats;
#undef _
  if (a)
    s = format (s, "\n%Ustats:%v", format_white_space, indent, a);

  vec_free (a);
  return s;
}

u8 *
format_avf_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  avf_input_trace_t *t = va_arg (*args, avf_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);
  int i = 0;

  s = format (s, "avf: %v (%d) qid %u next-node %U flow-id %u",
	      hi->name, t->hw_if_index, t->qid, format_vlib_next_node_name,
	      vm, node->index, t->next_index, t->flow_id);

  do
    {
      s = format (s, "\n%Udesc %u: status 0x%x error 0x%x ptype 0x%x len %u",
		  format_white_space, indent + 2, i,
		  t->qw1s[i] & pow2_mask (19),
		  (t->qw1s[i] >> AVF_RXD_ERROR_SHIFT) & pow2_mask (8),
		  (t->qw1s[i] >> AVF_RXD_PTYPE_SHIFT) & pow2_mask (8),
		  (t->qw1s[i] >> AVF_RXD_LEN_SHIFT));
    }
  while ((t->qw1s[i++] & AVF_RXD_STATUS_EOP) == 0 &&
	 i < AVF_RX_MAX_DESC_IN_CHAIN);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
