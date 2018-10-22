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
  avf_main_t *am = &avf_main;
  avf_device_t *ad = vec_elt_at_index (am->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, ad->pci_dev_handle);

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
  avf_main_t *am = &avf_main;
  avf_device_t *ad = vec_elt_at_index (am->devices, i);
  u32 indent = format_get_indent (s);
  u8 *a = 0;

  s = format (s, "flags: %U", format_avf_device_flags, ad);
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

#define _(c) if (ad->eth_stats.c) \
  a = format (a, "\n%U%-20U %u", format_white_space, indent + 2, \
	      format_c_identifier, #c, ad->eth_stats.c);
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
  avf_rx_vector_entry_t *rxve = &t->rxve;

  s = format (s, "avf: %v (%d) next-node %U",
	      hi->name, t->hw_if_index, format_vlib_next_node_name, vm,
	      node->index, t->next_index);
  s = format (s, "\n%Ustatus 0x%x error 0x%x ptype 0x%x length %u",
	      format_white_space, indent + 2, rxve->status, rxve->error,
	      rxve->ptype, rxve->length);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
