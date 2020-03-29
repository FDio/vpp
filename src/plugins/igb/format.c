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

#include <igb/igb.h>

u8 *
format_igb_device_name (u8 * s, va_list * args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 i = va_arg (*args, u32);
  igb_main_t *am = &igb_main;
  igb_device_t *ad = vec_elt_at_index (am->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, ad->pci_dev_handle);

  if (ad->name)
    return format (s, "%s", ad->name);

  s = format (s, "igb-%x/%x/%x/%x",
	      addr->domain, addr->bus, addr->slot, addr->function);
  return s;
}

u8 *
format_igb_device_flags (u8 * s, va_list * args)
{
  igb_device_t *ad = va_arg (*args, igb_device_t *);
  u8 *t = 0;

#define _(a, b, c) if (ad->flags & (1 << a)) \
t = format (t, "%s%s", t ? " ":"", c);
  foreach_igb_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_igb_device (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  igb_main_t *am = &igb_main;
  igb_device_t *ad = vec_elt_at_index (am->devices, i);
  u32 indent = format_get_indent (s);
  u8 *a = 0;

  s = format (s, "flags: %U", format_igb_device_flags, ad);

  if (ad->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, ad->error);

  if (a)
    s = format (s, "\n%Ustats:%v", format_white_space, indent, a);

  vec_free (a);
  return s;
}

u8 *
format_igb_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  igb_input_trace_t *t = va_arg (*args, igb_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);
  int i = 0;

  s = format (s, "igb: %v (%d) qid %u next-node %U",
	      hi->name, t->hw_if_index, t->qid, format_vlib_next_node_name,
	      vm, node->index, t->next_index);

  do
    {
      s = format (s, "\n%Udesc %u: status 0x%x error 0x%x ptype 0x%x len %u",
		  format_white_space, indent + 2, i,
		  t->qw1s[i] & pow2_mask (19),
		  (t->qw1s[i] >> IGB_RXD_ERROR_SHIFT) & pow2_mask (8),
		  (t->qw1s[i] >> IGB_RXD_PTYPE_SHIFT) & pow2_mask (8),
		  (t->qw1s[i] >> IGB_RXD_LEN_SHIFT));
    }
  while ((t->qw1s[i++] & IGB_RXD_STATUS_EOP) == 0 &&
	 i < IGB_RX_MAX_DESC_IN_CHAIN);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
