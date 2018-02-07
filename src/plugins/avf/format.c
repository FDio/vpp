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
  u32 i = va_arg (*args, u32);
  avf_main_t *am = &avf_main;
  avf_device_t *ad = vec_elt_at_index (am->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (ad->pci_dev_handle);

  s = format (s, "VirtualFunction%x/%x/%x/%x",
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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
