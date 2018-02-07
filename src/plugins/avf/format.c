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

  if (0);
#define _(a, b, c) else if (ad->flags & (1 << a)) \
t = format (t, "%s%s", t ? " ":"", c);
  foreach_avf_device_flags
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

  s = format (s, "flags %U", format_avf_device_flags, ad);
  if (ad->error)
    s = format (s, "\nerror %U", format_clib_error, ad->error);
  return s;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
