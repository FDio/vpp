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

#include <vmxnet3/vmxnet3.h>

u8 *
format_vmxnet3_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  vmxnet3_main_t *am = &vmxnet3_main;
  vmxnet3_device_t *ad = vec_elt_at_index (am->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (ad->pci_dev_handle);

  s = format (s, "VMXNET3%x/%x/%x/%x",
	      addr->domain, addr->bus, addr->slot, addr->function);
  return s;
}

u8 *
format_vmxnet3_device_flags (u8 * s, va_list * args)
{
  vmxnet3_device_t *ad = va_arg (*args, vmxnet3_device_t *);
  u8 *t = 0;

#define _(a, b, c) if (ad->flags & (1 << a)) \
t = format (t, "%s%s", t ? " ":"", c);
  foreach_vmxnet3_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_vmxnet3_device (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  vmxnet3_main_t *am = &vmxnet3_main;
  vmxnet3_device_t *ad = vec_elt_at_index (am->devices, i);

  s = format (s, "flags: %U", format_vmxnet3_device_flags, ad);
  return s;
}

u8 *
format_vmxnet3_input_trace (u8 * s, va_list * args)
{
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
