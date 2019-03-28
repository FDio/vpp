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

#include <rdma/rdma.h>

u8 *
format_rdma_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, i);

  if (rd->name)
    return format (s, "%s", rd->name);

  s = format (s, "rdma-%u", rd->dev_instance);
  return s;
}

u8 *
format_rdma_device_flags (u8 * s, va_list * args)
{
  rdma_device_t *rd = va_arg (*args, rdma_device_t *);
  u8 *t = 0;

#define _(a, b, c) if (rd->flags & (1 << a)) \
t = format (t, "%s%s", t ? " ":"", c);
  foreach_rdma_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_rdma_device (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, i);
  u32 indent = format_get_indent (s);

  s = format (s, "flags: %U", format_rdma_device_flags, rd);
  if (rd->error)
    s = format (s, "\n%Uerror %U", format_white_space, indent,
		format_clib_error, rd->error);

  return s;
}

u8 *
format_rdma_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  rdma_input_trace_t *t = va_arg (*args, rdma_input_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "rdma: %v (%d) next-node %U",
	      hi->name, t->hw_if_index, format_vlib_next_node_name, vm,
	      node->index, t->next_index);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
