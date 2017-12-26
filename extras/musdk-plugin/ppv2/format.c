/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/linux/syscall.h>
#include <vnet/plugin/plugin.h>
#include <ppv2/ppv2.h>

u8 *
format_ppv2_interface_name (u8 * s, va_list * args)
{
  ppv2_main_t *ppm = &ppv2_main;
  u32 dev_instance = va_arg (*args, u32);
  ppv2_if_t *ppif = pool_elt_at_index (ppm->interfaces, dev_instance);
  return format (s, "ppio%d/%d", ppif->ppio->pp2_id, ppif->ppio->port_id);
}

u8 *
format_ppv2_interface (u8 * s, va_list * args)
{
  ppv2_main_t *ppm = &ppv2_main;
  u32 dev_instance = va_arg (*args, u32);
  ppv2_if_t *ppif = pool_elt_at_index (ppm->interfaces, dev_instance);
  struct pp2_ppio_statistics stat;

  pp2_ppio_get_statistics (ppif->ppio, &stat, 0);

  s = format (s, "rx packets   %llu\n", stat.rx_packets);
  s = format (s, "tx packets   %llu\n", stat.tx_packets);
  s = format (s, "rx_fullq_dropped %llu\n", stat.rx_fullq_dropped);
  return s;
}

u8 *
format_ppv2_input_trace (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ppv2_input_trace_t *t = va_arg (*args, ppv2_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "ppv2: hw_if_index %d next-node %U",
	      t->hw_if_index, format_vlib_next_node_name, vm, node->index,
	      t->next_index);
  s = format (s, "\n%Ustatus %u len %u l3-type %u l3-offset %d l4-type %u "
	      "l4-offset %d is-frag %s",
	      format_white_space, indent + 2,
	      t->status, t->len, t->l3_type, t->l3_offset, t->l4_type,
	      t->l4_offset, t->isfrag ? "yes" : "no");
  s = format (s, "\n%Ucookie %x phys-addr %llx",
	      format_white_space, indent + 2, t->cookie, t->paddr);
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
