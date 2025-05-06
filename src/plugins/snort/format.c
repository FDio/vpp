
/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip4_packet.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

u8 *
format_snort_enq_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_enq_trace_t *t = va_arg (*args, snort_enq_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s,
	      "sw-if-index %u next-index %u\n"
	      "%Uinstance %u qpair %u desc-index %u\n"
	      "%Udesc: buffer-pool %u offset %u len %u address-space-id %u\n",
	      t->sw_if_index, t->next_index, format_white_space, indent,
	      t->instance, t->qpair, t->desc_index, format_white_space, indent,
	      t->desc.buffer_pool, t->desc.offset, t->desc.length,
	      t->desc.address_space_id);

  return s;
}

u8 *
format_snort_arc_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_arc_input_trace_t *t = va_arg (*args, snort_arc_input_trace_t *);

  return format (s, "sw-if-index %u instance %u", t->sw_if_index, t->instance);
}

u8 *
format_snort_deq_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_deq_trace_t *t = va_arg (*args, snort_deq_trace_t *);

  s = format (s, "snort-deq: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);

  return s;
}

u8 *
format_snort_daq_version (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  return format (s, "%u.%u.%u", (u8) (v >> 24), (u8) (v >> 16), (u8) (v >> 8));
}
