
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

  s =
    format (s, "sw-if-index %u next-index %u", t->sw_if_index, t->next_index);
  s = format (s, "\n%Uinstance %u qpair %u.%u", format_white_space, indent,
	      t->instance, t->qpair_id.thread_id, t->qpair_id.queue_id);
  s =
    format (s, "\n%Udesc: buffer-pool %u offset %u len %u", format_white_space,
	    indent, t->desc.buffer_pool, t->desc.offset, t->desc.length);
  s =
    format (s, "\n%Umetadata: address-space-id %u flags 0x%x ingress_index %d",
	    format_white_space, indent, t->desc.metadata.address_space_id,
	    t->desc.metadata.flags, t->desc.metadata.ingress_index);

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
  u32 indent = format_get_indent (s);

  s = format (s, "snort-deq: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);
  s = format (s, "%U buffer index %d, verdict %U", format_white_space, indent,
	      t->buffer_index, format_snort_verdict, t->verdict);

  return s;
}

u8 *
format_snort_arc_next_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_arc_next_trace_t *t = va_arg (*args, snort_arc_next_trace_t *);

  return format (s, "buffer-index %u next_index %u", t->buffer_index,
		 t->next_index);
}

u8 *
format_snort_daq_version (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  return format (s, "%u.%u.%u", (u8) (v >> 24), (u8) (v >> 16), (u8) (v >> 8));
}

u8 *
format_snort_verdict (u8 *s, va_list *args)
{
  daq_vpp_verdict_t v = va_arg (*args, daq_vpp_verdict_t);
  static char *strings[DAQ_VPP_MAX_DAQ_VERDICT] = {
    [DAQ_VPP_VERDICT_PASS] = "PASS",
    [DAQ_VPP_VERDICT_BLOCK] = "BLOCK",
    [DAQ_VPP_VERDICT_REPLACE] = "REPLACE",
    [DAQ_VPP_VERDICT_WHITELIST] = "WHITELIST",
    [DAQ_VPP_VERDICT_BLACKLIST] = "BLACKLIST",
    [DAQ_VPP_VERDICT_IGNORE] = "IGNORE",
  };

  if (v >= DAQ_VPP_MAX_DAQ_VERDICT || strings[v] == 0)
    return format (s, "unknown (%d)", v);

  return format (s, "%s", strings[v]);
}

u8 *
format_snort_mode (u8 *s, va_list *args)
{
  daq_vpp_mode_t v = va_arg (*args, daq_vpp_mode_t);
  static char *strings[DAQ_VPP_MAX_DAQ_MODE] = {
    [DAQ_VPP_MODE_NONE] = "none",
    [DAQ_VPP_MODE_PASSIVE] = "passive",
    [DAQ_VPP_MODE_INLINE] = "inline",
    [DAQ_VPP_MODE_READ_FILE] = "read-file",
  };

  if (v >= DAQ_VPP_MAX_DAQ_MODE || strings[v] == 0)
    return format (s, "unknown (%d)", v);

  return format (s, "%s", strings[v]);
}

u8 *
format_snort_desc (u8 *s, va_list *args)
{
  daq_vpp_desc_t *d = va_arg (*args, daq_vpp_desc_t *);

  s = format (s, "desc: buffer-pool %u offset %u length %u", d->buffer_pool,
	      d->offset, d->length);
  return s;
}
