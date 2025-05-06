#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <stdbool.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */


#include "gpcapng.h"
#include "gpcapng_node.h"


static char *pcapng_capture_error_strings[] = {
#define _(sym, string) string,
  foreach_pcapng_capture_error
#undef _
};

static u8 *
format_pcapng_capture_trace (u8 *s, va_list *args)
{
  // int i;
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pcapng_capture_trace_t *t = va_arg (*args, pcapng_capture_trace_t *);

  // u32 indent = format_get_indent (s);

  s = format (s, "PCAPNG: sw_if_index %d elapsed %ld, dest_index %d", t->sw_if_index, t->elapsed, t->dest_index);
  return s;
}

/* Node registration */
vlib_node_registration_t gpcapng_node_out;
vlib_node_registration_t gpcapng_node_in;

VLIB_REGISTER_NODE (gpcapng_node_out) = {
  .name = "geneve-pcapng-capture-out",
  .vector_size = sizeof (u32),
  .format_trace = format_pcapng_capture_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pcapng_capture_error_strings),
  .error_strings = pcapng_capture_error_strings,

  // Specify next nodes if any
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (gpcapng_node_in) = {
  .name = "geneve-pcapng-capture-in",
  .vector_size = sizeof (u32),
  .format_trace = format_pcapng_capture_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pcapng_capture_error_strings),
  .error_strings = pcapng_capture_error_strings,

  // Specify next nodes if any
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VNET_FEATURE_INIT (gpcapng_feature_out, static) = {
  .arc_name = "interface-output",
  .node_name = "geneve-pcapng-capture-out",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

VNET_FEATURE_INIT (gpcapng_feature_in, static) = {
  .arc_name = "device-input",
  .node_name = "geneve-pcapng-capture-in",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

