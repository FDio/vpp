/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ppp/packet.h>
#include <pppoeclient/pppox/pppox.h>
#include <pppoeclient/pppox/pppd/pppd.h>

static char *pppox_error_strings[] = {
#define pppox_error(n, s) s,
#include <pppoeclient/pppox/pppox_error.def>
#undef pppox_error
};

typedef struct
{
  u32 sw_if_index;
  u32 error;
} pppox_rx_trace_t;

static u8 *
format_pppox_rx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppox_rx_trace_t *t = va_arg (*args, pppox_rx_trace_t *);

  s = format (s, "PPPoX sw_if_index %u error %u", t->sw_if_index, t->error);
  return s;
}

static uword
pppox_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 pppox_pkts = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = PPPOX_INPUT_NEXT_DROP;
	  u32 error0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  pppox_pkts++;

	  /* Consume the control packet locally via pppd shim. */
	  if (consume_pppox_ctrl_pkt (bi0, b0) != 0)
	    error0 = PPPOX_ERROR_CONTROL_PLANE_DISABLED;

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppox_rx_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      tr->error = error0;
	    }

	  /* Route consumed buffer to error-drop so VPP graph frees it safely. */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, pppox_input_node.index, PPPOX_ERROR_TOTAL_RX_CTRL_PKTS,
			       pppox_pkts);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppox_input_node) = {
  .function = pppox_input,
  .name = "pppox-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PPPOX_N_ERROR,
  .error_strings = pppox_error_strings,

  .n_next_nodes = PPPOX_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [PPPOX_INPUT_NEXT_##s] = n,
    foreach_pppox_input_next
#undef _
  },

  .format_trace = format_pppox_rx_trace,
};

static u32 pppox_tx_node_index = ~0;

/* Resolve "pppoeclient-session-output" on the main thread at plugin init so
 * pppox TX enters the session-output node directly.  The former pppox-output
 * pass-through node only existed to create this edge lazily; merging it away
 * removes a graph hop and its cross-thread interface-stats state. */
void
pppox_resolve_tx_node (vlib_main_t *vm)
{
  vlib_node_t *tx = vlib_get_node_by_name (vm, (u8 *) "pppoeclient-session-output");

  if (tx)
    {
      pppox_tx_node_index = tx->index;
      return;
    }

  clib_warning ("pppox: pppoeclient-session-output node not found");
  tx = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  pppox_tx_node_index = tx ? tx->index : ~0;
}

u32
pppox_get_tx_node_index (void)
{
  return pppox_tx_node_index;
}

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
