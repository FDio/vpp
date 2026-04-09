/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#include <vnet/flow/flow.h>
#include <sfdp_services/base/verdict-testbench/verdict_testbench.h>

SFDP_SERVICE_DECLARE (verdict_testbench)

/*
 * TODO - Use session->unused0[0..1] as a u16 packet counter for forward/reverse traffic .
 * This should not conflict with other patches modfiying sfdp_session_t (i.e. patch adding sfdp
 * lookup offload) which adds new fields before unused0 */
#define VT_SESSION_PKT_COUNT(s) (*(u16 *) &(s)->unused0[0])

#define foreach_verdict_testbench_error                                                            \
  _ (PASS, "pass-through")                                                                         \
  _ (OFFLOADED, "verdict offloaded")                                                               \
  _ (KEPT, "kept in VPP")                                                                          \
  _ (OFFLOAD_FAILED, "offload failed")

typedef enum
{
#define _(sym, str) VERDICT_TESTBENCH_ERROR_##sym,
  foreach_verdict_testbench_error
#undef _
    VERDICT_TESTBENCH_N_ERROR,
} verdict_testbench_error_t;

static char *verdict_testbench_error_strings[] = {
#define _(sym, string) string,
  foreach_verdict_testbench_error
#undef _
};

typedef struct
{
  u32 flow_id;
  u16 pkt_count;
  u8 offloaded;
} verdict_testbench_trace_t;

static u8 *
format_verdict_testbench_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  verdict_testbench_trace_t *t = va_arg (*args, verdict_testbench_trace_t *);

  s = format (s,
	      "verdict-testbench: flow-id %u (session %u, %s) "
	      "pkt_count %u offloaded %u",
	      t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward", t->pkt_count,
	      t->offloaded);
  return s;
}

/* TODO - the assumption is that both forward and reverse traffic are steered towards the
 * same port - this is fine only within the context of this testbench which should be executed
 * on a test setup with 1-port VPP dut only */
static_always_inline void
vt_add_flow_for_direction (vlib_main_t *vm, vlib_node_runtime_t *node, verdict_testbench_main_t *vt,
			   sfdp_session_t *session, u32 src_addr, u32 dst_addr, u16 src_port,
			   u16 dst_port, u32 **flows_to_create)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_t flow = {};
  u32 flow_index;

  flow.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
  flow.pattern.ip4_n_tuple.src_addr.addr.data_u32 = src_addr;
  flow.pattern.ip4_n_tuple.dst_addr.addr.data_u32 = dst_addr;
  flow.pattern.ip4_n_tuple.src_addr.mask.data_u32 = ~0;
  flow.pattern.ip4_n_tuple.dst_addr.mask.data_u32 = ~0;
  flow.pattern.ip4_n_tuple.src_port.port = src_port;
  flow.pattern.ip4_n_tuple.dst_port.port = dst_port;
  flow.pattern.ip4_n_tuple.src_port.mask = 0xFFFF;
  flow.pattern.ip4_n_tuple.dst_port.mask = 0xFFFF;
  flow.pattern.ip4_n_tuple.protocol.prot = (ip_protocol_t) session->proto;
  flow.pattern.ip4_n_tuple.protocol.mask = 0xFF;

  flow.actions = VNET_FLOW_ACTION_STEER_TO_PORT;
  if (vt->enable_counters)
    flow.actions |= VNET_FLOW_ACTION_COUNT;
  flow.steer_to_hw_if_index = vt->tx_hw_if_index;
  flow.steer_from_hw_if_index = ~0; /* match all ingress ports */

  if (vnet_flow_add (vnm, &flow, &flow_index) == 0)
    {
      vec_add1 (*flows_to_create, flow_index);
    }
  else
    {
      vlib_node_increment_counter (vm, node->node_index, VERDICT_TESTBENCH_ERROR_OFFLOAD_FAILED, 1);
    }
}

/* Install steering rules for both forward and reverse directions of the
 * session so that traffic in either direction gets offloaded to the host. */
static_always_inline void
vt_create_and_offload_flow (vlib_main_t *vm, vlib_node_runtime_t *node,
			    verdict_testbench_main_t *vt, sfdp_session_t *session,
			    u32 **udp_flows_to_create, u32 **tcp_flows_to_create)
{
  u32 **flows_to_create;

  if (session->type != SFDP_SESSION_TYPE_IP4)
    return;

  if (session->proto == IP_PROTOCOL_UDP && (vt->enabled_protos & VT_PROTO_UDP))
    flows_to_create = udp_flows_to_create;
  else if (session->proto == IP_PROTOCOL_TCP && (vt->enabled_protos & VT_PROTO_TCP))
    flows_to_create = tcp_flows_to_create;
  else
    return;

  sfdp_session_ip4_key_t *key = &session->keys[SFDP_SESSION_KEY_PRIMARY].key4;
  u32 addr_lo = key->ip4_key.ip_addr_lo;
  u32 addr_hi = key->ip4_key.ip_addr_hi;
  u16 port_lo = clib_net_to_host_u16 (key->ip4_key.port_lo);
  u16 port_hi = clib_net_to_host_u16 (key->ip4_key.port_hi);

  /* forward: lo -> hi */
  vt_add_flow_for_direction (vm, node, vt, session, addr_lo, addr_hi, port_lo, port_hi,
			     flows_to_create);

  /* reverse: hi -> lo */
  vt_add_flow_for_direction (vm, node, vt, session, addr_hi, addr_lo, port_hi, port_lo,
			     flows_to_create);
}

VLIB_NODE_FN (sfdp_verdict_testbench_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  verdict_testbench_main_t *vt = &verdict_testbench_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_offloaded = 0, n_kept = 0;
  u32 *udp_flows_to_create = 0;
  u32 *tcp_flows_to_create = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      u32 session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
      sfdp_session_t *session = sfdp_session_at_index (session_idx);

      /* TODO: increment counter in unused0 */
      u16 pkt_count = ++VT_SESSION_PKT_COUNT (session);

      if (pkt_count < VT_PKT_THRESHOLD)
	goto next;

      /* Decision time: clear service from bitmap */
      session->bitmaps[SFDP_FLOW_FORWARD] &= ~SFDP_SERVICE_MASK (verdict_testbench);
      session->bitmaps[SFDP_FLOW_REVERSE] &= ~SFDP_SERVICE_MASK (verdict_testbench);

      u64 bucket = (session->session_id >> 1) % 10;

      if (bucket != 0 && vt->is_enabled)
	{
	  /* 90%: offload verdict to host */
	  vt_create_and_offload_flow (vm, node, vt, session, &udp_flows_to_create,
				      &tcp_flows_to_create);
	  n_offloaded++;
	}
      else
	{
	  n_kept++;
	}

    next:
      sfdp_next (b[0], to_next);
      b++;
      to_next++;
      n_left--;
    }

  /* End of frame: batch async enable per protocol */
  if (vec_len (udp_flows_to_create) > 0 || vec_len (tcp_flows_to_create) > 0)
    {
      vnet_main_t *vnm = vnet_get_main ();
      if (vec_len (udp_flows_to_create) > 0)
	vnet_flow_async_range_enable (vnm, vt->udp_template_index, udp_flows_to_create,
				      vt->hw_if_index);
      if (vec_len (tcp_flows_to_create) > 0)
	vnet_flow_async_range_enable (vnm, vt->tcp_template_index, tcp_flows_to_create,
				      vt->hw_if_index);
    }

  vec_free (udp_flows_to_create);
  vec_free (tcp_flows_to_create);

  if (n_offloaded)
    vlib_node_increment_counter (vm, node->node_index, VERDICT_TESTBENCH_ERROR_OFFLOADED,
				 n_offloaded);
  if (n_kept)
    vlib_node_increment_counter (vm, node->node_index, VERDICT_TESTBENCH_ERROR_KEPT, n_kept);

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      n_left = frame->n_vectors;
      b = bufs;
      for (int i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      verdict_testbench_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      u32 si = sfdp_session_from_flow_index (b[0]->flow_id);
	      sfdp_session_t *s = sfdp_session_at_index (si);
	      t->flow_id = b[0]->flow_id;
	      t->pkt_count = VT_SESSION_PKT_COUNT (s);
	      t->offloaded =
		!(s->bitmaps[SFDP_FLOW_FORWARD] & SFDP_SERVICE_MASK (verdict_testbench));
	      b++;
	    }
	  else
	    break;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sfdp_verdict_testbench_node) = {
  .name = "sfdp-verdict-testbench",
  .vector_size = sizeof (u32),
  .format_trace = format_verdict_testbench_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (verdict_testbench_error_strings),
  .error_strings = verdict_testbench_error_strings,
};

SFDP_SERVICE_DEFINE (verdict_testbench) = {
  .node_name = "sfdp-verdict-testbench",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop"),
  .is_terminal = 0,
};
