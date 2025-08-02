/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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
 */

#include "vnet/buffer.h"
#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <ping/common.h>

ping_traceroute_main_t ping_traceroute_main;

typedef struct
{
  u16 id;
  u16 seq;
  u32 cli_process_node;
  u8 is_ip6;
} icmp_echo_trace_t;

u8 *
format_icmp_echo_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  icmp_echo_trace_t *t = va_arg (*va, icmp_echo_trace_t *);

  s = format (s, "ICMP%s echo id %d seq %d", t->is_ip6 ? "6" : "4", t->id,
	      t->seq);
  if (t->cli_process_node == CLI_UNKNOWN_NODE)
    {
      s = format (s, " (unknown)");
    }
  else
    {
      s = format (s, " send to cli node %d", t->cli_process_node);
    }

  return s;
}

static_always_inline uword
ip46_icmp_reply_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, u8 icmp_type, int do_trace,
			 int is_ip6)
{
  u32 n_left_from, *from, *to_next;
  icmp46_reply_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  /*
	   * The buffers (replies) are either posted to the CLI thread
	   * awaiting for them for subsequent analysis and disposal,
	   * or are sent to the punt node.
	   *
	   * So the only "next" node is a punt, normally.
	   */
	  u32 next0 = ICMP46_REPLY_NEXT_PUNT;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);
	  from += 1;
	  n_left_from -= 1;

	  u16 run_id = ~0;
	  u16 icmp_seq = ~0;
	  i16 l3_offset;
	  i16 l4_offset;
	  uword cli_process_id = CLI_UNKNOWN_NODE;

	  if (ip46_get_icmp_id_and_seq (vm, b0, icmp_type, &run_id, &icmp_seq,
					&l3_offset, &l4_offset, is_ip6))
	    cli_process_id = get_cli_process_id_by_run_id (vm, run_id);

	  if (cli_process_id == CLI_UNKNOWN_NODE)
	    {
	      /* no outstanding requests for this reply, punt */
	      /* speculatively enqueue b0 to the current next frame */
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      /* verify speculative enqueue, maybe switch current next frame
	       */
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	  else
	    {
	      /* Post the buffer to CLI thread. It will take care of freeing
	       * it. */
	      vnet_buffer_cli_msg (b0)->inner_l3_hdr_offset = l3_offset;
	      vnet_buffer_cli_msg (b0)->inner_l4_hdr_offset = l4_offset;
	      ip46_post_reply_event (vm, cli_process_id, bi0, is_ip6);
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED) && do_trace)
	    {
	      icmp_echo_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->id = run_id;
	      tr->seq = icmp_seq;
	      tr->cli_process_node = cli_process_id;
	      tr->is_ip6 = is_ip6;
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/*
 * select "with-trace" or "without-trace" codepaths upfront.
 */
static_always_inline uword
ip46_icmp_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, u8 icmp_type, int is_ip6)
{
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    return ip46_icmp_reply_node_fn (vm, node, frame, icmp_type,
				    1 /* do_trace */, is_ip6);
  else
    return ip46_icmp_reply_node_fn (vm, node, frame, icmp_type,
				    0 /* do_trace */, is_ip6);
}

#define ip_icmp_nodes_fn(_type, _v6)                                          \
  static uword ip##_v6##_icmp_##_type##_node_fn (                             \
    vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)          \
  {                                                                           \
    return ip46_icmp_node_fn (vm, node, frame, ICMP##_v6##_##_type,           \
			      (_v6) == 6 /* is_ip6 */);                       \
  }

#define ip46_icmp_nodes_fn(_type)                                             \
  ip_icmp_nodes_fn (_type, 4);                                                \
  ip_icmp_nodes_fn (_type, 6);

#define ip_icmp_node_registration(_type, _v6)                                 \
  VLIB_REGISTER_NODE (ip##_v6##_icmp_##_type##_node) = {             \
    .function = ip##_v6##_icmp_##_type##_node_fn,                                 \
    .name = "ip" #_v6 "-icmp-" #_type "-reply",                                    \
    .vector_size = sizeof (u32),                                              \
    .format_trace = format_icmp_echo_trace,                                   \
    .n_next_nodes = ICMP46_REPLY_N_NEXT,                                 \
    .next_nodes = {                                                           \
      [ICMP46_REPLY_NEXT_DROP] = "ip" #_v6 "-drop",                          \
      [ICMP46_REPLY_NEXT_PUNT] = "ip" #_v6 "-punt",                          \
    }, \
};

#define ip46_icmp_node_registration(_type)                                    \
  ip_icmp_node_registration (_type, 4);                                       \
  ip_icmp_node_registration (_type, 6);

#define __(_type)                                                             \
  ip46_icmp_nodes_fn (_type);                                                 \
  ip46_icmp_node_registration (_type)
foreach_icmp_type_reply
#undef __

  static clib_error_t *
  ping_traceroute_common_init (vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ping_traceroute_main_t *ptm = &ping_traceroute_main;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&ptm->run_check_lock);

#define __(_type)                                                             \
  ip4_icmp_register_type (vm, ICMP4_##_type, ip4_icmp_##_type##_node.index);  \
  icmp6_register_type (vm, ICMP6_##_type, ip6_icmp_##_type##_node.index);
  foreach_icmp_type_reply
#undef __
    return 0;
}

VLIB_INIT_FUNCTION (ping_traceroute_common_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Ping & Traceroute (ping)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
