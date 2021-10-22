/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/udp/udp_packet.h>

typedef struct rfs_main_
{
  u32 out4_fq_index;
  u32 out6_fq_index;
  u32 n_workers;
} rfs_main_t;

static rfs_main_t rfs_main;

#include <rfs/rfs.h>

/* clang-format off */
#define foreach_rfs4_input_next		\
  _ (HANDOFF, "rfs4-handoff")		\

#define foreach_rfs6_input_next		\
  _ (HANDOFF, "rfs6-handoff")		\
/* clang-format on */

static char *rfs_input_error_strings[] = {
#define _(n, s) s,
    foreach_rfs_error
#undef _
};

typedef enum rfs_input_next_
{
  RFS_INPUT_NEXT_HANDOFF,
  RFS_INPUT_N_NEXT,
} rfs_input_next_t;

typedef struct
{
  u32 src_thread_index;
  u32 dst_thread_index;
  u32 hash;
} rfs_input_trace_t;

static u8 *
format_rfs_input_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  rfs_input_trace_t *t = va_arg (*args, rfs_input_trace_t *);

  s = format (s, "flow hash: %u src thread %u dst thread %u",
	      t->hash, t->src_thread_index, t->dst_thread_index);
  return s;
}

/* clang-format off */
#define rfs_ip4_flow_hash_cfg 				\
    IP_FLOW_HASH_SRC_ADDR | IP_FLOW_HASH_DST_ADDR	\
    | IP_FLOW_HASH_SRC_PORT | IP_FLOW_HASH_DST_PORT	\
    | IP_FLOW_HASH_PROTO
/* clang-format on */

always_inline u32
rfs_compute_thread (vlib_buffer_t *b, u8 is_ip4)
{
  udp_header_t *uh;
  u32 hash;

  if (is_ip4)
    {
      ip4_header_t *ih = vlib_buffer_get_current (b);
      if (ih->protocol != IP_PROTOCOL_UDP && ih->protocol != IP_PROTOCOL_TCP)
	return ~0;

      uh = ip4_next_header (ih);
      hash = ip4_compute_flow_hash (ih, rfs_ip4_flow_hash_cfg);
    }
  else
    {
      ip6_header_t *ih = vlib_buffer_get_current (b);
      if (ih->protocol != IP_PROTOCOL_UDP && ih->protocol != IP_PROTOCOL_TCP)
	return ~0;

      uh = ip6_next_header (ih);
      hash = ip6_compute_flow_hash (ih, rfs_ip4_flow_hash_cfg);
    }

  return (hash % rfs_main.n_workers) + 1;
}

always_inline uword
rfs46_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, int is_ip4)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left_from, *from, thread_index;

  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from)
    {
      u32 next0, flow_thread0;

      flow_thread0 = rfs_compute_thread (b[0], is_ip4);
      if (flow_thread0 == thread_index)
	{
	  vnet_feature_next (&next0, b[0]);
	}
      else
	{
	  vnet_buffer (b[0])->ip.flow_hash = flow_thread0;
	  next0 = RFS_INPUT_NEXT_HANDOFF;
	}

      next[0] = next0;

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (rfs4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return rfs46_input_inline (vm, node, frame, 1 /* is_ip4 */);
}

VLIB_REGISTER_NODE (rfs4_input_node) = {
  .name = "rfs4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_rfs_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = RFS_N_ERROR,
  .error_strings = rfs_input_error_strings,
  .n_next_nodes = RFS_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [RFS_INPUT_NEXT_##s] = n,
      foreach_rfs4_input_next
#undef _
  },
};

VNET_FEATURE_INIT (rfs4_input_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "rfs4-input",
  .runs_before = 0,
};

VLIB_NODE_FN (rfs6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return rfs46_input_inline (vm, node, frame, 0 /* is_ip4 */);
}

VLIB_REGISTER_NODE (rfs6_input_node) = {
    .name = "rfs6-input",
    .vector_size = sizeof (u32),
    .format_trace = format_rfs_input_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = RFS_N_ERROR,
    .error_strings = rfs_input_error_strings,
    .n_next_nodes = RFS_INPUT_N_NEXT,
    .next_nodes = {
#define _(s, n) [RFS_INPUT_NEXT_##s] = n,
        foreach_rfs6_input_next
#undef _
    },
};

VNET_FEATURE_INIT (rfs6_input_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "rfs6-input",
  .runs_before = 0,
};

always_inline uword
rfs46_handoff_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, u32 fq_index)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      /* reusing flow hash for thread index */
      ti[0] = vnet_buffer (b[0])->ip.flow_hash;
      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 RFS_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);

  return n_enq;
}

static char *rfs_handoff_error_strings[] = {
#define _(n, s) s,
  foreach_rfs_handoff_error
#undef _
};

typedef struct
{
  u32 next_worker;
} rfs_handoff_trace_t;

static u8 *
format_rfs_handoff_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  rfs_handoff_trace_t *t = va_arg (*args, rfs_handoff_trace_t *);

  s = format (s, "next worker: %u", t->next_worker);
  return s;
}

VLIB_NODE_FN (rfs4_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return rfs46_handoff_inline (vm, node, frame, rfs_main.out4_fq_index);
}

VLIB_REGISTER_NODE (rfs4_handoff_node) =
{
  .name = "rfs4-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_rfs_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (rfs_handoff_error_strings),
  .error_strings = rfs_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (rfs6_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return rfs46_handoff_inline (vm, node, frame, rfs_main.out6_fq_index);
}

VLIB_REGISTER_NODE (rfs6_handoff_node) =
{
  .name = "rfs6-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_rfs_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (rfs_handoff_error_strings),
  .error_strings = rfs_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

static clib_error_t *
rfs_init (vlib_main_t *vm)
{
  rfs_main_t *rm = &rfs_main;

  rm->out4_fq_index = vlib_frame_queue_main_init (rfs4_input_node.index, 0);
  rm->out6_fq_index = vlib_frame_queue_main_init (rfs6_input_node.index, 0);
  rm->n_workers = vlib_num_workers ();
  return 0;
}

VLIB_INIT_FUNCTION (rfs_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Receive Flow Steering",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
