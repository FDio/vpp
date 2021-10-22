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
#include <vnet/hash/hash.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/udp/udp_packet.h>

typedef struct rfs_main_
{
  vnet_hash_fn_t hash_fn;
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
  _ (HANDOFF, "rfs6-handoff")

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
} rfs_input_trace_t;

static u8 *
format_rfs_input_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  rfs_input_trace_t *t = va_arg (*args, rfs_input_trace_t *);

  s = format (s, "flow src thread %u dst thread %u", t->src_thread_index,
	      t->dst_thread_index);
  return s;
}

static void
rfs_input_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  u32 *from, n_left;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 1)
    {
      rfs_input_trace_t *t0;
      vlib_buffer_t *b0;
      u32 bi0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  t0->src_thread_index = vm->thread_index;
	  t0->dst_thread_index = vnet_buffer (b0)->ip.flow_hash;
	}

      from += 1;
      n_left -= 1;
    }
}

always_inline void
rfs_input_set_next (rfs_main_t *rm, vlib_buffer_t *b, u32 hash,
		    u32 thread_index, u16 *next)
{
  u32 flow_thread, next_index;

  flow_thread = (hash % rm->n_workers) + 1;
  if (flow_thread == thread_index)
    {
      vnet_feature_next (&next_index, b);
      *next = next_index;
    }
  else
    {
      vnet_buffer (b)->ip.flow_hash = flow_thread;
      *next = RFS_INPUT_NEXT_HANDOFF;
    }
}

always_inline uword
rfs46_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, int is_ip4)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_left_from, *from, thread_index;
  void *datas[VLIB_FRAME_SIZE], **data;
  u32 hashes[VLIB_FRAME_SIZE], *hash;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  rfs_main_t *rm = &rfs_main;

  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  data = datas;
  while (n_left_from >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      data[0] = vlib_buffer_get_current (b[0]);
      data[1] = vlib_buffer_get_current (b[1]);
      data[2] = vlib_buffer_get_current (b[2]);
      data[3] = vlib_buffer_get_current (b[3]);

      b += 4;
      data += 4;
      n_left_from -= 4;
    }

  while (n_left_from)
    {
      if (n_left_from > 1)
	vlib_prefetch_buffer_header (b[1], LOAD);

      data[0] = vlib_buffer_get_current (b[0]);

      b += 1;
      data += 1;
      n_left_from -= 1;
    }

  b = bufs;
  n_left_from = frame->n_vectors;
  rm->hash_fn (datas, hashes, n_left_from);
  hash = hashes;

  while (n_left_from >= 8)
    {
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      rfs_input_set_next (rm, b[0], hash[0], thread_index, &next[0]);
      rfs_input_set_next (rm, b[1], hash[1], thread_index, &next[1]);
      rfs_input_set_next (rm, b[2], hash[2], thread_index, &next[2]);
      rfs_input_set_next (rm, b[3], hash[3], thread_index, &next[3]);

      b += 4;
      hash += 4;
      next += 4;
      n_left_from -= 4;
    }

  while (n_left_from)
    {
      if (n_left_from > 1)
	vlib_prefetch_buffer_header (b[1], STORE);

      rfs_input_set_next (rm, b[0], hash[0], thread_index, &next[0]);

      b += 1;
      hash += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    rfs_input_trace_frame (vm, node, frame);

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

static void
rfs_handoff_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  u32 *from, n_left;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left)
    {
      rfs_handoff_trace_t *t0;
      vlib_buffer_t *b0;
      u32 bi0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  t0->next_worker = vnet_buffer (b0)->ip.flow_hash;
	}

      from += 1;
      n_left -= 1;
    }
}

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

  while (n_left_from >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      ti[0] = vnet_buffer (b[0])->ip.flow_hash;
      ti[1] = vnet_buffer (b[1])->ip.flow_hash;
      ti[2] = vnet_buffer (b[2])->ip.flow_hash;
      ti[3] = vnet_buffer (b[3])->ip.flow_hash;

      n_left_from -= 4;
      ti += 4;
      b += 4;
    }

  while (n_left_from)
    {
      /* reusing flow hash for thread index */
      ti[0] = vnet_buffer (b[0])->ip.flow_hash;
      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    rfs_handoff_trace_frame (vm, node, frame);

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 RFS_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);

  return n_enq;
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
  rm->hash_fn = vnet_hash_default_function (VNET_HASH_FN_TYPE_IP);
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
