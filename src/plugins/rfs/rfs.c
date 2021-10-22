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
#include <vppinfra/vector/compress.h>
#include <vppinfra/vector/mask_compare.h>

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
  _ (HANDOFF, "error-drop")		\

#define foreach_rfs6_input_next		\
  _ (HANDOFF, "error-drop")

/* clang-format on */

static vlib_error_desc_t rfs_input_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_rfs_input_error
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
		       vlib_buffer_t **bufs, u16 *threads, u32 n_vectors)
{
  vlib_buffer_t **b;
  u16 *thread;
  u32 n_left;

  b = bufs;
  thread = threads;
  n_left = n_vectors;

  while (n_left)
    {
      rfs_input_trace_t *t;

      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->src_thread_index = vm->thread_index;
	  t->dst_thread_index = thread[0];
	}

      b += 1;
      thread += 1;
      n_left -= 1;
    }
}

always_inline uword
rfs46_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, u32 fq_index)
{
  u32 hashes[VLIB_FRAME_SIZE], *hash, out_bufs[VLIB_FRAME_SIZE], n_comp;
  u16 out_nexts[VLIB_FRAME_SIZE], out_threads[VLIB_FRAME_SIZE];
  u32 n_left_from, *from, thread_index, n_enq, n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  void *datas[VLIB_FRAME_SIZE], **data;
  u16 threads[VLIB_FRAME_SIZE], *next;
  u64 mask[VLIB_FRAME_SIZE / 64];
  rfs_main_t *rm = &rfs_main;
  int i;

  thread_index = vm->thread_index;
  n_vectors = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  n_left_from = n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;

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

  rm->hash_fn (datas, hashes, n_vectors);

  hash = hashes;
  for (i = 0; i < n_vectors; i++)
    threads[i] = (hash[i] % rm->n_workers) + 1;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    rfs_input_trace_frame (vm, node, bufs, threads, n_vectors);

  clib_mask_compare_u16 (thread_index, threads, mask, n_vectors);
  n_comp = clib_compress_u32 (out_bufs, from, mask, n_vectors);

  if (!n_comp)
    goto handoff;

  vlib_get_buffers (vm, out_bufs, bufs, n_comp);
  b = bufs;
  next = out_nexts;
  n_left_from = n_comp;

  while (n_left_from >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      vnet_feature_next_u16 (&next[0], b[0]);
      vnet_feature_next_u16 (&next[1], b[1]);
      vnet_feature_next_u16 (&next[2], b[2]);
      vnet_feature_next_u16 (&next[3], b[3]);

      b += 4;
      next += 4;
      n_left_from -= 4;
    }
  while (n_left_from)
    {
      if (n_left_from > 1)
	vlib_prefetch_buffer_header (b[1], LOAD);

      vnet_feature_next_u16 (next, b[0]);

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, out_bufs, out_nexts, n_comp);
  vlib_node_increment_counter (vm, node->node_index, RFS_INPUT_ERROR_FORWARD,
			       n_comp);

  if (n_comp == n_vectors)
    return n_vectors;

handoff:

  for (i = 0; i < clib_min (ARRAY_LEN (mask), n_vectors / 64 + 1); i++)
    mask[i] = ~mask[i];

  n_comp = clib_compress_u32 (out_bufs, from, mask, n_vectors);
  n_comp = clib_compress_u16 (out_threads, threads, mask, n_vectors);

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, out_bufs,
					 out_threads, n_comp, 1);

  vlib_node_increment_counter (vm, node->node_index, RFS_INPUT_ERROR_HANDOFF,
			       n_enq);
  if (n_enq < n_comp)
    vlib_node_increment_counter (
      vm, node->node_index, RFS_INPUT_ERROR_CONGESTION_DROP, n_comp - n_enq);

  return n_vectors;
}

VLIB_NODE_FN (rfs4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return rfs46_input_inline (vm, node, frame, rfs_main.out4_fq_index);
}

VLIB_REGISTER_NODE (rfs4_input_node) = {
  .name = "rfs4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_rfs_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = RFS_N_ERROR,
  .error_counters = rfs_input_error_counters,
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
  return rfs46_input_inline (vm, node, frame, rfs_main.out6_fq_index);
}

VLIB_REGISTER_NODE (rfs6_input_node) = {
    .name = "rfs6-input",
    .vector_size = sizeof (u32),
    .format_trace = format_rfs_input_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = RFS_N_ERROR,
    .error_counters = rfs_input_error_counters,
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
