/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <stdint.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/classify/flow_classify.h>
#include <vnet/classify/vnet_classify.h>

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 table_index;
  u32 offset;
} flow_classify_trace_t;

static u8 *
format_flow_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flow_classify_trace_t * t = va_arg (*args, flow_classify_trace_t *);

  s = format (s, "FLOW_CLASSIFY: sw_if_index %d next %d table %d offset %d",
              t->sw_if_index, t->next_index, t->table_index, t->offset);
  return s;
}

#define foreach_flow_classify_error                 \
_(MISS, "Flow classify misses")                     \
_(HIT, "Flow classify hits")                        \
_(CHAIN_HIT, "Flow classify hits after chain walk") \
_(DROP, "Flow classify action drop")

typedef enum {
#define _(sym,str) FLOW_CLASSIFY_ERROR_##sym,
  foreach_flow_classify_error
#undef _
  FLOW_CLASSIFY_N_ERROR,
} flow_classify_error_t;

static char * flow_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_flow_classify_error
#undef _
};

static inline uword
flow_classify_inline (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame,
                      flow_classify_table_id_t tid)
{
  u32 n_left_from, * from, * to_next;
  flow_classify_next_index_t next_index;
  flow_classify_main_t * fcm = &flow_classify_main;
  vnet_classify_main_t * vcm = fcm->vnet_classify_main;
  f64 now = vlib_time_now (vm);
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  u32 drop = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  /* First pass: compute hashes */
  while (n_left_from > 2)
    {
      vlib_buffer_t * b0, * b1;
      u32 bi0, bi1;
      u8 * h0, * h1;
      u32 sw_if_index0, sw_if_index1;
      u32 table_index0, table_index1;
      vnet_classify_table_t * t0, * t1;

      /* Prefetch next iteration */
      {
        vlib_buffer_t * p1, * p2;

        p1 = vlib_get_buffer (vm, from[1]);
        p2 = vlib_get_buffer (vm, from[2]);

        vlib_prefetch_buffer_header (p1, STORE);
        CLIB_PREFETCH (p1->data, CLIB_CACHE_LINE_BYTES, STORE);
        vlib_prefetch_buffer_header (p2, STORE);
        CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      h0 = b0->data;

      bi1 = from[1];
      b1 = vlib_get_buffer (vm, bi1);
      h1 = b1->data;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      table_index0 = fcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      table_index1 = fcm->classify_table_index_by_sw_if_index[tid][sw_if_index1];

      t0 = pool_elt_at_index (vcm->tables, table_index0);

      t1 = pool_elt_at_index (vcm->tables, table_index1);

      vnet_buffer(b0)->l2_classify.hash =
        vnet_classify_hash_packet (t0, (u8 *) h0);

      vnet_classify_prefetch_bucket (t0, vnet_buffer(b0)->l2_classify.hash);

      vnet_buffer(b1)->l2_classify.hash =
        vnet_classify_hash_packet (t1, (u8 *) h1);

      vnet_classify_prefetch_bucket (t1, vnet_buffer(b1)->l2_classify.hash);

      vnet_buffer(b0)->l2_classify.table_index = table_index0;

      vnet_buffer(b1)->l2_classify.table_index = table_index1;

      from += 2;
      n_left_from -= 2;
    }

  while (n_left_from > 0)
    {
      vlib_buffer_t * b0;
      u32 bi0;
      u8 * h0;
      u32 sw_if_index0;
      u32 table_index0;
      vnet_classify_table_t * t0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      h0 = b0->data;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      table_index0 = fcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      t0 = pool_elt_at_index (vcm->tables, table_index0);
      vnet_buffer(b0)->l2_classify.hash =
        vnet_classify_hash_packet (t0, (u8 *) h0);

      vnet_buffer(b0)->l2_classify.table_index = table_index0;
      vnet_classify_prefetch_bucket (t0, vnet_buffer(b0)->l2_classify.hash);

      from++;
      n_left_from--;
    }

  next_index = node->cached_next_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Not enough load/store slots to dual loop... */
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0 = FLOW_CLASSIFY_NEXT_INDEX_DROP;
          u32 table_index0;
          vnet_classify_table_t * t0;
          vnet_classify_entry_t * e0;
          u64 hash0;
          u8 * h0;

          /* Stride 3 seems to work best */
          if (PREDICT_TRUE (n_left_from > 3))
            {
              vlib_buffer_t * p1 = vlib_get_buffer(vm, from[3]);
              vnet_classify_table_t * tp1;
              u32 table_index1;
              u64 phash1;

              table_index1 = vnet_buffer(p1)->l2_classify.table_index;

              if (PREDICT_TRUE (table_index1 != ~0))
                {
                  tp1 = pool_elt_at_index (vcm->tables, table_index1);
                  phash1 = vnet_buffer(p1)->l2_classify.hash;
                  vnet_classify_prefetch_entry (tp1, phash1);
                }
            }

          /* Speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          h0 = b0->data;
          table_index0 = vnet_buffer(b0)->l2_classify.table_index;
          e0 = 0;
          t0 = 0;

          vnet_get_config_data (fcm->vnet_config_main[tid],
                                &b0->current_config_index,
                                &next0,
                                /* # bytes of config data */ 0);

          if (PREDICT_TRUE(table_index0 != ~0))
            {
              hash0 = vnet_buffer(b0)->l2_classify.hash;
              t0 = pool_elt_at_index (vcm->tables, table_index0);
              e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
              if (e0)
                {
                  hits++;
                }
              else
                {
                  misses++;
                  vnet_classify_add_del_session (vcm, table_index0,
                                                 h0, ~0, 0, 0, 0, 0, 1);
                  /* increment counter */
                  vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
                }
            }
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              flow_classify_trace_t * t =
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
              t->next_index = next0;
              t->table_index = t0 ? t0 - vcm->tables : ~0;
              t->offset = (t0 && e0) ? vnet_classify_get_offset (t0, e0): ~0;
            }

          /* Verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
                               FLOW_CLASSIFY_ERROR_MISS,
                               misses);
  vlib_node_increment_counter (vm, node->node_index,
                               FLOW_CLASSIFY_ERROR_HIT,
                               hits);
  vlib_node_increment_counter (vm, node->node_index,
                               FLOW_CLASSIFY_ERROR_CHAIN_HIT,
                               chain_hits);
  vlib_node_increment_counter (vm, node->node_index,
                               FLOW_CLASSIFY_ERROR_DROP,
                               drop);

  return frame->n_vectors;
}

static uword
ip4_flow_classify (vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  return flow_classify_inline(vm, node, frame, FLOW_CLASSIFY_TABLE_IP4);
}

VLIB_REGISTER_NODE (ip4_flow_classify_node) = {
  .function = ip4_flow_classify,
  .name = "ip4-flow-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_flow_classify_trace,
  .n_errors = ARRAY_LEN(flow_classify_error_strings),
  .error_strings = flow_classify_error_strings,
  .n_next_nodes = FLOW_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [FLOW_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_flow_classify_node, ip4_flow_classify);

static uword
ip6_flow_classify (vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  return flow_classify_inline(vm, node, frame, FLOW_CLASSIFY_TABLE_IP6);
}

VLIB_REGISTER_NODE (ip6_flow_classify_node) = {
  .function = ip6_flow_classify,
  .name = "ip6-flow-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_flow_classify_trace,
  .n_errors = ARRAY_LEN(flow_classify_error_strings),
  .error_strings = flow_classify_error_strings,
  .n_next_nodes = FLOW_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [FLOW_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_flow_classify_node, ip6_flow_classify);


static clib_error_t *
flow_classify_init (vlib_main_t *vm)
{
  flow_classify_main_t * fcm = &flow_classify_main;

  fcm->vlib_main = vm;
  fcm->vnet_main = vnet_get_main();
  fcm->vnet_classify_main = &vnet_classify_main;

  return 0;
}

VLIB_INIT_FUNCTION (flow_classify_init);
