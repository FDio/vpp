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
#include <vnet/classify/policer_classify.h>

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 table_index;
  u32 offset;
} policer_classify_trace_t;

static u8 *
format_policer_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  policer_classify_trace_t * t = va_arg (*args, policer_classify_trace_t *);

  s = format (s, "POLICER_CLASSIFY: sw_if_index %d next %d table %d offset %d",
              t->sw_if_index, t->next_index, t->table_index, t->offset);
  return s;
}

typedef enum {
  POLICER_CLASSIFY_NEXT_DROP,
  POLICER_CLASSIFY_NEXT_POLICER,
  POLICER_CLASSIFY_N_NEXT,
} policer_classify_next_t;

#define foreach_policer_classify_error               \
_(MISS, "Policer classify misses")                      \
_(HIT, "Policer classify hits")                         \
_(CHAIN_HIT, "Polcier classify hits after chain walk")

typedef enum {
#define _(sym,str) POLICER_CLASSIFY_ERROR_##sym,
  foreach_policer_classify_error
#undef _
  POLICER_CLASSIFY_N_ERROR,
} policer_classify_error_t;

static char * policer_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_policer_classify_error
#undef _
};

static inline uword
policer_classify_inline (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame,
                         policer_classify_table_id_t tid)
{
  u32 n_left_from, * from, * to_next;
  policer_classify_next_t next_index;
  policer_classify_main_t * pcm = &policer_classify_main;
  vnet_classify_main_t * vcm = pcm->vnet_classify_main;
  f64 now = vlib_time_now (vm);
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  u32 n_next_nodes;

  n_next_nodes = node->n_next_nodes;

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
      table_index0 = pcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      table_index1 = pcm->classify_table_index_by_sw_if_index[tid][sw_if_index1];

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
      table_index0 = pcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

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
          u32 next0 = POLICER_CLASSIFY_NEXT_DROP;
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

          if (tid == POLICER_CLASSIFY_TABLE_L2)
            {
              /* Feature bitmap update */
              vnet_buffer(b0)->l2.feature_bitmap &= ~L2INPUT_FEAT_POLICER_CLAS;
              /* Determine the next node */
              next0 = feat_bitmap_get_next_node_index(pcm->feat_next_node_index,
                vnet_buffer(b0)->l2.feature_bitmap);
            }
          else
            vnet_get_config_data (pcm->vnet_config_main[tid],
                                  &b0->current_config_index,
                                  &next0,
                                  /* # bytes of config data */ 0);

          vnet_buffer(b0)->l2_classify.opaque_index = ~0;

          if (PREDICT_TRUE(table_index0 != ~0))
            {
              hash0 = vnet_buffer(b0)->l2_classify.hash;
              t0 = pool_elt_at_index (vcm->tables, table_index0);
              e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);

              if (e0)
                {
                  vnet_buffer(b0)->policer.index = e0->next_index;
                  vnet_buffer(b0)->policer.color = e0->opaque_index;
                  vlib_buffer_advance (b0, e0->advance);
                  next0 = POLICER_CLASSIFY_NEXT_POLICER;
                  hits++;
                }
              else
                {
                  while (1)
                    {
                      if (PREDICT_TRUE(t0->next_table_index != ~0))
                        {
                          t0 = pool_elt_at_index (vcm->tables,
                                                  t0->next_table_index);
                        }
                      else
                        {
                          next0 = (t0->miss_next_index < n_next_nodes)?
                                   t0->miss_next_index:next0;
                          misses++;
                          break;
                        }

                      hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
                      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
                      if (e0)
                        {
                          vnet_buffer(b0)->policer.index = e0->next_index;
                          vnet_buffer(b0)->policer.color = e0->opaque_index;
                          vlib_buffer_advance (b0, e0->advance);
                          next0 = POLICER_CLASSIFY_NEXT_POLICER;
                          hits++;
                          chain_hits++;
                          break;
                        }
                    }
                }
            }
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              policer_classify_trace_t * t =
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
              t->next_index = next0;
              t->table_index = t0 ? t0 - vcm->tables : ~0;
              t->offset = e0 ? vnet_classify_get_offset (t0, e0): ~0;
            }

          /* Verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
                               POLICER_CLASSIFY_ERROR_MISS,
                               misses);
  vlib_node_increment_counter (vm, node->node_index,
                               POLICER_CLASSIFY_ERROR_HIT,
                               hits);
  vlib_node_increment_counter (vm, node->node_index,
                               POLICER_CLASSIFY_ERROR_CHAIN_HIT,
                               chain_hits);

  return frame->n_vectors;
}

static uword
ip4_policer_classify (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return policer_classify_inline(vm, node, frame, POLICER_CLASSIFY_TABLE_IP4);
}

VLIB_REGISTER_NODE (ip4_policer_classify_node) = {
  .function = ip4_policer_classify,
  .name = "ip4-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN(policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_DROP] = "error-drop",
    [POLICER_CLASSIFY_NEXT_POLICER] = "policer-by-opaque-ip4",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_policer_classify_node, ip4_policer_classify);

static uword
ip6_policer_classify (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return policer_classify_inline(vm, node, frame, POLICER_CLASSIFY_TABLE_IP6);
}

VLIB_REGISTER_NODE (ip6_policer_classify_node) = {
  .function = ip6_policer_classify,
  .name = "ip6-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN(policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_DROP] = "error-drop",
    [POLICER_CLASSIFY_NEXT_POLICER] = "policer-by-opaque-ip6",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_policer_classify_node, ip6_policer_classify);

static uword
l2_policer_classify (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * frame)
{
  return policer_classify_inline(vm, node, frame, POLICER_CLASSIFY_TABLE_L2);
}

VLIB_REGISTER_NODE (l2_policer_classify_node) = {
  .function = l2_policer_classify,
  .name = "l2-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN(policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_DROP] = "error-drop",
    [POLICER_CLASSIFY_NEXT_POLICER] = "policer-by-opaque-l2",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (l2_policer_classify_node, l2_policer_classify);

static void
vnet_policer_classify_feature_enable (vlib_main_t * vnm,
                                      policer_classify_main_t * pcm,
                                      u32 sw_if_index,
                                      policer_classify_table_id_t tid,
                                      int feature_enable)
{
  if (tid == POLICER_CLASSIFY_TABLE_L2)
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_POLICER_CLAS,
                                  feature_enable);
    }
  else
    {
      ip_lookup_main_t * lm;
      ip_config_main_t * ipcm;
      u32 ftype;
      u32 ci;

      if (tid == POLICER_CLASSIFY_TABLE_IP4)
        {
          lm = &ip4_main.lookup_main;
          ftype = ip4_main.ip4_unicast_rx_feature_policer_classify;
        }
      else
        {
          lm = &ip6_main.lookup_main;
          ftype = ip6_main.ip6_unicast_rx_feature_policer_classify;
        }

      ipcm = &lm->rx_config_mains[VNET_UNICAST];

      ci = ipcm->config_index_by_sw_if_index[sw_if_index];
      ci = (feature_enable ? vnet_config_add_feature : vnet_config_del_feature)
        (vnm, &ipcm->config_main, ci, ftype, 0, 0);

      ipcm->config_index_by_sw_if_index[sw_if_index] = ci;
      pcm->vnet_config_main[tid] = &ipcm->config_main;
    }
}

int vnet_set_policer_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
                                     u32 ip4_table_index, u32 ip6_table_index,
                                     u32 l2_table_index, u32 is_add)
{
  policer_classify_main_t * pcm = &policer_classify_main;
  vnet_classify_main_t * vcm = pcm->vnet_classify_main;
  u32 pct[POLICER_CLASSIFY_N_TABLES] = {ip4_table_index, ip6_table_index,
                                        l2_table_index};
  u32 ti;

  /* Assume that we've validated sw_if_index in the API layer */

  for (ti = 0; ti < POLICER_CLASSIFY_N_TABLES; ti++)
    {
      if (pct[ti] == ~0)
        continue;

      if (pool_is_free_index (vcm->tables, pct[ti]))
        return VNET_API_ERROR_NO_SUCH_TABLE;

      vec_validate_init_empty
        (pcm->classify_table_index_by_sw_if_index[ti], sw_if_index, ~0);

      /* Reject any DEL operation with wrong sw_if_index */
      if (!is_add &&
          (pct[ti] != pcm->classify_table_index_by_sw_if_index[ti][sw_if_index]))
        {
          clib_warning ("Non-existent intf_idx=%d with table_index=%d for delete",
                        sw_if_index, pct[ti]);
          return VNET_API_ERROR_NO_SUCH_TABLE;
        }

      /* Return ok on ADD operaton if feature is already enabled */
      if (is_add &&
          pcm->classify_table_index_by_sw_if_index[ti][sw_if_index] != ~0)
          return 0;

      vnet_policer_classify_feature_enable (vm, pcm, sw_if_index, ti, is_add);

      if (is_add)
        pcm->classify_table_index_by_sw_if_index[ti][sw_if_index] = pct[ti];
      else
        pcm->classify_table_index_by_sw_if_index[ti][sw_if_index] = ~0;
    }


  return 0;
}

static clib_error_t *
set_policer_classify_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 sw_if_index = ~0;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 l2_table_index = ~0;
  u32 is_add = 1;
  u32 idx_cnt = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "interface %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
        ;
      else if (unformat (input, "ip4-table %d", &ip4_table_index))
        idx_cnt++;
      else if (unformat (input, "ip6-table %d", &ip6_table_index))
        idx_cnt++;
      else if (unformat (input, "l2-table %d", &l2_table_index))
        idx_cnt++;
      else if (unformat (input, "del"))
        is_add = 0;
      else
        break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface must be specified.");

  if (!idx_cnt)
    return clib_error_return (0, "Table index should be specified.");

  if (idx_cnt > 1)
    return clib_error_return (0, "Only one table index per API is allowed.");

  rv = vnet_set_policer_classify_intfc(vm, sw_if_index, ip4_table_index,
                                       ip6_table_index, l2_table_index, is_add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_MATCHING_INTERFACE:
      return clib_error_return (0, "No such interface");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "No such classifier table");
    }
  return 0;
}

VLIB_CLI_COMMAND (set_input_acl_command, static) = {
    .path = "set policer classify",
    .short_help =
    "set policer classify interface <int> [ip4-table <index>]\n"
    "  [ip6-table <index>] [l2-table <index>] [del]",
    .function = set_policer_classify_command_fn,
};

static uword
unformat_table_type (unformat_input_t * input, va_list * va)
{
  u32 * r = va_arg (*va, u32 *);
  u32 tid;

  if (unformat (input, "ip4"))
    tid = POLICER_CLASSIFY_TABLE_IP4;
  else if (unformat (input, "ip6"))
    tid = POLICER_CLASSIFY_TABLE_IP6;
  else if (unformat (input, "l2"))
    tid = POLICER_CLASSIFY_TABLE_L2;
  else
    return 0;

  *r = tid;
  return 1;
}
static clib_error_t *
show_policer_classify_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  policer_classify_main_t * pcm = &policer_classify_main;
  u32 type = POLICER_CLASSIFY_N_TABLES;
  u32 * vec_tbl;
  int i;

  if (unformat (input, "type %U", unformat_table_type, &type))
    ;
  else
    return clib_error_return (0, "Type must be specified.");;

  if (type == POLICER_CLASSIFY_N_TABLES)
    return clib_error_return (0, "Invalid table type.");

  vec_tbl = pcm->classify_table_index_by_sw_if_index[type];

  if (vec_len(vec_tbl))
      vlib_cli_output (vm, "%10s%20s\t\t%s", "Intfc idx", "Classify table",
                       "Interface name");
  else
    vlib_cli_output (vm, "No tables configured.");

  for (i = 0; i < vec_len (vec_tbl); i++)
    {
      if (vec_elt(vec_tbl, i) == ~0)
        continue;

      vlib_cli_output (vm, "%10d%20d\t\t%U", i, vec_elt(vec_tbl, i),
                       format_vnet_sw_if_index_name, pcm->vnet_main, i);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_policer_classify_command, static) = {
    .path = "show classify policer",
    .short_help = "show classify policer type [ip4|ip6|l2]",
    .function = show_policer_classify_command_fn,
};

static clib_error_t *
policer_classify_init (vlib_main_t *vm)
{
  policer_classify_main_t * pcm = &policer_classify_main;

  pcm->vlib_main = vm;
  pcm->vnet_main = vnet_get_main();
  pcm->vnet_classify_main = &vnet_classify_main;

  /* Initialize L2 feature next-node indexes */
  feat_bitmap_init_next_nodes(vm,
                              l2_policer_classify_node.index,
                              L2INPUT_N_FEAT,
                              l2input_get_feat_names(),
                              pcm->feat_next_node_index);

  return 0;
}

VLIB_INIT_FUNCTION (policer_classify_init);
