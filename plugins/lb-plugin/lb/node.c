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

#include <lb/lb.h>

#include <vnet/gre/packet.h>
#include <lb/lbhash.h>

#define foreach_lb_error \
 _(NONE, "no error") \
 _(PROTO_NOT_SUPPORTED, "protocol not supported") \
 _(NO_SERVER, "no configured application server")

typedef enum {
#define _(sym,str) LB_ERROR_##sym,
  foreach_lb_error
#undef _
    LB_N_ERROR,
} lb_error_t;

static char *lb_error_strings[] = {
#define _(sym,string) string,
    foreach_lb_error
#undef _
};

typedef enum {
  LB_NEXT_LOOKUP,
  LB_NEXT_DROP,
  LB_N_NEXT,
} lb_next_t;

typedef struct {
  u32 vip_index;
  u32 as_index;
  u8 new;
} lb_trace_t;

u8 *lb_format_adjacency(u8 * s,
                        struct ip_lookup_main_t * lm,
                        ip_adjacency_t *adj)
{
  lb_main_t *lbm = &lb_main;
  lb_adj_data_t *ad = (lb_adj_data_t *) &adj->opaque;
  __attribute__((unused)) lb_vip_t *vip = pool_elt_at_index (lbm->vips, ad->vip_index);
  return format(s, "idx:%d", ad->vip_index);
}

u8 *
format_lb_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lb_trace_t *t = va_arg (*args, lb_trace_t *);
  return format (s, "lb vip: %d as: %d %s", t->vip_index, t->as_index, t->new?"new":"established");
}

lb_hash_t *lb_get_sticky_table(u32 cpu_index)
{
  lb_main_t *lbm = &lb_main;
  lb_hash_t *sticky_ht = lbm->per_cpu[cpu_index].sticky_ht;
  //Check if size changed
  if (PREDICT_FALSE(sticky_ht && (lbm->per_cpu_sticky_buckets != lb_hash_nbuckets(sticky_ht)))) {

    //Dereference everything in there
    lb_hash_entry_t *e;
    lb_hash_foreach_entry(sticky_ht, e) {
      u32 vip_index = e->key[2] >> 32;
      vlib_refcount_add(&lbm->vips[vip_index].as_refcount,
                        cpu_index, e->value, -1);
      vlib_refcount_add(&lbm->vips[vip_index].as_refcount,
                              cpu_index, 0, -1);
    }

    lb_hash_free(sticky_ht);
    sticky_ht = NULL;
  }

  //Create if necessary
  if (PREDICT_FALSE(sticky_ht == NULL)) {
    lbm->per_cpu[cpu_index].sticky_ht = lb_hash_alloc(lbm->per_cpu_sticky_buckets, lbm->flow_timeout);
    sticky_ht = lbm->per_cpu[cpu_index].sticky_ht;
  }

  ASSERT(sticky_ht);

  //Update timeout
  sticky_ht->timeout = lbm->flow_timeout;
  return sticky_ht;
}

static uword
lb4_node_fn (vlib_main_t * vm,
         vlib_node_runtime_t * node,
         vlib_frame_t * frame)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  lb_main_t *lbm = &lb_main;
  vlib_node_runtime_t *error_node = vlib_node_get_runtime(vm, lb4_node.index);
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      ip_adjacency_t *adj0;
      lb_adj_data_t *ad0;
      __attribute__((unused)) lb_vip_t *vip0;
      __attribute__((unused)) ip4_header_t *ip40;

      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;

      p0 = vlib_get_buffer (vm, pi0);
      ip40 = vlib_buffer_get_current (p0);

      adj0 = ip_get_adjacency (lm, vnet_buffer (p0)->ip.adj_index[VLIB_TX]);
      ad0 = (lb_adj_data_t *) &adj0->opaque;
      vip0 = pool_elt_at_index (lbm->vips, ad0->vip_index);

      if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
      {
        lb_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
        tr->as_index = ~0;
        tr->vip_index = ad0->vip_index;
        tr->new = 0;
      }

      p0->error = error_node->errors[LB_ERROR_PROTO_NOT_SUPPORTED];
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                       n_left_to_next, pi0, LB_NEXT_DROP);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  return frame->n_vectors;
}

static uword
lb6_node_fn (vlib_main_t * vm,
         vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  lb_main_t *lbm = &lb_main;
  vlib_node_runtime_t *error_node = vlib_node_get_runtime(vm, lb6_node.index);
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 cpu_index = os_get_cpu_number();
  u32 lb_time = lb_hash_time_now(vm);

  lb_hash_t *sticky_ht = lb_get_sticky_table(cpu_index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;


  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      ip_adjacency_t *adj0;
      lb_adj_data_t *ad0;
      lb_vip_t *vip0;
      lb_as_t *as0;
      ip6_header_t *ip60;
      gre_header_t *gre0;
      u16 len0;
      u32 value0, available_index0, hash0;
      u64 key0[3];
      lb_error_t error0 = LB_ERROR_NONE;
      lb_next_t next0 = LB_NEXT_LOOKUP;

      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;

      p0 = vlib_get_buffer (vm, pi0);
      ip60 = vlib_buffer_get_current (p0);
      len0 = clib_net_to_host_u16(ip60->payload_length);

      adj0 = ip_get_adjacency (lm, vnet_buffer (p0)->ip.adj_index[VLIB_TX]);
      ad0 = (lb_adj_data_t *) &adj0->opaque;
      vip0 = pool_elt_at_index (lbm->vips, ad0->vip_index);

      //TODO: Improve that key
      key0[0] = ip60->src_address.as_u64[0];
      key0[1] = ip60->src_address.as_u64[1];
      key0[2] = ((udp_header_t *)(ip60 + 1))->src_port | ((vip0 - lbm->vips) << 32);

      hash0 = lb_hash_hash(key0);
      lb_hash_get(sticky_ht, key0, hash0, lb_time, &available_index0, &value0);
      if (PREDICT_TRUE(value0 != ~0)) {
        //Found an existing entry
        as0 = &vip0->ass[value0];
      } else if (PREDICT_TRUE(available_index0 != ~0)) {
        //There is an available slot for a new flow
        as0 = &vip0->ass[vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index];
        //Check if we use the default
        if (PREDICT_FALSE(as0 == vip0->ass)) {
          error0 = LB_ERROR_NO_SERVER;
          next0 = LB_NEXT_DROP;
        } else {
          vlib_increment_simple_counter(&lbm->vip_counters[LB_VIP_COUNTER_TRACKED_SESSION],
                                        cpu_index, vip0 - lbm->vips, 1);
        }

        //Dereference previously used
        vlib_refcount_add(&vip0->as_refcount, cpu_index, lb_hash_available_value(sticky_ht, available_index0), -1);
        vlib_refcount_add(&vip0->as_refcount, cpu_index, as0 - vip0->ass, 1);

        //Add sticky entry
        //Note that when there is no AS configured, an entry is configured anyway.
        //But no configured AS is not something that should happen
        lb_hash_put(sticky_ht, key0, as0 - vip0->ass, available_index0, lb_time);
      } else {
        //Could not store new entry in the table
        as0 = &vip0->ass[vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index];
        vlib_increment_simple_counter(&lbm->vip_counters[LB_VIP_COUNTER_UNTRACKED_PACKET],
                                                cpu_index, vip0 - lbm->vips, 1);
      }

      //Now let's encap
      vlib_buffer_advance(p0, - sizeof(ip6_header_t) - sizeof(gre_header_t));
      ip60 = vlib_buffer_get_current(p0);
      gre0 = (gre_header_t *)(ip60 + 1);
      ip60->dst_address = as0->address.ip6;
      ip60->src_address = lbm->ip6_src_address;
      ip60->hop_limit = 128;
      ip60->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6<<28);
      ip60->payload_length = clib_host_to_net_u16(len0 + sizeof(ip6_header_t) + sizeof(gre_header_t));
      ip60->protocol = IP_PROTOCOL_GRE;
      gre0->flags_and_version = 0;
      gre0->protocol = 0x86DD;

      if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
      {
        lb_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
        tr->as_index = ~0;
        tr->vip_index = ad0->vip_index;
        tr->new = 0;
      }

      p0->error = error_node->errors[error0];
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                       n_left_to_next, pi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lb6_node) =
{
  .function = lb6_node_fn,
  .name = "lb6",
  .vector_size = sizeof (u32),
  .format_trace = format_lb_trace,

  .n_errors = LB_N_ERROR,
  .error_strings = lb_error_strings,

  .n_next_nodes = LB_N_NEXT,
  .next_nodes =
  {
      [LB_NEXT_LOOKUP] = "ip6-lookup",
      [LB_NEXT_DROP] = "error-drop"
  },
};

VNET_IP6_REGISTER_ADJACENCY(lb6) = {
  .node_name = "lb6",
  .fn = lb_format_adjacency,
  .next_index = &lb_main.ip6_lookup_next_index
};

VLIB_REGISTER_NODE (lb4_node) =
{
  .function = lb4_node_fn,
  .name = "lb4",
  .vector_size = sizeof (u32),
  .format_trace = format_lb_trace,

  .n_errors = LB_N_ERROR,
  .error_strings = lb_error_strings,

  .n_next_nodes = LB_N_NEXT,
  .next_nodes =
  {
      [LB_NEXT_LOOKUP] = "ip4-lookup",
      [LB_NEXT_DROP] = "error-drop"
  },
};

VNET_IP4_REGISTER_ADJACENCY(lb4) = {
  .node_name = "lb4",
  .fn = lb_format_adjacency,
  .next_index = &lb_main.ip4_lookup_next_index
};
