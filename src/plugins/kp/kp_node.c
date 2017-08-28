/*
 * Copyright (c) 2016 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or anated to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <kp/kp.h>

#include <kp/kphash.h>

#define foreach_kp_error \
 _(NONE, "no error") \
 _(PROTO_NOT_SUPPORTED, "protocol not supported")

typedef enum {
#define _(sym,str) KP_ERROR_##sym,
  foreach_kp_error
#undef _
    KP_N_ERROR,
} kp_error_t;

static char *kp_error_strings[] = {
#define _(sym,string) string,
    foreach_kp_error
#undef _
};

typedef struct {
  u32 vip_index;
  u32 as_index;
} kp_trace_t;

u8 *
format_kp_trace (u8 * s, va_list * args)
{
  kp_main_t *kpm = &kp_main;
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  kp_trace_t *t = va_arg (*args, kp_trace_t *);
  if (pool_is_free_index(kpm->vips, t->vip_index)) {
      s = format(s, "kp vip[%d]: This VIP was freed since capture\n");
  } else {
      s = format(s, "kp vip[%d]: %U\n", t->vip_index, format_kp_vip, &kpm->vips[t->vip_index]);
  }
  if (pool_is_free_index(kpm->ass, t->as_index)) {
      s = format(s, "kp as[%d]: This AS was freed since capture\n");
  } else {
      s = format(s, "kp as[%d]: %U\n", t->as_index, format_kp_as, &kpm->ass[t->as_index]);
  }
  return s;
}

kp_hash_t *kp_get_sticky_table(u32 thread_index)
{
  kp_main_t *kpm = &kp_main;
  kp_hash_t *sticky_ht = kpm->per_cpu[thread_index].sticky_ht;
  //Check if size changed
  if (PREDICT_FALSE(sticky_ht && (kpm->per_cpu_sticky_buckets != kp_hash_nbuckets(sticky_ht))))
    {
      //Dereference everything in there
      kp_hash_bucket_t *b;
      u32 i;
      kp_hash_foreach_entry(sticky_ht, b, i) {
	vlib_refcount_add(&kpm->as_refcount, thread_index, b->value[i], -1);
	vlib_refcount_add(&kpm->as_refcount, thread_index, 0, 1);
      }

      kp_hash_free(sticky_ht);
      sticky_ht = NULL;
    }

  //Create if necessary
  if (PREDICT_FALSE(sticky_ht == NULL)) {
    kpm->per_cpu[thread_index].sticky_ht = kp_hash_alloc(kpm->per_cpu_sticky_buckets, kpm->flow_timeout);
    sticky_ht = kpm->per_cpu[thread_index].sticky_ht;
    clib_warning("Regenerated sticky table %p", sticky_ht);
  }

  ASSERT(sticky_ht);

  //Update timeout
  sticky_ht->timeout = kpm->flow_timeout;
  return sticky_ht;
}

u64
kp_node_get_other_ports4(ip4_header_t *ip40)
{
  return 0;
}

u64
kp_node_get_other_ports6(ip6_header_t *ip60)
{
  return 0;
}

static_always_inline u32
kp_node_get_hash(vlib_buffer_t *p, u8 is_input_v4)
{
  u32 hash;
  if (is_input_v4)
    {
      ip4_header_t *ip40;
      u64 ports;
      ip40 = vlib_buffer_get_current (p);
      if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_TCP ||
		       ip40->protocol == IP_PROTOCOL_UDP))
	ports = ((u64)((udp_header_t *)(ip40 + 1))->src_port << 16) |
	  ((u64)((udp_header_t *)(ip40 + 1))->dst_port);
      else
	ports = kp_node_get_other_ports4(ip40);

      hash = kp_hash_hash(*((u64 *)&ip40->address_pair), ports,
			  0, 0, 0);
    }
  else
    {
      ip6_header_t *ip60;
      ip60 = vlib_buffer_get_current (p);
      u64 ports;
      if (PREDICT_TRUE (ip60->protocol == IP_PROTOCOL_TCP ||
			ip60->protocol == IP_PROTOCOL_UDP))
	ports = ((u64)((udp_header_t *)(ip60 + 1))->src_port << 16) |
	((u64)((udp_header_t *)(ip60 + 1))->dst_port);
      else
	ports = kp_node_get_other_ports6(ip60);

      hash = kp_hash_hash(ip60->src_address.as_u64[0],
			  ip60->src_address.as_u64[1],
			  ip60->dst_address.as_u64[0],
			  ip60->dst_address.as_u64[1],
			  ports);
    }
  return hash;
}

static_always_inline uword
kp_node_fn (vlib_main_t * vm,
         vlib_node_runtime_t * node, vlib_frame_t * frame,
         u8 is_input_v4, //Compile-time parameter stating that is input is v4 (or v6)
         u8 is_nat_v4) //Compile-time parameter stating that is NAT is v4 (or v6)
{
  kp_main_t *kpm = &kp_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 thread_index = vlib_get_thread_index();
  u32 kp_time = kp_hash_time_now(vm);

  kp_hash_t *sticky_ht = kp_get_sticky_table(thread_index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 nexthash0 = 0;
  if (PREDICT_TRUE(n_left_from > 0))
    nexthash0 = kp_node_get_hash(vlib_get_buffer (vm, from[0]), is_input_v4);

  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      kp_vip_t *vip0;
      u32 asindex0;
      //u16 len0 = 0;
      u32 available_index0;
      u8 counter = 0;
      u32 hash0 = nexthash0;

      if (PREDICT_TRUE(n_left_from > 1))
	{
	  vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
	  //Compute next hash and prefetch bucket
	  nexthash0 = kp_node_get_hash(p1, is_input_v4);
	  kp_hash_prefetch_bucket(sticky_ht, nexthash0);
	  //Prefetch for encap, next
	  CLIB_PREFETCH (vlib_buffer_get_current(p1) - 64, 64, STORE);
	}

      if (PREDICT_TRUE(n_left_from > 2))
	{
	  vlib_buffer_t *p2;
	  p2 = vlib_get_buffer(vm, from[2]);
	  /* prefetch packet header and data */
	  vlib_prefetch_buffer_header(p2, STORE);
	  CLIB_PREFETCH (vlib_buffer_get_current(p2), 64, STORE);
	}

      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;

      p0 = vlib_get_buffer (vm, pi0);
      vip0 = pool_elt_at_index (kpm->vips,
				vnet_buffer (p0)->ip.adj_index[VLIB_TX]);

      kp_hash_get(sticky_ht, hash0, vnet_buffer (p0)->ip.adj_index[VLIB_TX],
		  kp_time, &available_index0, &asindex0);

      if (PREDICT_TRUE(asindex0 != ~0))
	{
	  //Found an existing entry
	  counter = KP_VIP_COUNTER_NEXT_PACKET;
	}
      else if (PREDICT_TRUE(available_index0 != ~0))
	{
	  //There is an available slot for a new flow
	  asindex0 = vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index;
	  counter = KP_VIP_COUNTER_FIRST_PACKET;
	  counter = (asindex0 == 0)?KP_VIP_COUNTER_NO_SERVER:counter;

	  //TODO: There are race conditions with as0 and vip0 manipulation.
	  //Configuration may be changed, vectors resized, etc...

	  //Dereference previously used
	  vlib_refcount_add(&kpm->as_refcount, thread_index,
			    kp_hash_available_value(sticky_ht, hash0, available_index0), -1);
	  vlib_refcount_add(&kpm->as_refcount, thread_index,
			    asindex0, 1);

	  //Add sticky entry
	  //Note that when there is no AS configured, an entry is configured anyway.
	  //But no configured AS is not something that should happen
	  kp_hash_put(sticky_ht, hash0, asindex0,
		      vnet_buffer (p0)->ip.adj_index[VLIB_TX],
		      available_index0, kp_time);
	}
      else
	{
	  //Could not store new entry in the table
	  asindex0 = vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index;
	  counter = KP_VIP_COUNTER_UNTRACKED_PACKET;
	}

      vlib_increment_simple_counter(&kpm->vip_counters[counter],
				    thread_index,
				    vnet_buffer (p0)->ip.adj_index[VLIB_TX],
				    1);
      //Now let's do NAT
      {
	udp_header_t *port0;
	if (is_nat_v4)
	  {
	    ip4_header_t *ip40;
	    ip40 = vlib_buffer_get_current(p0);
	    port0 = (udp_header_t *)(ip40 + 1);
	    ip40->dst_address = kpm->ass[asindex0].address.ip4;
	    ip40->checksum = ip4_header_checksum (ip40);
	  }
	else
	  {
	    ip6_header_t *ip60;
	    ip60 = vlib_buffer_get_current(p0);
	    port0 = (udp_header_t *)(ip60 + 1);
	    ip60->dst_address = kpm->ass[asindex0].address.ip6;
	  }
          port0->dst_port = vip0->target_port;
      }

      if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  kp_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
	  tr->as_index = asindex0;
	  tr->vip_index = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	}

      //Enqueue to next
      //Note that this is going to error if asindex0 == 0
      vnet_buffer (p0)->ip.adj_index[VLIB_TX] = kpm->ass[asindex0].dpo.dpoi_index;
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
				       n_left_to_next, pi0,
				       kpm->ass[asindex0].dpo.dpoi_next_node);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  return frame->n_vectors;
}

static uword
kp6_nat6_node_fn (vlib_main_t * vm,
         vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return kp_node_fn(vm, node, frame, 0, 0);
}

static uword
kp6_nat4_node_fn (vlib_main_t * vm,
         vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return kp_node_fn(vm, node, frame, 0, 1);
}

static uword
kp4_nat6_node_fn (vlib_main_t * vm,
         vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return kp_node_fn(vm, node, frame, 1, 0);
}

static uword
kp4_nat4_node_fn (vlib_main_t * vm,
         vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return kp_node_fn(vm, node, frame, 1, 1);
}

VLIB_REGISTER_NODE (kp6_nat6_node) =
{
  .function = kp6_nat6_node_fn,
  .name = "kp6-nat6",
  .vector_size = sizeof (u32),
  .format_trace = format_kp_trace,

  .n_errors = KP_N_ERROR,
  .error_strings = kp_error_strings,

  .n_next_nodes = KP_N_NEXT,
  .next_nodes =
  {
      [KP_NEXT_DROP] = "error-drop"
  },
};

VLIB_REGISTER_NODE (kp6_nat4_node) =
{
  .function = kp6_nat4_node_fn,
  .name = "kp6-nat4",
  .vector_size = sizeof (u32),
  .format_trace = format_kp_trace,

  .n_errors = KP_N_ERROR,
  .error_strings = kp_error_strings,

  .n_next_nodes = KP_N_NEXT,
  .next_nodes =
  {
      [KP_NEXT_DROP] = "error-drop"
  },
};

VLIB_REGISTER_NODE (kp4_nat6_node) =
{
  .function = kp4_nat6_node_fn,
  .name = "kp4-nat6",
  .vector_size = sizeof (u32),
  .format_trace = format_kp_trace,

  .n_errors = KP_N_ERROR,
  .error_strings = kp_error_strings,

  .n_next_nodes = KP_N_NEXT,
  .next_nodes =
  {
      [KP_NEXT_DROP] = "error-drop"
  },
};

VLIB_REGISTER_NODE (kp4_nat4_node) =
{
  .function = kp4_nat4_node_fn,
  .name = "kp4-nat4",
  .vector_size = sizeof (u32),
  .format_trace = format_kp_trace,

  .n_errors = KP_N_ERROR,
  .error_strings = kp_error_strings,

  .n_next_nodes = KP_N_NEXT,
  .next_nodes =
  {
      [KP_NEXT_DROP] = "error-drop"
  },
};

