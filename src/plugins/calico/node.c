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

#include <calico/calico.h>
#include <vnet/fib/ip4_fib.h>

#include <vnet/gre/packet.h>
#include <calico/calicohash.h>

#define foreach_calico_error \
 _(NONE, "no error") \
 _(PROTO_NOT_SUPPORTED, "protocol not supported")

typedef enum
{
#define _(sym,str) CALICO_ERROR_##sym,
  foreach_calico_error
#undef _
  CALICO_N_ERROR,
} calico_error_t;

static char *calico_error_strings[] =
  {
#define _(sym,string) string,
      foreach_calico_error
#undef _
    };

typedef struct
{
  u32 vip_index;
  u32 as_index;
} calico_trace_t;

typedef struct
{
  u32 vip_index;
  u32 as_index;
  u32 rx_sw_if_index;
  u32 next_index;
} calico_nat_trace_t;

u8 *
format_calico_trace (u8 * s, va_list * args)
{
  calico_main_t *cam = &calico_main;
  CLIB_UNUSED(vlib_main_t * vm)
= va_arg (*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node)
  = va_arg (*args, vlib_node_t *);
  calico_trace_t *t = va_arg (*args, calico_trace_t *);
  if (pool_is_free_index(cam->vips, t->vip_index))
    {
      s = format (s, "calico vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "calico vip[%d]: %U\n", t->vip_index, format_calico_vip,
                  &cam->vips[t->vip_index]);
    }
  if (pool_is_free_index(cam->ass, t->as_index))
    {
      s = format (s, "calico as[%d]: This AS was freed since capture\n");
    }
  else
    {
      s = format (s, "calico as[%d]: %U\n", t->as_index, format_calico_as,
                  &cam->ass[t->as_index]);
    }
  return s;
}

u8 *
format_calico_nat_trace (u8 * s, va_list * args)
{
  calico_main_t *cam = &calico_main;
  CLIB_UNUSED(vlib_main_t * vm)
= va_arg (*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node)
  = va_arg (*args, vlib_node_t *);
  calico_nat_trace_t *t = va_arg (*args, calico_nat_trace_t *);

  if (pool_is_free_index(cam->vips, t->vip_index))
    {
      s = format (s, "calico vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "calico vip[%d]: %U\n", t->vip_index, format_calico_vip,
                  &cam->vips[t->vip_index]);
    }
  if (pool_is_free_index(cam->ass, t->as_index))
    {
      s = format (s, "calico as[%d]: This AS was freed since capture\n");
    }
  else
    {
      s = format (s, "calico as[%d]: %U\n", t->as_index, format_calico_as,
                  &cam->ass[t->as_index]);
    }
  s = format (s, "calico nat: rx_sw_if_index = %d, next_index = %d",
              t->rx_sw_if_index, t->next_index);

  return s;
}

calico_hash_t *
calico_get_sticky_table (u32 thread_index)
{
  calico_main_t *cam = &calico_main;
  calico_hash_t *sticky_ht = cam->per_cpu[thread_index].sticky_ht;
  //Check if size changed
  if (PREDICT_FALSE(
      sticky_ht && (cam->per_cpu_sticky_buckets != calico_hash_nbuckets(sticky_ht))))
    {
      //Dereference everything in there
      calico_hash_bucket_t *b;
      u32 i;
      calico_hash_foreach_entry(sticky_ht, b, i)
        {
          vlib_refcount_add (&cam->as_refcount, thread_index, b->value[i], -1);
          vlib_refcount_add (&cam->as_refcount, thread_index, 0, 1);
        }

      calico_hash_free (sticky_ht);
      sticky_ht = NULL;
    }

  //Create if necessary
  if (PREDICT_FALSE(sticky_ht == NULL))
    {
      cam->per_cpu[thread_index].sticky_ht = calico_hash_alloc (
          cam->per_cpu_sticky_buckets, cam->flow_timeout);
      sticky_ht = cam->per_cpu[thread_index].sticky_ht;
    }

  ASSERT(sticky_ht);

  //Update timeout
  sticky_ht->timeout = cam->flow_timeout;
  return sticky_ht;
}

u64
calico_node_get_other_ports4 (ip4_header_t *ip40)
{
  return 0;
}

u64
calico_node_get_other_ports6 (ip6_header_t *ip60)
{
  return 0;
}

static inline int
calico_search_5tuple (calico_main_t *cam, ip6_header_t * ip60, udp_header_t *udp0, u32* vip_index0)
{
  clib_bihash_kv_40_8_t kv, val;
  u64 t;
  t = (u64) (vlib_time_now (cam->vlib_main) * 1000.f);
  int rv;

  kv.key[0] = ip60->src_address.as_u64[0];
  kv.key[1] = ip60->src_address.as_u64[1];
  kv.key[2] = ip60->dst_address.as_u64[0];
  kv.key[3] = ip60->dst_address.as_u64[1];
  kv.key[4] = ((u64) ip60->protocol << 32) | (((u64) udp0->src_port) << 16) | ((u64) udp0->dst_port);
  // FIXME fib index ?
  rv = clib_bihash_search_40_8 (&cam->return_path_5tuple_map, &kv, &val);
  if (rv)
    return rv;

  if (t - (val.value >> 32) < CALICO_NAT_TIMEOUT)
    {
      *vip_index0 = (u32) val.value & 0xffffffff;
      return 0;
    }
  clib_bihash_add_del_40_8(&cam->return_path_5tuple_map, &kv, 0 /* is_add */);
  return 1;
}

static inline void
calico_add_5tuple (calico_main_t *cam, ip6_header_t * ip60, udp_header_t *udp0, u32 vip_index0)
{
  clib_bihash_kv_40_8_t kv;
  u64 t;
  t = (u64) (vlib_time_now (cam->vlib_main) * 1000.f);
  kv.key[0] = ip60->dst_address.as_u64[0];
  kv.key[1] = ip60->dst_address.as_u64[1];
  kv.key[2] = ip60->src_address.as_u64[0];
  kv.key[3] = ip60->src_address.as_u64[1];
  kv.key[4] = ((u64) ip60->protocol << 32) | (((u64) udp0->dst_port) << 16) | ((u64) udp0->src_port);
  // FIXME fib index ?
  kv.value = t << 32 | (u64) vip_index0;
  clib_bihash_add_del_40_8(&cam->return_path_5tuple_map, &kv, 1 /* is_add */);
}

static_always_inline void
calico_node_get_hash (calico_main_t *cam, vlib_buffer_t *p, u8 is_input_v4,
                  u32 *hash, u32 *vip_idx, u8 per_port_vip)
{
  vip_port_key_t key;
  clib_bihash_kv_8_8_t kv, value;

  /* For vip case, retrieve vip index for ip lookup */
  *vip_idx = vnet_buffer (p)->ip.adj_index[VLIB_TX];

  if (per_port_vip)
    {
      /* For per-port-vip case, ip lookup stores dummy index */
      key.vip_prefix_index = *vip_idx;
    }

  if (is_input_v4)
    {
      ip4_header_t *ip40;
      u64 ports;

      ip40 = vlib_buffer_get_current (p);
      if (PREDICT_TRUE(
          ip40->protocol == IP_PROTOCOL_TCP
              || ip40->protocol == IP_PROTOCOL_UDP))
        ports = ((u64) ((udp_header_t *) ip4_next_header(ip40))->src_port << 16)
            | ((u64) ((udp_header_t *) ip4_next_header(ip40))->dst_port);
      else
        ports = calico_node_get_other_ports4 (ip40);

      *hash = lb_hash_hash (*((u64 *) &ip40->address_pair), ports, 0, 0, 0);

      if (per_port_vip)
        {
          key.protocol = ip40->protocol;
          key.port = (u16)(ports & 0xFFFF);
        }
    }
  else
    {
      ip6_header_t *ip60;
      ip60 = vlib_buffer_get_current (p);
      u64 ports;

      if (PREDICT_TRUE(
          ip60->protocol == IP_PROTOCOL_TCP
              || ip60->protocol == IP_PROTOCOL_UDP))
        ports = ((u64) ((udp_header_t *) ip6_next_header(ip60))->src_port << 16)
            | ((u64) ((udp_header_t *) ip6_next_header(ip60))->dst_port);
      else
        ports = calico_node_get_other_ports6 (ip60);

      *hash = lb_hash_hash (ip60->src_address.as_u64[0],
                           ip60->src_address.as_u64[1],
                           ip60->dst_address.as_u64[0],
                           ip60->dst_address.as_u64[1], ports);

      if (per_port_vip)
        {
          key.protocol = ip60->protocol;
          key.port = (u16)(ports & 0xFFFF);
        }
    }

  /* For per-port-vip case, retrieve vip index for vip_port_filter table */
  if (per_port_vip)
    {
      kv.key = key.as_u64;
      if (clib_bihash_search_8_8(&cam->vip_index_per_port, &kv, &value) < 0)
        {
          /* return default vip */
          *vip_idx = 0;
          return;
        }
      *vip_idx = value.value;
    }
}

static_always_inline uword
calico_node_fn (vlib_main_t * vm,
            vlib_node_runtime_t * node,
            vlib_frame_t * frame,
            u8 is_input_v4, //Compile-time parameter stating that is input is v4 (or v6)
            calico_encap_type_t encap_type, //Compile-time parameter is GRE4/GRE6/L3DSR/NAT4/NAT6
            u8 per_port_vip) //Compile-time parameter stating that is per_port_vip or not
{
  calico_main_t *cam = &calico_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 thread_index = vm->thread_index;
  u32 calico_time = calico_hash_time_now (vm);

  calico_hash_t *sticky_ht = calico_get_sticky_table (thread_index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 nexthash0 = 0;
  u32 next_vip_idx0 = ~0;
  if (PREDICT_TRUE(n_left_from > 0))
    {
      vlib_buffer_t *p0 = vlib_get_buffer (vm, from[0]);
      calico_node_get_hash (cam, p0, is_input_v4, &nexthash0,
                        &next_vip_idx0, per_port_vip);
    }

  while (n_left_from > 0)
    {
      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 pi0;
          vlib_buffer_t *p0;
          calico_vip_t *vip0;
          u32 asindex0 = 0;
          u32 available_index0;
          u8 counter = 0;
          u32 hash0 = nexthash0;
          u32 vip_index0 = next_vip_idx0;
          u32 next0;

          if (PREDICT_TRUE(n_left_from > 1))
            {
              vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
              //Compute next hash and prefetch bucket
              calico_node_get_hash (cam, p1, is_input_v4,
                                &nexthash0, &next_vip_idx0,
                                per_port_vip);
              calico_hash_prefetch_bucket (sticky_ht, nexthash0);
              //Prefetch for encap, next
              CLIB_PREFETCH(vlib_buffer_get_current (p1) - 64, 64, STORE);
            }

          if (PREDICT_TRUE(n_left_from > 2))
            {
              vlib_buffer_t *p2;
              p2 = vlib_get_buffer (vm, from[2]);
              /* prefetch packet header and data */
              vlib_prefetch_buffer_header(p2, STORE);
              CLIB_PREFETCH(vlib_buffer_get_current (p2), 64, STORE);
            }

          pi0 = to_next[0] = from[0];
          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          p0 = vlib_get_buffer (vm, pi0);

          vip0 = pool_elt_at_index(cam->vips, vip_index0);

          // if (is_input_v4)
          //   {
          //     ip4_header_t *ip40;
          //     ip40 = vlib_buffer_get_current (p0);
          //   }
          // else
          //   {
          //     ip6_header_t *ip60;
          //     ip60 = vlib_buffer_get_current (p0);
          //   }

          calico_hash_get (sticky_ht, hash0,
                       vip_index0, calico_time,
                       &available_index0, &asindex0);

          if (PREDICT_TRUE(asindex0 != 0))
            {
              //Found an existing entry
              counter = CALICO_VIP_COUNTER_NEXT_PACKET;
            }
          else if (PREDICT_TRUE(available_index0 != ~0))
            {
              //There is an available slot for a new flow
              asindex0 =
                  vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index;
              counter = CALICO_VIP_COUNTER_FIRST_PACKET;
              counter = (asindex0 == 0) ? CALICO_VIP_COUNTER_NO_SERVER : counter;

              //TODO: There are race conditions with as0 and vip0 manipulation.
              //Configuration may be changed, vectors resized, etc...

              //Dereference previously used
              vlib_refcount_add (
                  &cam->as_refcount, thread_index,
                  calico_hash_available_value (sticky_ht, hash0, available_index0),
                  -1);
              vlib_refcount_add (&cam->as_refcount, thread_index, asindex0, 1);

              //Add sticky entry
              //Note that when there is no AS configured, an entry is configured anyway.
              //But no configured AS is not something that should happen
              calico_hash_put (sticky_ht, hash0, asindex0,
                           vip_index0,
                           available_index0, calico_time);
            }
          else
            {
              //Could not store new entry in the table
              asindex0 =
                  vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index;
              counter = CALICO_VIP_COUNTER_UNTRACKED_PACKET;
            }

          vlib_increment_simple_counter (
              &cam->vip_counters[counter], thread_index,
              vip_index0,
              1);

          //Now let's encap
          ip_csum_t csum;
          udp_header_t *uh;
          tcp_header_t *th;

          /* do NAT */
          if ((is_input_v4 == 1) && (encap_type == CALICO_ENCAP_TYPE_NAT4))
            {
              /* NAT44 */
              ip4_header_t *ip40;
              u32 old_dst;
              ip40 = vlib_buffer_get_current (p0);
              old_dst = ip40->dst_address.as_u32;
              ip40->dst_address = cam->ass[asindex0].address.ip4;

              csum = ip40->checksum;
              csum = ip_csum_sub_even (csum, old_dst);
              csum = ip_csum_add_even (
                  csum, cam->ass[asindex0].address.ip4.as_u32);
              ip40->checksum = ip_csum_fold (csum);

              if (ip40->protocol == IP_PROTOCOL_TCP)
                {
		  th = (tcp_header_t *) ip4_next_header(ip40);
                  csum = th->checksum;
                  csum = ip_csum_sub_even (csum, old_dst);
                  csum = ip_csum_add_even (
                      csum, cam->ass[asindex0].address.ip4.as_u32);
                  csum = ip_csum_sub_even (csum, th->dst_port);
                  th->dst_port = vip0->target_port;
                  csum = ip_csum_add_even (csum, th->dst_port);
                  th->checksum = ip_csum_fold (csum);
                }
              else if (ip40->protocol == IP_PROTOCOL_UDP)
                {
                  uh = (udp_header_t *) ip4_next_header(ip40);
                  uh->dst_port = vip0->target_port;
                  csum = uh->checksum;
                  csum = ip_csum_sub_even (csum, old_dst);
                  csum = ip_csum_add_even (
                      csum, cam->ass[asindex0].address.ip4.as_u32);
                  uh->checksum = ip_csum_fold (csum);
                }
              else
                {
                  asindex0 = 0;
                }
            }
          else if ((is_input_v4 == 0) && (encap_type == CALICO_ENCAP_TYPE_NAT6))
            {
              /* NAT66 */
              ip6_header_t *ip60;
              ip6_address_t old_dst;
              udp_header_t *udp0;
              tcp_header_t *tcp0;

              ip60 = vlib_buffer_get_current (p0);

              old_dst.as_u64[0] = ip60->dst_address.as_u64[0];
              old_dst.as_u64[1] = ip60->dst_address.as_u64[1];
              ip60->dst_address.as_u64[0] =
                  cam->ass[asindex0].address.ip6.as_u64[0];
              ip60->dst_address.as_u64[1] =
                  cam->ass[asindex0].address.ip6.as_u64[1];
              udp0 = ip6_next_header(ip60);

              if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_TCP))
                {
		  tcp0 = (tcp_header_t *) udp0;
                  csum = tcp0->checksum;
                  csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
                  csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
                  csum = ip_csum_add_even (csum, cam->ass[asindex0].address.ip6.as_u64[0]);
                  csum = ip_csum_add_even (csum, cam->ass[asindex0].address.ip6.as_u64[1]);
                  csum = ip_csum_sub_even (csum, tcp0->dst_port);
                  tcp0->dst_port = vip0->target_port;
                  csum = ip_csum_add_even (csum, tcp0->dst_port);
                  tcp0->checksum = ip_csum_fold (csum);
                  calico_add_5tuple (cam, ip60, udp0, vip_index0);
                }
              else if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_UDP))
                {
                  udp0->dst_port = vip0->target_port;
                  csum = udp0->checksum;
                  csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
                  csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
                  csum = ip_csum_add_even (csum, cam->ass[asindex0].address.ip6.as_u64[0]);
                  csum = ip_csum_add_even (csum, cam->ass[asindex0].address.ip6.as_u64[1]);
                  udp0->checksum = ip_csum_fold (csum);
                  calico_add_5tuple (cam, ip60, udp0, vip_index0);
                }
              else
                {
                  asindex0 = 0;
                }
            }
          next0 = cam->ass[asindex0].dpo.dpoi_next_node;
          //Note that this is going to error if asindex0 == 0
          vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
              cam->ass[asindex0].dpo.dpoi_index;

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              calico_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof(*tr));
              tr->as_index = asindex0;
              tr->vip_index = vip_index0;
            }

          //Enqueue to next
          vlib_validate_buffer_enqueue_x1(
              vm, node, next_index, to_next, n_left_to_next, pi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
calico_nat_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame, u32 is_nat4)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_processed = 0;
  calico_main_t *cam = &calico_main;
  u32 stats_node_index;

  stats_node_index =
      is_nat4 ? calico_nat4_in2out_node.index : calico_nat6_in2out_node.index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 nexthash0 = 0;
  u32 next_vip_idx0 = ~0;
  if (PREDICT_TRUE(n_left_from > 0))
    {
      vlib_buffer_t *p0 = vlib_get_buffer (vm, from[0]);
      calico_node_get_hash (cam, p0, is_nat4, &nexthash0,
                        &next_vip_idx0, 1 /* per_port_vip */);
    }

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          ip_csum_t csum;
          u16 old_port0, new_port0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          u32 vip_index0 = next_vip_idx0;
	  u32 iph_offset0 = 0;

          // u32 rx_fib_index0;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
	  iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;

          next0 = CALICO_NAT4_IN2OUT_NEXT_LOOKUP;
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          // rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (
          //     sw_if_index0);

          if (PREDICT_TRUE(n_left_from > 1))
            {
              vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
              //Compute next hash and prefetch bucket
              calico_node_get_hash (cam, p1, is_nat4,
                                &nexthash0, &next_vip_idx0,
                                1 /* per_port_vip */);
            }

          if (vip_index0)
	    {
	      /* Do not touch traffic destinated to a VIP */
	      next0 = CALICO_NAT4_IN2OUT_NEXT_LOOKUP;
              goto trace0;
	    }

          if (is_nat4)
            {
      //         ip4_header_t * ip40;
      //         u32 old_addr0, new_addr0;
      //         calico_snat4_key_t key40;
      //         calico_snat_mapping_t *sm40;
      //         u32 index40;

      //         ip40 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  // iph_offset0);
      //         udp0 = ip4_next_header (ip40);
      //         tcp0 = (tcp_header_t *) udp0;
      //         proto0 = calico_ip_proto_to_nat_proto (ip40->protocol);

      //         key40.addr = ip40->src_address;
      //         key40.protocol = proto0;
      //         key40.port = udp0->src_port;
      //         key40.fib_index = rx_fib_index0;

      //         if (calico_nat44_mapping_match (cam, &key40, &index40))
      //           {
      //             next0 = CALICO_NAT6_IN2OUT_NEXT_SNAT6;
      //             goto trace0;
      //           }

      //         // sm40 = pool_elt_at_index(cam->snat_mappings, index40);
      //         new_addr0 = sm40->src_ip.ip4.as_u32;
      //         new_port0 = sm40->src_port;
      //         vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm40->fib_index;
      //         old_addr0 = ip40->src_address.as_u32;
      //         ip40->src_address.as_u32 = new_addr0;

      //         csum = ip40->checksum;
      //         csum = ip_csum_sub_even (csum, old_addr0);
      //         csum = ip_csum_add_even (csum, new_addr0);
      //         ip40->checksum = ip_csum_fold (csum);

      //         if (PREDICT_TRUE(proto0 == CALICO_NAT_PROTOCOL_TCP))
      //           {
      //             old_port0 = tcp0->src_port;
      //             tcp0->src_port = new_port0;

      //             csum = tcp0->checksum;
      //             csum = ip_csum_sub_even (csum, old_addr0);
      //             csum = ip_csum_sub_even (csum, old_port0);
      //             csum = ip_csum_add_even (csum, new_addr0);
      //             csum = ip_csum_add_even (csum, new_port0);
      //             tcp0->checksum = ip_csum_fold (csum);
      //           }
      //         else if (PREDICT_TRUE(proto0 == CALICO_NAT_PROTOCOL_UDP))
      //           {
      //             old_port0 = udp0->src_port;
      //             udp0->src_port = new_port0;

      //             csum = udp0->checksum;
      //             csum = ip_csum_sub_even (csum, old_addr0);
      //             csum = ip_csum_sub_even (csum, old_port0);
      //             csum = ip_csum_add_even (csum, new_addr0);
      //             csum = ip_csum_add_even (csum, new_port0);
      //             udp0->checksum = ip_csum_fold (csum);
      //           }

      //         pkts_processed += next0 != CALICO_NAT4_IN2OUT_NEXT_DROP;
            }
          else
            {
              ip6_header_t * ip60;
              ip6_address_t old_addr0, new_addr0;
              calico_vip_t *vip0;

              ip60 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  iph_offset0);
              udp0 = ip6_next_header (ip60);

	      if (calico_search_5tuple(cam, ip60, udp0, &vip_index0))
		{
		    next0 = CALICO_NAT6_IN2OUT_NEXT_SNAT6;
                    goto trace0;
		}

              vip0 = pool_elt_at_index(cam->vips, vip_index0);

              new_addr0.as_u64[0] = vip0->prefix.ip6.as_u64[0];
              new_addr0.as_u64[1] = vip0->prefix.ip6.as_u64[1];
              new_port0 = vip0->port;
              old_addr0.as_u64[0] = ip60->src_address.as_u64[0];
              old_addr0.as_u64[1] = ip60->src_address.as_u64[1];
              ip60->src_address.as_u64[0] = new_addr0.as_u64[0];
              ip60->src_address.as_u64[1] = new_addr0.as_u64[1];

              if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_TCP))
                {
        	  tcp0 = (tcp_header_t *) udp0;
                  old_port0 = tcp0->src_port;
                  tcp0->src_port = new_port0;

                  csum = tcp0->checksum;
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[0]);
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[1]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[0]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[1]);
                  csum = ip_csum_sub_even (csum, old_port0);
                  csum = ip_csum_add_even (csum, new_port0);
                  tcp0->checksum = ip_csum_fold (csum);
                }
              else if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_UDP))
                {
                  old_port0 = udp0->src_port;
                  udp0->src_port = new_port0;

                  csum = udp0->checksum;
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[0]);
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[1]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[0]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[1]);
                  csum = ip_csum_sub_even (csum, old_port0);
                  csum = ip_csum_add_even (csum, new_port0);
                  udp0->checksum = ip_csum_fold (csum);
                }

              pkts_processed += next0 != CALICO_NAT4_IN2OUT_NEXT_DROP;
            }

          trace0: if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              calico_nat_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
              t->rx_sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               CALICO_NAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
calico_snat_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                 vlib_frame_t * frame, u32 is_input_v4)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t *b0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          ip_csum_t csum;
          u32 next0;
	  u32 iph_offset0 = 0;

          if (PREDICT_TRUE(n_left_from > 1))
            {
              vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
              //Prefetch for encap, next
              CLIB_PREFETCH(vlib_buffer_get_current (p1) - 64, 64, STORE);
            }

          if (PREDICT_TRUE(n_left_from > 2))
            {
              vlib_buffer_t *p2;
              p2 = vlib_get_buffer (vm, from[2]);
              /* prefetch packet header and data */
              vlib_prefetch_buffer_header(p2, STORE);
              CLIB_PREFETCH(vlib_buffer_get_current (p2), 64, STORE);
            }

          bi0 = to_next[0] = from[0];
          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          next0 = CALICO_SNAT6_NEXT_OUTPUT;
	  iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;

          if (is_input_v4)
            {
              goto trace0;
            }
          else
            {
              ip6_header_t * ip60;
              ip60 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			iph_offset0);
              udp0 = ip6_next_header (ip60);
              ip6_address_t old_addr0, new_addr0;
              if (calico_search_snat6_entry(&ip60->src_address, &ip60->dst_address, &new_addr0, 0))
        	{
		  goto trace0;
        	}

              old_addr0.as_u64[0] = ip60->src_address.as_u64[0];
              old_addr0.as_u64[1] = ip60->src_address.as_u64[1];
              ip60->src_address.as_u64[0] = new_addr0.as_u64[0];
              ip60->src_address.as_u64[1] = new_addr0.as_u64[1];

              if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_TCP))
                {
        	  tcp0 = (tcp_header_t *) udp0;
                  csum = tcp0->checksum;
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[0]);
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[1]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[0]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[1]);
                  tcp0->checksum = ip_csum_fold (csum);
                }
              else if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_UDP))
                {
                  csum = udp0->checksum;
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[0]);
                  csum = ip_csum_sub_even (csum, old_addr0.as_u64[1]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[0]);
                  csum = ip_csum_add_even (csum, new_addr0.as_u64[1]);
                  udp0->checksum = ip_csum_fold (csum);
                }

            }

    trace0:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
            	/* Todo */
            }

          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next, n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
calico6_nat6_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return calico_node_fn (vm, node, frame, 0, CALICO_ENCAP_TYPE_NAT6, 1);
}

static uword
calico4_nat4_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return calico_node_fn (vm, node, frame, 1, CALICO_ENCAP_TYPE_NAT4, 1);
}

static uword
calico_nat4_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return calico_nat_in2out_node_fn (vm, node, frame, 1);
}

static uword
calico_nat6_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return calico_nat_in2out_node_fn (vm, node, frame, 0);
}

static uword
calico_snat6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return calico_snat_node_fn (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (calico6_nat6_port_node) =
  {
    .function = calico6_nat6_port_node_fn,
    .name = "calico6-nat6-port",
    .vector_size = sizeof(u32),
    .format_trace = format_calico_trace,
    .n_errors = CALICO_N_ERROR,
    .error_strings = calico_error_strings,
    .n_next_nodes = CALICO_N_NEXT,
    .next_nodes =
        { [CALICO_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (calico4_nat4_port_node) =
  {
    .function = calico4_nat4_port_node_fn,
    .name = "calico4-nat4-port",
    .vector_size = sizeof(u32),
    .format_trace = format_calico_trace,
    .n_errors = CALICO_N_ERROR,
    .error_strings = calico_error_strings,
    .n_next_nodes = CALICO_N_NEXT,
    .next_nodes =
        { [CALICO_NEXT_DROP] = "error-drop" },
  };

VNET_FEATURE_INIT (calico_nat4_in2out_node_fn, static) =
  {
    .arc_name = "ip4-unicast",
    .node_name = "calico-nat4-in2out",
    .runs_before =  VNET_FEATURES("ip4-lookup"),
  };

VLIB_REGISTER_NODE (calico_nat4_in2out_node) =
  {
    .function = calico_nat4_in2out_node_fn,
    .name = "calico-nat4-in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_calico_nat_trace,
    .n_errors = CALICO_N_ERROR,
    .error_strings = calico_error_strings,
    .n_next_nodes = CALICO_NAT4_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [CALICO_NAT4_IN2OUT_NEXT_DROP] = "error-drop",
          [CALICO_NAT4_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
      },
  };

VNET_FEATURE_INIT (calico_nat6_in2out_node_fn, static) =
  {
    .arc_name = "ip6-output",
    .node_name = "calico-nat6-in2out",
    .runs_before = VNET_FEATURES("interface-output"),
  };

VLIB_REGISTER_NODE (calico_nat6_in2out_node) =
  {
    .function = calico_nat6_in2out_node_fn,
    .name = "calico-nat6-in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_calico_nat_trace,
    .n_errors = CALICO_N_ERROR,
    .error_strings = calico_error_strings,
    .n_next_nodes = CALICO_NAT6_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [CALICO_NAT6_IN2OUT_NEXT_DROP] = "error-drop",
          [CALICO_NAT6_IN2OUT_NEXT_LOOKUP] = "interface-output",
          [CALICO_NAT6_IN2OUT_NEXT_SNAT6] = "calico-snat6",
      },
  };

VLIB_REGISTER_NODE (calico_snat6_node) =
  {
    .function = calico_snat6_node_fn,
    .name = "calico-snat6",
    .vector_size = sizeof(u32),
    .format_trace = format_calico_nat_trace,
    .n_errors = CALICO_N_ERROR,
    .error_strings = calico_error_strings,
    .n_next_nodes = CALICO_SNAT6_N_NEXT,
    .next_nodes =
      {
          [CALICO_SNAT6_NEXT_DROP] = "error-drop",
          [CALICO_SNAT6_NEXT_OUTPUT] = "interface-output",
      },
  };

