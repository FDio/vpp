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
#include <vnet/fib/ip4_fib.h>

#include <vnet/gre/packet.h>
#include <lb/lbhash.h>

#define foreach_lb_error \
 _(NONE, "no error") \
 _(PROTO_NOT_SUPPORTED, "protocol not supported")

typedef enum
{
#define _(sym,str) LB_ERROR_##sym,
  foreach_lb_error
#undef _
  LB_N_ERROR,
} lb_error_t;

static char *lb_error_strings[] =
  {
#define _(sym,string) string,
      foreach_lb_error
#undef _
    };

typedef struct
{
  u32 vip_index;
  u32 as_index;
} lb_trace_t;

typedef struct
{
  u32 vip_index;

  u32 node_port;
} lb_nodeport_trace_t;

typedef struct
{
  u32 vip_index;
  u32 as_index;
  u32 rx_sw_if_index;
  u32 next_index;
} lb_nat_trace_t;

u8 *
format_lb_trace (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  CLIB_UNUSED(vlib_main_t * vm)
= va_arg (*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node)
  = va_arg (*args, vlib_node_t *);
  lb_trace_t *t = va_arg (*args, lb_trace_t *);
  if (pool_is_free_index(lbm->vips, t->vip_index))
    {
      s = format (s, "lb vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "lb vip[%d]: %U\n", t->vip_index, format_lb_vip,
                  &lbm->vips[t->vip_index]);
    }
  if (pool_is_free_index(lbm->ass, t->as_index))
    {
      s = format (s, "lb as[%d]: This AS was freed since capture\n");
    }
  else
    {
      s = format (s, "lb as[%d]: %U\n", t->as_index, format_lb_as,
                  &lbm->ass[t->as_index]);
    }
  return s;
}

u8 *
format_lb_nat_trace (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  CLIB_UNUSED(vlib_main_t * vm)
= va_arg (*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node)
  = va_arg (*args, vlib_node_t *);
  lb_nat_trace_t *t = va_arg (*args, lb_nat_trace_t *);

  if (pool_is_free_index(lbm->vips, t->vip_index))
    {
      s = format (s, "lb vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "lb vip[%d]: %U\n", t->vip_index, format_lb_vip,
                  &lbm->vips[t->vip_index]);
    }
  if (pool_is_free_index(lbm->ass, t->as_index))
    {
      s = format (s, "lb as[%d]: This AS was freed since capture\n");
    }
  else
    {
      s = format (s, "lb as[%d]: %U\n", t->as_index, format_lb_as,
                  &lbm->ass[t->as_index]);
    }
  s = format (s, "lb nat: rx_sw_if_index = %d, next_index = %d",
              t->rx_sw_if_index, t->next_index);

  return s;
}

lb_hash_t *
lb_get_sticky_table (u32 thread_index)
{
  lb_main_t *lbm = &lb_main;
  lb_hash_t *sticky_ht = lbm->per_cpu[thread_index].sticky_ht;
  //Check if size changed
  if (PREDICT_FALSE(
      sticky_ht && (lbm->per_cpu_sticky_buckets != lb_hash_nbuckets(sticky_ht))))
    {
      //Dereference everything in there
      lb_hash_bucket_t *b;
      u32 i;
      lb_hash_foreach_entry(sticky_ht, b, i)
        {
          vlib_refcount_add (&lbm->as_refcount, thread_index, b->value[i], -1);
          vlib_refcount_add (&lbm->as_refcount, thread_index, 0, 1);
        }

      lb_hash_free (sticky_ht);
      sticky_ht = NULL;
    }

  //Create if necessary
  if (PREDICT_FALSE(sticky_ht == NULL))
    {
      lbm->per_cpu[thread_index].sticky_ht = lb_hash_alloc (
          lbm->per_cpu_sticky_buckets, lbm->flow_timeout);
      sticky_ht = lbm->per_cpu[thread_index].sticky_ht;
      clib_warning("Regenerated sticky table %p", sticky_ht);
    }

  ASSERT(sticky_ht);

  //Update timeout
  sticky_ht->timeout = lbm->flow_timeout;
  return sticky_ht;
}

u64
lb_node_get_other_ports4 (ip4_header_t *ip40)
{
  return 0;
}

u64
lb_node_get_other_ports6 (ip6_header_t *ip60)
{
  return 0;
}

static_always_inline void
lb_node_get_hash (lb_main_t *lbm, vlib_buffer_t *p, u8 is_input_v4,
                  u32 *hash, u32 *vip_idx, u8 per_port_vip)
{
  vip_port_key_t key;
  clib_bihash_kv_8_8_t kv, value;

  /* For vip case, retrieve vip index for ip lookup */
  *vip_idx = vnet_buffer (p)->ip.adj_index;

  if (per_port_vip)
    {
      /* For per-port-vip case, ip lookup stores placeholder index */
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
        ports = ((u64) ((udp_header_t *) (ip40 + 1))->src_port << 16)
            | ((u64) ((udp_header_t *) (ip40 + 1))->dst_port);
      else
        ports = lb_node_get_other_ports4 (ip40);

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
        ports = ((u64) ((udp_header_t *) (ip60 + 1))->src_port << 16)
            | ((u64) ((udp_header_t *) (ip60 + 1))->dst_port);
      else
        ports = lb_node_get_other_ports6 (ip60);

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
      if (clib_bihash_search_8_8(&lbm->vip_index_per_port, &kv, &value) < 0)
        {
          /* return default vip */
          *vip_idx = 0;
          return;
        }
      *vip_idx = value.value;
    }
}

static_always_inline uword
lb_node_fn (vlib_main_t * vm,
            vlib_node_runtime_t * node,
            vlib_frame_t * frame,
            u8 is_input_v4, //Compile-time parameter stating that is input is v4 (or v6)
            lb_encap_type_t encap_type, //Compile-time parameter is GRE4/GRE6/L3DSR/NAT4/NAT6
            u8 per_port_vip) //Compile-time parameter stating that is per_port_vip or not
{
  lb_main_t *lbm = &lb_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 thread_index = vm->thread_index;
  u32 lb_time = lb_hash_time_now (vm);

  lb_hash_t *sticky_ht = lb_get_sticky_table (thread_index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 nexthash0 = 0;
  u32 next_vip_idx0 = ~0;
  if (PREDICT_TRUE(n_left_from > 0))
    {
      vlib_buffer_t *p0 = vlib_get_buffer (vm, from[0]);
      lb_node_get_hash (lbm, p0, is_input_v4, &nexthash0,
                        &next_vip_idx0, per_port_vip);
    }

  while (n_left_from > 0)
    {
      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 pi0;
          vlib_buffer_t *p0;
          lb_vip_t *vip0;
          u32 asindex0 = 0;
          u16 len0;
          u32 available_index0;
          u8 counter = 0;
          u32 hash0 = nexthash0;
          u32 vip_index0 = next_vip_idx0;
          u32 next0;

          if (PREDICT_TRUE(n_left_from > 1))
            {
              vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
              //Compute next hash and prefetch bucket
              lb_node_get_hash (lbm, p1, is_input_v4,
                                &nexthash0, &next_vip_idx0,
                                per_port_vip);
              lb_hash_prefetch_bucket (sticky_ht, nexthash0);
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

          vip0 = pool_elt_at_index(lbm->vips, vip_index0);

          if (is_input_v4)
            {
              ip4_header_t *ip40;
              ip40 = vlib_buffer_get_current (p0);
              len0 = clib_net_to_host_u16 (ip40->length);
            }
          else
            {
              ip6_header_t *ip60;
              ip60 = vlib_buffer_get_current (p0);
              len0 = clib_net_to_host_u16 (ip60->payload_length)
                  + sizeof(ip6_header_t);
            }

          lb_hash_get (sticky_ht, hash0,
                       vip_index0, lb_time,
                       &available_index0, &asindex0);

          if (PREDICT_TRUE(asindex0 != 0))
            {
              //Found an existing entry
              counter = LB_VIP_COUNTER_NEXT_PACKET;
            }
          else if (PREDICT_TRUE(available_index0 != ~0))
            {
              //There is an available slot for a new flow
              asindex0 =
                  vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index;
              counter = LB_VIP_COUNTER_FIRST_PACKET;
              counter = (asindex0 == 0) ? LB_VIP_COUNTER_NO_SERVER : counter;

              //TODO: There are race conditions with as0 and vip0 manipulation.
              //Configuration may be changed, vectors resized, etc...

              //Dereference previously used
              vlib_refcount_add (
                  &lbm->as_refcount, thread_index,
                  lb_hash_available_value (sticky_ht, hash0, available_index0),
                  -1);
              vlib_refcount_add (&lbm->as_refcount, thread_index, asindex0, 1);

              //Add sticky entry
              //Note that when there is no AS configured, an entry is configured anyway.
              //But no configured AS is not something that should happen
              lb_hash_put (sticky_ht, hash0, asindex0,
                           vip_index0,
                           available_index0, lb_time);
            }
          else
            {
              //Could not store new entry in the table
              asindex0 =
                  vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index;
              counter = LB_VIP_COUNTER_UNTRACKED_PACKET;
            }

          vlib_increment_simple_counter (
              &lbm->vip_counters[counter], thread_index,
              vip_index0,
              1);

          //Now let's encap
          if ((encap_type == LB_ENCAP_TYPE_GRE4)
              || (encap_type == LB_ENCAP_TYPE_GRE6))
            {
              gre_header_t *gre0;
              if (encap_type == LB_ENCAP_TYPE_GRE4) /* encap GRE4*/
                {
                  ip4_header_t *ip40;
                  vlib_buffer_advance (
                      p0, -sizeof(ip4_header_t) - sizeof(gre_header_t));
                  ip40 = vlib_buffer_get_current (p0);
                  gre0 = (gre_header_t *) (ip40 + 1);
                  ip40->src_address = lbm->ip4_src_address;
                  ip40->dst_address = lbm->ass[asindex0].address.ip4;
                  ip40->ip_version_and_header_length = 0x45;
                  ip40->ttl = 128;
                  ip40->fragment_id = 0;
                  ip40->flags_and_fragment_offset = 0;
                  ip40->length = clib_host_to_net_u16 (
                      len0 + sizeof(gre_header_t) + sizeof(ip4_header_t));
                  ip40->protocol = IP_PROTOCOL_GRE;
                  ip40->checksum = ip4_header_checksum (ip40);
                }
              else /* encap GRE6*/
                {
                  ip6_header_t *ip60;
                  vlib_buffer_advance (
                      p0, -sizeof(ip6_header_t) - sizeof(gre_header_t));
                  ip60 = vlib_buffer_get_current (p0);
                  gre0 = (gre_header_t *) (ip60 + 1);
                  ip60->dst_address = lbm->ass[asindex0].address.ip6;
                  ip60->src_address = lbm->ip6_src_address;
                  ip60->hop_limit = 128;
                  ip60->ip_version_traffic_class_and_flow_label =
                      clib_host_to_net_u32 (0x6 << 28);
                  ip60->payload_length = clib_host_to_net_u16 (
                      len0 + sizeof(gre_header_t));
                  ip60->protocol = IP_PROTOCOL_GRE;
                }

              gre0->flags_and_version = 0;
              gre0->protocol =
                  (is_input_v4) ?
                      clib_host_to_net_u16 (0x0800) :
                      clib_host_to_net_u16 (0x86DD);
            }
          else if (encap_type == LB_ENCAP_TYPE_L3DSR) /* encap L3DSR*/
            {
              ip4_header_t *ip40;
              ip_csum_t csum;
              u32 old_dst, new_dst;
              u8 old_tos, new_tos;

              ip40 = vlib_buffer_get_current (p0);
              old_dst = ip40->dst_address.as_u32;
              new_dst = lbm->ass[asindex0].address.ip4.as_u32;
              ip40->dst_address.as_u32 = lbm->ass[asindex0].address.ip4.as_u32;
              /* Get and rewrite DSCP bit */
              old_tos = ip40->tos;
              new_tos = (u8) ((vip0->encap_args.dscp & 0x3F) << 2);
              ip40->tos = (u8) ((vip0->encap_args.dscp & 0x3F) << 2);

              csum = ip40->checksum;
              csum = ip_csum_update (csum, old_tos, new_tos,
                                     ip4_header_t,
                                     tos /* changed member */);
              csum = ip_csum_update (csum, old_dst, new_dst,
                                     ip4_header_t,
                                     dst_address /* changed member */);
              ip40->checksum = ip_csum_fold (csum);

              /* Recomputing L4 checksum after dst-IP modifying */
              if (ip40->protocol == IP_PROTOCOL_TCP)
                {
                  tcp_header_t *th0;
                  th0 = ip4_next_header (ip40);
                  th0->checksum = 0;
                  th0->checksum = ip4_tcp_udp_compute_checksum (vm, p0, ip40);
                }
              else if (ip40->protocol == IP_PROTOCOL_UDP)
                {
                  udp_header_t *uh0;
                  uh0 = ip4_next_header (ip40);
                  uh0->checksum = 0;
                  uh0->checksum = ip4_tcp_udp_compute_checksum (vm, p0, ip40);
                }
            }
          else if ((encap_type == LB_ENCAP_TYPE_NAT4)
              || (encap_type == LB_ENCAP_TYPE_NAT6))
            {
              ip_csum_t csum;
              udp_header_t *uh;

              /* do NAT */
              if ((is_input_v4 == 1) && (encap_type == LB_ENCAP_TYPE_NAT4))
                {
                  /* NAT44 */
                  ip4_header_t *ip40;
                  u32 old_dst;
                  ip40 = vlib_buffer_get_current (p0);
                  uh = (udp_header_t *) (ip40 + 1);
                  old_dst = ip40->dst_address.as_u32;
                  ip40->dst_address = lbm->ass[asindex0].address.ip4;

                  csum = ip40->checksum;
                  csum = ip_csum_sub_even (csum, old_dst);
                  csum = ip_csum_add_even (
                      csum, lbm->ass[asindex0].address.ip4.as_u32);
                  ip40->checksum = ip_csum_fold (csum);

                  if (ip40->protocol == IP_PROTOCOL_UDP)
                    {
                      uh->dst_port = vip0->encap_args.target_port;
                      csum = uh->checksum;
                      csum = ip_csum_sub_even (csum, old_dst);
                      csum = ip_csum_add_even (
                          csum, lbm->ass[asindex0].address.ip4.as_u32);
                      uh->checksum = ip_csum_fold (csum);
                    }
                  else
                    {
                      asindex0 = 0;
                    }
                }
              else if ((is_input_v4 == 0) && (encap_type == LB_ENCAP_TYPE_NAT6))
                {
                  /* NAT66 */
                  ip6_header_t *ip60;
                  ip6_address_t old_dst;

                  ip60 = vlib_buffer_get_current (p0);
                  uh = (udp_header_t *) (ip60 + 1);

                  old_dst.as_u64[0] = ip60->dst_address.as_u64[0];
                  old_dst.as_u64[1] = ip60->dst_address.as_u64[1];
                  ip60->dst_address.as_u64[0] =
                      lbm->ass[asindex0].address.ip6.as_u64[0];
                  ip60->dst_address.as_u64[1] =
                      lbm->ass[asindex0].address.ip6.as_u64[1];

                  if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_UDP))
                    {
                      uh->dst_port = vip0->encap_args.target_port;
                      csum = uh->checksum;
                      csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
                      csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
                      csum = ip_csum_add_even (
                          csum, lbm->ass[asindex0].address.ip6.as_u64[0]);
                      csum = ip_csum_add_even (
                          csum, lbm->ass[asindex0].address.ip6.as_u64[1]);
                      uh->checksum = ip_csum_fold (csum);
                    }
                  else
                    {
                      asindex0 = 0;
                    }
                }
            }
          next0 = lbm->ass[asindex0].dpo.dpoi_next_node;
          //Note that this is going to error if asindex0 == 0
          vnet_buffer (p0)->ip.adj_index =
              lbm->ass[asindex0].dpo.dpoi_index;

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lb_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof(*tr));
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

u8 *
format_nodeport_lb_trace (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  CLIB_UNUSED(vlib_main_t * vm)
= va_arg (*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node)
  = va_arg (*args, vlib_node_t *);
  lb_nodeport_trace_t *t = va_arg (*args, lb_nodeport_trace_t *);
  if (pool_is_free_index(lbm->vips, t->vip_index))
    {
      s = format (s, "lb vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "lb vip[%d]: %U\n", t->vip_index, format_lb_vip,
                  &lbm->vips[t->vip_index]);
    }

  s = format (s, "  lb node_port: %d", t->node_port);

  return s;
}

static uword
lb_nodeport_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                     vlib_frame_t * frame, u8 is_input_v4)
{
  lb_main_t *lbm = &lb_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 pi0;
          vlib_buffer_t *p0;
          udp_header_t * udp_0;
          uword * entry0;

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

          pi0 = to_next[0] = from[0];
          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          p0 = vlib_get_buffer (vm, pi0);

          if (is_input_v4)
            {
              ip4_header_t *ip40;
              vlib_buffer_advance (
                  p0, -(word) (sizeof(udp_header_t) + sizeof(ip4_header_t)));
              ip40 = vlib_buffer_get_current (p0);
              udp_0 = (udp_header_t *) (ip40 + 1);
            }
          else
            {
              ip6_header_t *ip60;
              vlib_buffer_advance (
                  p0, -(word) (sizeof(udp_header_t) + sizeof(ip6_header_t)));
              ip60 = vlib_buffer_get_current (p0);
              udp_0 = (udp_header_t *) (ip60 + 1);
            }

          entry0 = hash_get_mem(lbm->vip_index_by_nodeport, &(udp_0->dst_port));

          //Enqueue to next
          vnet_buffer(p0)->ip.adj_index = entry0 ? entry0[0]
              : ADJ_INDEX_INVALID;

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lb_nodeport_trace_t *tr = vlib_add_trace (vm, node, p0,
                                                        sizeof(*tr));
              tr->vip_index = entry0 ? entry0[0] : ADJ_INDEX_INVALID;
              tr->node_port = (u32) clib_net_to_host_u16 (udp_0->dst_port);
            }

          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
              n_left_to_next, pi0,
              is_input_v4 ?
                  LB4_NODEPORT_NEXT_IP4_NAT4 : LB6_NODEPORT_NEXT_IP6_NAT6);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;

}

/**
 * @brief Match NAT44 static mapping.
 *
 * @param sm          NAT main.
 * @param match       Address and port to match.
 * @param index       index to the pool.
 *
 * @returns 0 if match found, otherwise -1.
 */
int
lb_nat44_mapping_match (lb_main_t *lbm, lb_snat4_key_t * match, u32 *index)
{
  clib_bihash_kv_8_8_t kv4, value;
  clib_bihash_8_8_t *mapping_hash = &lbm->mapping_by_as4;

  kv4.key = match->as_u64;
  kv4.value = 0;
  if (clib_bihash_search_8_8 (mapping_hash, &kv4, &value))
    {
      return 1;
    }

  *index = value.value;
  return 0;
}

/**
 * @brief Match NAT66 static mapping.
 *
 * @param sm          NAT main.
 * @param match       Address and port to match.
 * @param mapping     External or local address and port of the matched mapping.
 *
 * @returns 0 if match found otherwise 1.
 */
int
lb_nat66_mapping_match (lb_main_t *lbm, lb_snat6_key_t * match, u32 *index)
{
  clib_bihash_kv_24_8_t kv6, value;
  lb_snat6_key_t m_key6;
  clib_bihash_24_8_t *mapping_hash = &lbm->mapping_by_as6;

  m_key6.addr.as_u64[0] = match->addr.as_u64[0];
  m_key6.addr.as_u64[1] = match->addr.as_u64[1];
  m_key6.port = match->port;
  m_key6.protocol = 0;
  m_key6.fib_index = 0;

  kv6.key[0] = m_key6.as_u64[0];
  kv6.key[1] = m_key6.as_u64[1];
  kv6.key[2] = m_key6.as_u64[2];
  kv6.value = 0;
  if (clib_bihash_search_24_8 (mapping_hash, &kv6, &value))
    {
      return 1;
    }

  *index = value.value;
  return 0;
}

static uword
lb_nat_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame, u32 is_nat4)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_processed = 0;
  lb_main_t *lbm = &lb_main;
  u32 stats_node_index;

  stats_node_index =
      is_nat4 ? lb_nat4_in2out_node.index : lb_nat6_in2out_node.index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

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

          u32 proto0;
          u32 rx_fib_index0;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          next0 = LB_NAT4_IN2OUT_NEXT_LOOKUP;
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (
              sw_if_index0);

          if (is_nat4)
            {
              ip4_header_t * ip40;
              u32 old_addr0, new_addr0;
              lb_snat4_key_t key40;
              lb_snat_mapping_t *sm40;
              u32 index40;

              ip40 = vlib_buffer_get_current (b0);
              udp0 = ip4_next_header (ip40);
              tcp0 = (tcp_header_t *) udp0;
              proto0 = lb_ip_proto_to_nat_proto (ip40->protocol);

              key40.addr = ip40->src_address;
              key40.protocol = proto0;
              key40.port = udp0->src_port;
              key40.fib_index = rx_fib_index0;

              if (lb_nat44_mapping_match (lbm, &key40, &index40))
                {
                  next0 = LB_NAT4_IN2OUT_NEXT_DROP;
                  goto trace0;
                }

              sm40 = pool_elt_at_index(lbm->snat_mappings, index40);
              new_addr0 = sm40->src_ip.ip4.as_u32;
              new_port0 = sm40->src_port;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm40->fib_index;
              old_addr0 = ip40->src_address.as_u32;
              ip40->src_address.as_u32 = new_addr0;

              csum = ip40->checksum;
              csum = ip_csum_sub_even (csum, old_addr0);
              csum = ip_csum_add_even (csum, new_addr0);
              ip40->checksum = ip_csum_fold (csum);

              if (PREDICT_TRUE(proto0 == LB_NAT_PROTOCOL_TCP))
                {
                  old_port0 = tcp0->src_port;
                  tcp0->src_port = new_port0;

                  csum = tcp0->checksum;
                  csum = ip_csum_sub_even (csum, old_addr0);
                  csum = ip_csum_sub_even (csum, old_port0);
                  csum = ip_csum_add_even (csum, new_addr0);
                  csum = ip_csum_add_even (csum, new_port0);
                  tcp0->checksum = ip_csum_fold (csum);
                }
              else if (PREDICT_TRUE(proto0 == LB_NAT_PROTOCOL_UDP))
                {
                  old_port0 = udp0->src_port;
                  udp0->src_port = new_port0;

                  csum = udp0->checksum;
                  csum = ip_csum_sub_even (csum, old_addr0);
                  csum = ip_csum_sub_even (csum, old_port0);
                  csum = ip_csum_add_even (csum, new_addr0);
                  csum = ip_csum_add_even (csum, new_port0);
                  udp0->checksum = ip_csum_fold (csum);
                }

              pkts_processed += next0 != LB_NAT4_IN2OUT_NEXT_DROP;
            }
          else
            {
              ip6_header_t * ip60;
              ip6_address_t old_addr0, new_addr0;
              lb_snat6_key_t key60;
              lb_snat_mapping_t *sm60;
              u32 index60;

              ip60 = vlib_buffer_get_current (b0);
              udp0 = ip6_next_header (ip60);
              tcp0 = (tcp_header_t *) udp0;
              proto0 = lb_ip_proto_to_nat_proto (ip60->protocol);

              key60.addr.as_u64[0] = ip60->src_address.as_u64[0];
              key60.addr.as_u64[1] = ip60->src_address.as_u64[1];
              key60.protocol = proto0;
              key60.port = udp0->src_port;
              key60.fib_index = rx_fib_index0;

              if (lb_nat66_mapping_match (lbm, &key60, &index60))
                {
                  next0 = LB_NAT6_IN2OUT_NEXT_DROP;
                  goto trace0;
                }

              sm60 = pool_elt_at_index(lbm->snat_mappings, index60);
              new_addr0.as_u64[0] = sm60->src_ip.as_u64[0];
              new_addr0.as_u64[1] = sm60->src_ip.as_u64[1];
              new_port0 = sm60->src_port;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm60->fib_index;
              old_addr0.as_u64[0] = ip60->src_address.as_u64[0];
              old_addr0.as_u64[1] = ip60->src_address.as_u64[1];
              ip60->src_address.as_u64[0] = new_addr0.as_u64[0];
              ip60->src_address.as_u64[1] = new_addr0.as_u64[1];

              if (PREDICT_TRUE(proto0 == LB_NAT_PROTOCOL_TCP))
                {
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
              else if (PREDICT_TRUE(proto0 == LB_NAT_PROTOCOL_UDP))
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

              pkts_processed += next0 != LB_NAT4_IN2OUT_NEXT_DROP;
            }

          trace0: if (PREDICT_FALSE(
              (node->flags & VLIB_NODE_FLAG_TRACE) && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lb_nat_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
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
                               LB_NAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
lb6_gre6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE6, 0);
}

static uword
lb6_gre4_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE4, 0);
}

static uword
lb4_gre6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE6, 0);
}

static uword
lb4_gre4_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE4, 0);
}

static uword
lb6_gre6_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE6, 1);
}

static uword
lb6_gre4_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE4, 1);
}

static uword
lb4_gre6_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE6, 1);
}

static uword
lb4_gre4_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE4, 1);
}

static uword
lb4_l3dsr_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_L3DSR, 0);
}

static uword
lb4_l3dsr_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_L3DSR, 1);
}

static uword
lb6_nat6_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_NAT6, 1);
}

static uword
lb4_nat4_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_NAT4, 1);
}

static uword
lb_nat4_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_nat_in2out_node_fn (vm, node, frame, 1);
}

static uword
lb_nat6_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_nat_in2out_node_fn (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (lb6_gre6_node) =
  {
    .function = lb6_gre6_node_fn,
    .name = "lb6-gre6",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_gre4_node) =
  {
    .function = lb6_gre4_node_fn,
    .name = "lb6-gre4",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre6_node) =
  {
    .function = lb4_gre6_node_fn,
    .name = "lb4-gre6",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre4_node) =
  {
    .function = lb4_gre4_node_fn,
    .name = "lb4-gre4",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_gre6_port_node) =
  {
    .function = lb6_gre6_port_node_fn,
    .name = "lb6-gre6-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_gre4_port_node) =
  {
    .function = lb6_gre4_port_node_fn,
    .name = "lb6-gre4-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre6_port_node) =
  {
    .function = lb4_gre6_port_node_fn,
    .name = "lb4-gre6-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre4_port_node) =
  {
    .function = lb4_gre4_port_node_fn,
    .name = "lb4-gre4-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_l3dsr_port_node) =
  {
    .function = lb4_l3dsr_port_node_fn,
    .name = "lb4-l3dsr-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_l3dsr_node) =
  {
    .function = lb4_l3dsr_node_fn,
    .name = "lb4-l3dsr",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_nat6_port_node) =
  {
    .function = lb6_nat6_port_node_fn,
    .name = "lb6-nat6-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_nat4_port_node) =
  {
    .function = lb4_nat4_port_node_fn,
    .name = "lb4-nat4-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

static uword
lb4_nodeport_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return lb_nodeport_node_fn (vm, node, frame, 1);
}

static uword
lb6_nodeport_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return lb_nodeport_node_fn (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (lb4_nodeport_node) =
  {
    .function = lb4_nodeport_node_fn,
    .name = "lb4-nodeport",
    .vector_size = sizeof(u32),
    .format_trace = format_nodeport_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB4_NODEPORT_N_NEXT,
    .next_nodes =
        {
            [LB4_NODEPORT_NEXT_IP4_NAT4] = "lb4-nat4-port",
            [LB4_NODEPORT_NEXT_DROP] = "error-drop",
        },
  };

VLIB_REGISTER_NODE (lb6_nodeport_node) =
  {
    .function = lb6_nodeport_node_fn,
    .name = "lb6-nodeport",
    .vector_size = sizeof(u32),
    .format_trace = format_nodeport_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB6_NODEPORT_N_NEXT,
    .next_nodes =
      {
          [LB6_NODEPORT_NEXT_IP6_NAT6] = "lb6-nat6-port",
          [LB6_NODEPORT_NEXT_DROP] = "error-drop",
      },
  };

VNET_FEATURE_INIT (lb_nat4_in2out_node_fn, static) =
  {
    .arc_name = "ip4-unicast",
    .node_name = "lb-nat4-in2out",
    .runs_before =  VNET_FEATURES("ip4-lookup"),
  };

VLIB_REGISTER_NODE (lb_nat4_in2out_node) =
  {
    .function = lb_nat4_in2out_node_fn,
    .name = "lb-nat4-in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_nat_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_NAT4_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [LB_NAT4_IN2OUT_NEXT_DROP] = "error-drop",
          [LB_NAT4_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
      },
  };

VNET_FEATURE_INIT (lb_nat6_in2out_node_fn, static) =
  {
    .arc_name = "ip6-unicast",
    .node_name = "lb-nat6-in2out",
    .runs_before = VNET_FEATURES("ip6-lookup"),
  };

VLIB_REGISTER_NODE (lb_nat6_in2out_node) =
  {
    .function = lb_nat6_in2out_node_fn,
    .name = "lb-nat6-in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_nat_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_NAT6_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [LB_NAT6_IN2OUT_NEXT_DROP] = "error-drop",
          [LB_NAT6_IN2OUT_NEXT_LOOKUP] = "ip6-lookup",
      },
  };
