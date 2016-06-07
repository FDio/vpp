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

#ifndef included_vnet_handoff_h
#define included_vnet_handoff_h

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/mpls-gre/packet.h>

typedef enum {
  HANDOFF_DISPATCH_NEXT_IP4_INPUT,
  HANDOFF_DISPATCH_NEXT_IP6_INPUT,
  HANDOFF_DISPATCH_NEXT_MPLS_INPUT,
  HANDOFF_DISPATCH_NEXT_ETHERNET_INPUT,
  HANDOFF_DISPATCH_NEXT_DROP,
  HANDOFF_DISPATCH_N_NEXT,
} handoff_dispatch_next_t;

static inline
void vlib_put_handoff_queue_elt (vlib_frame_queue_elt_t * hf)
{
  CLIB_MEMORY_BARRIER();
  hf->valid = 1;
}

static inline vlib_frame_queue_elt_t *
vlib_get_handoff_queue_elt (u32 vlib_worker_index)
{
  vlib_frame_queue_t *fq;
  vlib_frame_queue_elt_t *elt;
  u64 new_tail;

  fq = vlib_frame_queues[vlib_worker_index];
  ASSERT (fq);

  new_tail = __sync_add_and_fetch (&fq->tail, 1);

  /* Wait until a ring slot is available */
  while (new_tail >= fq->head_hint + fq->nelts)
      vlib_worker_thread_barrier_check ();

  elt = fq->elts + (new_tail & (fq->nelts-1));

  /* this would be very bad... */
  while (elt->valid)
    ;

  elt->msg_type = VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME;
  elt->last_n_vectors = elt->n_vectors = 0;

  return elt;
}

static inline vlib_frame_queue_t *
is_vlib_handoff_queue_congested (
    u32 vlib_worker_index,
    u32 queue_hi_thresh,
    vlib_frame_queue_t ** handoff_queue_by_worker_index)
{
  vlib_frame_queue_t *fq;

  fq = handoff_queue_by_worker_index [vlib_worker_index];
  if (fq != (vlib_frame_queue_t *)(~0))
      return fq;

  fq = vlib_frame_queues[vlib_worker_index];
  ASSERT (fq);

  if (PREDICT_FALSE(fq->tail >= (fq->head_hint + queue_hi_thresh))) {
    /* a valid entry in the array will indicate the queue has reached
     * the specified threshold and is congested
     */
    handoff_queue_by_worker_index [vlib_worker_index] = fq;
    fq->enqueue_full_events++;
    return fq;
  }

  return NULL;
}

static inline vlib_frame_queue_elt_t *
dpdk_get_handoff_queue_elt (u32 vlib_worker_index,
			    vlib_frame_queue_elt_t **
			      handoff_queue_elt_by_worker_index)
{
  vlib_frame_queue_elt_t *elt;

  if (handoff_queue_elt_by_worker_index [vlib_worker_index])
      return handoff_queue_elt_by_worker_index [vlib_worker_index];

  elt = vlib_get_handoff_queue_elt (vlib_worker_index);

  handoff_queue_elt_by_worker_index [vlib_worker_index] = elt;

  return elt;
}

static inline u64 ipv4_get_key (ip4_header_t *ip)
{
   u64  hash_key;

   hash_key = *((u64*)(&ip->address_pair)) ^ ip->protocol;

   return hash_key;
}

static inline u64 ipv6_get_key (ip6_header_t *ip)
{
   u64  hash_key;

   hash_key = ip->src_address.as_u64[0] ^
              rotate_left(ip->src_address.as_u64[1],13) ^
              rotate_left(ip->dst_address.as_u64[0],26) ^
              rotate_left(ip->dst_address.as_u64[1],39) ^
              ip->protocol;

   return hash_key;
}

#define MPLS_BOTTOM_OF_STACK_BIT_MASK   0x00000100U
#define MPLS_LABEL_MASK                 0xFFFFF000U

static inline u64 mpls_get_key (mpls_unicast_header_t *m)
{
   u64                     hash_key;
   u8                      ip_ver;


   /* find the bottom of the MPLS label stack. */
   if (PREDICT_TRUE(m->label_exp_s_ttl &
                    clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK))) {
       goto bottom_lbl_found;
   }
   m++;

   if (PREDICT_TRUE(m->label_exp_s_ttl &
                    clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK))) {
       goto bottom_lbl_found;
   }
   m++;

   if (m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK)) {
       goto bottom_lbl_found;
   }
   m++;

   if (m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK)) {
       goto bottom_lbl_found;
   }
   m++;

   if (m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK)) {
       goto bottom_lbl_found;
   }

   /* the bottom label was not found - use the last label */
   hash_key = m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_LABEL_MASK);

   return hash_key;

bottom_lbl_found:
   m++;
   ip_ver = (*((u8 *)m) >> 4);

   /* find out if it is IPV4 or IPV6 header */
   if (PREDICT_TRUE(ip_ver == 4)) {
       hash_key = ipv4_get_key((ip4_header_t *)m);
   } else if (PREDICT_TRUE(ip_ver == 6)) {
       hash_key = ipv6_get_key((ip6_header_t *)m);
   } else {
       /* use the bottom label */
       hash_key = (m-1)->label_exp_s_ttl & clib_net_to_host_u32(MPLS_LABEL_MASK);
   }

   return hash_key;

}


static inline u64
eth_get_key (ethernet_header_t *h0)
{
   u64 hash_key;

   if (PREDICT_TRUE(h0->type) == clib_host_to_net_u16(ETHERNET_TYPE_IP4)) {
       hash_key = ipv4_get_key((ip4_header_t *)(h0+1));
   } else if (h0->type == clib_host_to_net_u16(ETHERNET_TYPE_IP6)) {
       hash_key = ipv6_get_key((ip6_header_t *)(h0+1));
   } else if (h0->type == clib_host_to_net_u16(ETHERNET_TYPE_MPLS_UNICAST)) {
       hash_key = mpls_get_key((mpls_unicast_header_t *)(h0+1));
   } else if ((h0->type == clib_host_to_net_u16(ETHERNET_TYPE_VLAN)) ||
              (h0->type == clib_host_to_net_u16(ETHERNET_TYPE_DOT1AD))) {
       ethernet_vlan_header_t * outer = (ethernet_vlan_header_t *)(h0 + 1);

       outer = (outer->type == clib_host_to_net_u16(ETHERNET_TYPE_VLAN)) ?
                                  outer+1 : outer;
       if (PREDICT_TRUE(outer->type) == clib_host_to_net_u16(ETHERNET_TYPE_IP4)) {
           hash_key = ipv4_get_key((ip4_header_t *)(outer+1));
       } else if (outer->type == clib_host_to_net_u16 (ETHERNET_TYPE_IP6)) {
           hash_key = ipv6_get_key((ip6_header_t *)(outer+1));
       } else if (outer->type == clib_host_to_net_u16(ETHERNET_TYPE_MPLS_UNICAST)) {
           hash_key = mpls_get_key((mpls_unicast_header_t *)(outer+1));
       }  else {
           hash_key = outer->type;
       }
   } else {
       hash_key  = 0;
   }

   return hash_key;
}

#endif /* included_vnet_handoff_h */
