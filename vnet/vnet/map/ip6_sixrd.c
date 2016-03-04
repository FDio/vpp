/*---------------------------------------------------------------------------
 * Copyright (c) 2009-2014 Cisco and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */
/*
 * Defines used for testing various optimisation schemes
 */
#define SIXRD_ENCAP_DUAL 0

#include "sixrd.h"

static vlib_node_registration_t ip6_sixrd_node;

typedef enum {
  IP6_SIXRD_NEXT_IP4_LOOKUP,
  IP6_SIXRD_NEXT_DROP,
  IP6_SIXRD_N_NEXT,
} ip6_sixrd_next_t;

/*
 * ip6_sixrd
 */
static uword
ip6_sixrd (vlib_main_t *vm,
	   vlib_node_runtime_t *node,
	   vlib_frame_t *frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node = vlib_node_get_runtime(vm, ip6_sixrd_node.index);
  u32 encap = 0;
  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0) {
    vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 pi0;
      vlib_buffer_t *p0;
      sixrd_domain_t *d0;
      u8 error0 = SIXRD_ERROR_NONE;
      ip6_header_t *ip60;
      ip4_header_t *ip4h0;
      u32 next0 = IP6_SIXRD_NEXT_IP4_LOOKUP;
      u32 sixrd_domain_index0 = ~0;

      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next +=1;
      n_left_to_next -= 1;

      p0 = vlib_get_buffer(vm, pi0);
      ip60 = vlib_buffer_get_current(p0);
      //      p0->current_length = clib_net_to_host_u16(ip40->length);
      d0 = ip6_sixrd_get_domain(vnet_buffer(p0)->ip.adj_index[VLIB_TX], &sixrd_domain_index0);
      ASSERT(d0);

      /* SIXRD calc */
      u64 dal60 = clib_net_to_host_u64(ip60->dst_address.as_u64[0]);
      u32 da40 = sixrd_get_addr(d0, dal60);
      u16 len = clib_net_to_host_u16(ip60->payload_length) + 60;
      if (da40 == 0) error0 = SIXRD_ERROR_UNKNOWN;

      /* construct ipv4 header */
      vlib_buffer_advance(p0, - (sizeof(ip4_header_t)));
      ip4h0 = vlib_buffer_get_current(p0);
      vnet_buffer(p0)->sw_if_index[VLIB_TX] = (u32)~0;
      ip4h0->ip_version_and_header_length = 0x45;
      ip4h0->tos = 0;
      ip4h0->length = clib_host_to_net_u16(len);
      ip4h0->fragment_id = 0;
      ip4h0->flags_and_fragment_offset = 0;
      ip4h0->ttl = 0x40;
      ip4h0->protocol = IP_PROTOCOL_IPV6;
      ip4h0->src_address = d0->ip4_src;
      ip4h0->dst_address.as_u32 = clib_host_to_net_u32(da40);
      ip4h0->checksum = ip4_header_checksum(ip4h0);

      next0 = error0 == SIXRD_ERROR_NONE ? IP6_SIXRD_NEXT_IP4_LOOKUP : IP6_SIXRD_NEXT_DROP;

      if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED)) {
	sixrd_trace_t *tr = vlib_add_trace(vm, node, p0, sizeof(*tr));
	tr->sixrd_domain_index = sixrd_domain_index0;
      }

      p0->error = error_node->errors[error0];
      if (PREDICT_TRUE(error0 == SIXRD_ERROR_NONE)) encap++;

      vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next, n_left_to_next, pi0, next0);
    }
    vlib_put_next_frame(vm, node, next_index, n_left_to_next);  
  }
  vlib_node_increment_counter(vm, ip6_sixrd_node.index, SIXRD_ERROR_ENCAPSULATED, encap);

  return frame->n_vectors;
}

static char *sixrd_error_strings[] = {
#define _(sym,string) string,
  foreach_sixrd_error
#undef _
};

VLIB_REGISTER_NODE(ip6_sixrd_node,static) = {
  .function = ip6_sixrd,
  .name = "ip6-sixrd",
  .vector_size = sizeof(u32),
  .format_trace = format_sixrd_trace,
  .n_errors = SIXRD_N_ERROR,
  .error_strings = sixrd_error_strings,
  .n_next_nodes = IP6_SIXRD_N_NEXT,
  .next_nodes = {
    [IP6_SIXRD_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_SIXRD_NEXT_DROP] = "error-drop",
  },
};
