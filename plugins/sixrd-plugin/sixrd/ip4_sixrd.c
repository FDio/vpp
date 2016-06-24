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
#include "sixrd.h"

static vlib_node_registration_t ip4_sixrd_node;

typedef enum {
  IP4_SIXRD_NEXT_IP6_LOOKUP,
  IP4_SIXRD_NEXT_DROP,
  IP4_SIXRD_N_NEXT,
} ip4_sixrd_next_t;

/*
 * ip4_sixrd_sec_check
 */
static_always_inline void
ip4_sixrd_sec_check (sixrd_domain_t *d, ip4_address_t sa4, ip6_address_t sa6, u8 *error)
{
  u32 a = sixrd_get_addr(d, sa6.as_u64[0]);
  clib_warning("Security check: %U %U", format_ip4_address, &a, format_ip4_address, &sa4);
  if (PREDICT_FALSE(sixrd_get_addr(d, sa6.as_u64[0]) != sa4.as_u32))
    *error = SIXRD_ERROR_SEC_CHECK;
}

/*
 * ip4_sixrd
 */
static uword
ip4_sixrd (vlib_main_t *vm,
	   vlib_node_runtime_t *node,
	   vlib_frame_t *frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node = vlib_node_get_runtime(vm, ip4_sixrd_node.index);
  u32 decap = 0;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0) {
    vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

    /* Single loop */
    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 pi0;
      vlib_buffer_t *p0;
      u8 error0 = SIXRD_ERROR_NONE;
      sixrd_domain_t *d0 = 0;
      ip4_header_t *ip40;
      ip6_header_t *ip60;
      u32 sixrd_domain_index0 = ~0;
      u32 next0;

      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next +=1;
      n_left_to_next -= 1;

      p0 = vlib_get_buffer(vm, pi0);
      ip40 = vlib_buffer_get_current(p0);

      /* Throw away anything that isn't IP in IP. */
      if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_IPV6 && clib_net_to_host_u16(ip40->length) >= 60)) {
	vlib_buffer_advance(p0, sizeof(ip4_header_t));
	ip60 = vlib_buffer_get_current(p0);
	d0 = ip4_sixrd_get_domain(vnet_buffer(p0)->ip.adj_index[VLIB_TX], (ip6_address_t *)&ip60->src_address,
				&sixrd_domain_index0, &error0);
      } else {
	error0 = SIXRD_ERROR_BAD_PROTOCOL;
      }
      if (d0) {
	/* SIXRD inbound security check */
	ip4_sixrd_sec_check(d0, ip40->src_address, ip60->src_address, &error0);
      }

      next0 = error0 == SIXRD_ERROR_NONE ? IP4_SIXRD_NEXT_IP6_LOOKUP : IP4_SIXRD_NEXT_DROP;

      if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED)) {
	sixrd_trace_t *tr = vlib_add_trace(vm, node, p0, sizeof(*tr));
	tr->sixrd_domain_index = sixrd_domain_index0;
      }

      p0->error = error_node->errors[error0];
      if (PREDICT_TRUE(error0 == SIXRD_ERROR_NONE)) decap++;
      vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next, n_left_to_next, pi0, next0);

    }
    vlib_put_next_frame(vm, node, next_index, n_left_to_next);
  }
  vlib_node_increment_counter(vm, ip4_sixrd_node.index, SIXRD_ERROR_DECAPSULATED, decap);

  return frame->n_vectors;
}

static char *sixrd_error_strings[] = {
#define _(sym,string) string,
  foreach_sixrd_error
#undef _
};

VLIB_REGISTER_NODE(ip4_sixrd_node,static) = {
  .function = ip4_sixrd,
  .name = "ip4-sixrd",
  .vector_size = sizeof(u32),
  .format_trace = format_sixrd_trace,
  .n_errors = SIXRD_N_ERROR,
  .error_strings = sixrd_error_strings,
  .n_next_nodes = IP4_SIXRD_N_NEXT,
  .next_nodes = {
    [IP4_SIXRD_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP4_SIXRD_NEXT_DROP] = "error-drop",
  },
};
