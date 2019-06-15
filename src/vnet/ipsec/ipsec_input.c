/*
 * decap.c : IPSec tunnel decapsulation
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>
#include <vnet/ipsec/ipsec_io.h>

#define foreach_ipsec_input_error               \
_(RX_PKTS, "IPSEC pkts received")		\
_(RX_MATCH_PKTS, "IPSEC pkts matched")

typedef enum
{
#define _(sym,str) IPSEC_INPUT_ERROR_##sym,
  foreach_ipsec_input_error
#undef _
    IPSEC_INPUT_N_ERROR,
} ipsec_input_error_t;

static char *ipsec_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_input_error
#undef _
};

typedef struct
{
  ip_protocol_t proto;
  u32 spd;
  u32 policy_index;
  u32 sa_id;
  u32 spi;
  u32 seq;
} ipsec_input_trace_t;

/* packet trace format function */
static u8 *
format_ipsec_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_input_trace_t *t = va_arg (*args, ipsec_input_trace_t *);

  s = format (s, "%U: sa_id %u spd %u policy %d spi %u seq %u",
	      format_ip_protocol, t->proto, t->sa_id,
	      t->spd, t->policy_index, t->spi, t->seq);

  return s;
}

always_inline ipsec_policy_t *
ipsec_input_protect_policy_match (ipsec_spd_t * spd, u32 sa, u32 da, u32 spi)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_sa_t *s;
  u32 *i;

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT])
  {
    p = pool_elt_at_index (im->policies, *i);
    s = pool_elt_at_index (im->sad, p->sa_index);

    if (spi != s->spi)
      continue;

    if (ipsec_sa_is_set_IS_TUNNEL (s))
      {
	if (da != s->tunnel_dst_addr.ip4.as_u32)
	  continue;

	if (sa != s->tunnel_src_addr.ip4.as_u32)
	  continue;

	return p;
      }

    if (da < p->laddr.start.ip4.as_u32)
      continue;

    if (da > p->laddr.stop.ip4.as_u32)
      continue;

    if (sa < p->raddr.start.ip4.as_u32)
      continue;

    if (sa > p->raddr.stop.ip4.as_u32)
      continue;

    return p;
  }
  return 0;
}

always_inline uword
ip6_addr_match_range (ip6_address_t * a, ip6_address_t * la,
		      ip6_address_t * ua)
{
  if ((memcmp (a->as_u64, la->as_u64, 2 * sizeof (u64)) >= 0) &&
      (memcmp (a->as_u64, ua->as_u64, 2 * sizeof (u64)) <= 0))
    return 1;
  return 0;
}

always_inline ipsec_policy_t *
ipsec6_input_protect_policy_match (ipsec_spd_t * spd,
				   ip6_address_t * sa,
				   ip6_address_t * da, u32 spi)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_sa_t *s;
  u32 *i;

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT])
  {
    p = pool_elt_at_index (im->policies, *i);
    s = pool_elt_at_index (im->sad, p->sa_index);

    if (spi != s->spi)
      continue;

    if (ipsec_sa_is_set_IS_TUNNEL (s))
      {
	if (!ip6_address_is_equal (sa, &s->tunnel_src_addr.ip6))
	  continue;

	if (!ip6_address_is_equal (da, &s->tunnel_dst_addr.ip6))
	  continue;

	return p;
      }

    if (!ip6_addr_match_range (sa, &p->raddr.start.ip6, &p->raddr.stop.ip6))
      continue;

    if (!ip6_addr_match_range (da, &p->laddr.start.ip6, &p->laddr.stop.ip6))
      continue;

    return p;
  }
  return 0;
}

static vlib_node_registration_t ipsec4_input_node;

VLIB_NODE_FN (ipsec4_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next, thread_index;
  ipsec_main_t *im = &ipsec_main;
  u32 ipsec_unprocessed = 0;
  u32 ipsec_matched = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  thread_index = vm->thread_index;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, pi0;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0;
	  esp_header_t *esp0;
	  ah_header_t *ah0;
	  ip4_ipsec_config_t *c0;
	  ipsec_spd_t *spd0;
	  ipsec_policy_t *p0 = 0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  b0->flags |= VNET_BUFFER_F_IS_IP4;
	  b0->flags &= ~VNET_BUFFER_F_IS_IP6;
	  c0 = vnet_feature_next_with_data (&next0, b0, sizeof (c0[0]));

	  spd0 = pool_elt_at_index (im->spds, c0->spd_index);

	  ip0 = vlib_buffer_get_current (b0);

	  if (PREDICT_TRUE
	      (ip0->protocol == IP_PROTOCOL_IPSEC_ESP
	       || ip0->protocol == IP_PROTOCOL_UDP))
	    {
#if 0
	      clib_warning
		("packet received from %U to %U spi %u size %u spd_id %u",
		 format_ip4_address, ip0->src_address.as_u8,
		 format_ip4_address, ip0->dst_address.as_u8,
		 clib_net_to_host_u32 (esp0->spi),
		 clib_net_to_host_u16 (ip0->length), spd0->id);
#endif

	      esp0 = (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	      if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_UDP))
		{
		  esp0 =
		    (esp_header_t *) ((u8 *) esp0 + sizeof (udp_header_t));
		}
	      /* FIXME TODO missing check whether there is enough data inside
	       * IP/UDP to contain ESP header & stuff ? */
	      p0 = ipsec_input_protect_policy_match (spd0,
						     ip0->src_address.as_u32,
						     ip0->dst_address.as_u32,
						     clib_net_to_host_u32
						     (esp0->spi));

	      if (PREDICT_TRUE (p0 != NULL))
		{
		  ipsec_matched += 1;

		  pi0 = p0 - im->policies;
		  vlib_increment_combined_counter
		    (&ipsec_spd_policy_counters,
		     thread_index, pi0, 1,
		     clib_net_to_host_u16 (ip0->length));

		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  next0 = im->esp4_decrypt_next_index;
		  vlib_buffer_advance (b0, ((u8 *) esp0 - (u8 *) ip0));
		  goto trace0;
		}
	      else
		{
		  pi0 = ~0;
		};

	      /* FIXME bypass and discard */
	    trace0:
	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ipsec_input_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));

		  tr->proto = ip0->protocol;
		  if (p0)
		    tr->sa_id = p0->sa_id;
		  tr->spi = clib_net_to_host_u32 (esp0->spi);
		  tr->seq = clib_net_to_host_u32 (esp0->seq);
		  tr->spd = spd0->id;
		  tr->policy_index = pi0;
		}
	    }
	  else if (ip0->protocol == IP_PROTOCOL_IPSEC_AH)
	    {
	      ah0 = (ah_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	      p0 = ipsec_input_protect_policy_match (spd0,
						     ip0->src_address.as_u32,
						     ip0->dst_address.as_u32,
						     clib_net_to_host_u32
						     (ah0->spi));

	      if (PREDICT_TRUE (p0 != 0))
		{
		  ipsec_matched += 1;

		  pi0 = p0 - im->policies;
		  vlib_increment_combined_counter
		    (&ipsec_spd_policy_counters,
		     thread_index, pi0, 1,
		     clib_net_to_host_u16 (ip0->length));

		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  next0 = im->ah4_decrypt_next_index;
		  goto trace1;
		}
	      else
		{
		  pi0 = ~0;
		}
	      /* FIXME bypass and discard */
	    trace1:
	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ipsec_input_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));

		  tr->proto = ip0->protocol;
		  if (p0)
		    tr->sa_id = p0->sa_id;
		  tr->spi = clib_net_to_host_u32 (ah0->spi);
		  tr->seq = clib_net_to_host_u32 (ah0->seq_no);
		  tr->spd = spd0->id;
		  tr->policy_index = pi0;
		}
	    }
	  else
	    {
	      ipsec_unprocessed += 1;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_PKTS,
			       from_frame->n_vectors - ipsec_unprocessed);

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_MATCH_PKTS,
			       ipsec_matched);
  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec4_input_node,static) = {
  .name = "ipsec4-input-feature",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_input_error_strings),
  .error_strings = ipsec_input_error_strings,
  .n_next_nodes = IPSEC_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IPSEC_INPUT_NEXT_##s] = n,
    foreach_ipsec_input_next
#undef _
  },
};
/* *INDENT-ON* */

static vlib_node_registration_t ipsec6_input_node;


VLIB_NODE_FN (ipsec6_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next, thread_index;
  ipsec_main_t *im = &ipsec_main;
  u32 ipsec_unprocessed = 0;
  u32 ipsec_matched = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  thread_index = vm->thread_index;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, pi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0;
	  esp_header_t *esp0;
	  ip4_ipsec_config_t *c0;
	  ipsec_spd_t *spd0;
	  ipsec_policy_t *p0 = 0;
	  ah_header_t *ah0;
	  u32 header_size = sizeof (ip0[0]);

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  b0->flags |= VNET_BUFFER_F_IS_IP6;
	  b0->flags &= ~VNET_BUFFER_F_IS_IP4;
	  c0 = vnet_feature_next_with_data (&next0, b0, sizeof (c0[0]));

	  spd0 = pool_elt_at_index (im->spds, c0->spd_index);

	  ip0 = vlib_buffer_get_current (b0);
	  esp0 = (esp_header_t *) ((u8 *) ip0 + header_size);
	  ah0 = (ah_header_t *) ((u8 *) ip0 + header_size);

	  if (PREDICT_TRUE (ip0->protocol == IP_PROTOCOL_IPSEC_ESP))
	    {
#if 0
	      clib_warning
		("packet received from %U to %U spi %u size %u spd_id %u",
		 format_ip6_address, &ip0->src_address, format_ip6_address,
		 &ip0->dst_address, clib_net_to_host_u32 (esp0->spi),
		 clib_net_to_host_u16 (ip0->payload_length) + header_size,
		 spd0->id);
#endif
	      p0 = ipsec6_input_protect_policy_match (spd0,
						      &ip0->src_address,
						      &ip0->dst_address,
						      clib_net_to_host_u32
						      (esp0->spi));

	      if (PREDICT_TRUE (p0 != 0))
		{
		  ipsec_matched += 1;

		  pi0 = p0 - im->policies;
		  vlib_increment_combined_counter
		    (&ipsec_spd_policy_counters,
		     thread_index, pi0, 1,
		     clib_net_to_host_u16 (ip0->payload_length) +
		     header_size);

		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  next0 = im->esp6_decrypt_next_index;
		  vlib_buffer_advance (b0, header_size);
		  goto trace0;
		}
	      else
		{
		  pi0 = ~0;
		}
	    }
	  else if (ip0->protocol == IP_PROTOCOL_IPSEC_AH)
	    {
	      p0 = ipsec6_input_protect_policy_match (spd0,
						      &ip0->src_address,
						      &ip0->dst_address,
						      clib_net_to_host_u32
						      (ah0->spi));

	      if (PREDICT_TRUE (p0 != 0))
		{
		  ipsec_matched += 1;
		  pi0 = p0 - im->policies;
		  vlib_increment_combined_counter
		    (&ipsec_spd_policy_counters,
		     thread_index, pi0, 1,
		     clib_net_to_host_u16 (ip0->payload_length) +
		     header_size);

		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  next0 = im->ah6_decrypt_next_index;
		  goto trace0;
		}
	      else
		{
		  pi0 = ~0;
		}
	    }
	  else
	    {
	      ipsec_unprocessed += 1;
	    }

	trace0:
	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));

	      if (p0)
		tr->sa_id = p0->sa_id;
	      tr->proto = ip0->protocol;
	      tr->spi = clib_net_to_host_u32 (esp0->spi);
	      tr->seq = clib_net_to_host_u32 (esp0->seq);
	      tr->spd = spd0->id;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ipsec6_input_node.index,
			       IPSEC_INPUT_ERROR_RX_PKTS,
			       from_frame->n_vectors - ipsec_unprocessed);

  vlib_node_increment_counter (vm, ipsec6_input_node.index,
			       IPSEC_INPUT_ERROR_RX_MATCH_PKTS,
			       ipsec_matched);

  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec6_input_node,static) = {
  .name = "ipsec6-input-feature",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_input_error_strings),
  .error_strings = ipsec_input_error_strings,
  .n_next_nodes = IPSEC_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IPSEC_INPUT_NEXT_##s] = n,
    foreach_ipsec_input_next
#undef _
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
