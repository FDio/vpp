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

#define foreach_ipsec_input_error                   \
 _(RX_PKTS, "IPSEC pkts received")                  \
 _(DECRYPTION_FAILED, "IPSEC decryption failed")

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

  if (t->spi == 0 && t->seq == 0)
    {
      s = format (s, "esp: no esp packet");
      return s;
    }

  if (t->sa_id != 0)
    {
      s = format (s, "esp: sa_id %u spi %u seq %u", t->sa_id, t->spi, t->seq);
    }
  else
    {
      s = format (s, "esp: no sa spi %u seq %u", t->spi, t->seq);
    }
  return s;
}

always_inline ipsec_policy_t *
ipsec_input_protect_policy_match (ipsec_spd_t * spd, u32 sa, u32 da, u32 spi)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_sa_t *s;
  u32 *i;

  vec_foreach (i, spd->ipv4_inbound_protect_policy_indices)
  {
    p = pool_elt_at_index (spd->policies, *i);
    s = pool_elt_at_index (im->sad, p->sa_index);

    if (spi != s->spi)
      continue;

    if (s->is_tunnel)
      {
	if (da != clib_net_to_host_u32 (s->tunnel_dst_addr.ip4.as_u32))
	  continue;

	if (sa != clib_net_to_host_u32 (s->tunnel_src_addr.ip4.as_u32))
	  continue;

	return p;
      }

    if (da < clib_net_to_host_u32 (p->laddr.start.ip4.as_u32))
      continue;

    if (da > clib_net_to_host_u32 (p->laddr.stop.ip4.as_u32))
      continue;

    if (sa < clib_net_to_host_u32 (p->raddr.start.ip4.as_u32))
      continue;

    if (sa > clib_net_to_host_u32 (p->raddr.stop.ip4.as_u32))
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
ipsec_input_ip6_protect_policy_match (ipsec_spd_t * spd,
				      ip6_address_t * sa,
				      ip6_address_t * da, u32 spi)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_sa_t *s;
  u32 *i;

  vec_foreach (i, spd->ipv6_inbound_protect_policy_indices)
  {
    p = pool_elt_at_index (spd->policies, *i);
    s = pool_elt_at_index (im->sad, p->sa_index);

    if (spi != s->spi)
      continue;

    if (s->is_tunnel)
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

static vlib_node_registration_t ipsec_input_ip4_node;

static uword
ipsec_input_ip4_node_fn (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0;
	  esp_header_t *esp0;
	  ip4_ipsec_config_t *c0;
	  ipsec_spd_t *spd0;
	  ipsec_policy_t *p0 = 0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  c0 =
	    vnet_feature_next_with_data (vnet_buffer (b0)->sw_if_index
					 [VLIB_RX], &next0, b0,
					 sizeof (c0[0]));

	  spd0 = pool_elt_at_index (im->spds, c0->spd_index);

	  ip0 = vlib_buffer_get_current (b0);
	  esp0 = (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));

	  if (PREDICT_TRUE (ip0->protocol == IP_PROTOCOL_IPSEC_ESP))
	    {
#if 0
	      clib_warning
		("packet received from %U to %U spi %u size %u spd_id %u",
		 format_ip4_address, ip0->src_address.as_u8,
		 format_ip4_address, ip0->dst_address.as_u8,
		 clib_net_to_host_u32 (esp0->spi),
		 clib_net_to_host_u16 (ip0->length), spd0->id);
#endif

	      p0 = ipsec_input_protect_policy_match (spd0,
						     clib_net_to_host_u32
						     (ip0->src_address.
						      as_u32),
						     clib_net_to_host_u32
						     (ip0->dst_address.
						      as_u32),
						     clib_net_to_host_u32
						     (esp0->spi));

	      if (PREDICT_TRUE (p0 != 0))
		{
		  p0->counter.packets++;
		  p0->counter.bytes += clib_net_to_host_u16 (ip0->length);
		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  vnet_buffer (b0)->ipsec.flags = 0;
		  next0 = im->esp_decrypt_next_index;
		  vlib_buffer_advance (b0, ip4_header_bytes (ip0));
		  goto trace0;
		}
	    }

	  /* FIXME bypass and discard */

	trace0:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      if (ip0->protocol == IP_PROTOCOL_IPSEC_ESP)
		{
		  if (p0)
		    tr->sa_id = p0->sa_id;
		  tr->spi = clib_host_to_net_u32 (esp0->spi);
		  tr->seq = clib_host_to_net_u32 (esp0->seq);
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, ipsec_input_ip4_node.index,
			       IPSEC_INPUT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec_input_ip4_node,static) = {
  .function = ipsec_input_ip4_node_fn,
  .name = "ipsec-input-ip4",
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

VLIB_NODE_FUNCTION_MULTIARCH (ipsec_input_ip4_node, ipsec_input_ip4_node_fn)
     static vlib_node_registration_t ipsec_input_ip6_node;

     static uword
       ipsec_input_ip6_node_fn (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0;
	  esp_header_t *esp0;
	  ip4_ipsec_config_t *c0;
	  ipsec_spd_t *spd0;
	  ipsec_policy_t *p0 = 0;
	  u32 header_size = sizeof (ip0[0]);

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  c0 =
	    vnet_feature_next_with_data (vnet_buffer (b0)->sw_if_index
					 [VLIB_RX], &next0, b0,
					 sizeof (c0[0]));

	  spd0 = pool_elt_at_index (im->spds, c0->spd_index);

	  ip0 = vlib_buffer_get_current (b0);
	  esp0 = (esp_header_t *) ((u8 *) ip0 + header_size);

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
	      p0 = ipsec_input_ip6_protect_policy_match (spd0,
							 &ip0->src_address,
							 &ip0->dst_address,
							 clib_net_to_host_u32
							 (esp0->spi));

	      if (PREDICT_TRUE (p0 != 0))
		{
		  p0->counter.packets++;
		  p0->counter.bytes +=
		    clib_net_to_host_u16 (ip0->payload_length);
		  p0->counter.bytes += header_size;
		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  vnet_buffer (b0)->ipsec.flags = 0;
		  next0 = im->esp_decrypt_next_index;
		  vlib_buffer_advance (b0, header_size);
		  goto trace0;
		}
	    }

	trace0:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      if (ip0->protocol == IP_PROTOCOL_IPSEC_ESP)
		{
		  if (p0)
		    tr->sa_id = p0->sa_id;
		  tr->spi = clib_host_to_net_u32 (esp0->spi);
		  tr->seq = clib_host_to_net_u32 (esp0->seq);
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, ipsec_input_ip6_node.index,
			       IPSEC_INPUT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec_input_ip6_node,static) = {
  .function = ipsec_input_ip6_node_fn,
  .name = "ipsec-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipsec_input_error_strings),
  .error_strings = ipsec_input_error_strings,

  .sibling_of = "ipsec-input-ip4",
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ipsec_input_ip6_node, ipsec_input_ip6_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
