/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <dns/dns.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

vlib_node_registration_t dns46_request_node;

typedef struct
{
  u32 pool_index;
  u32 disposition;
} dns46_request_trace_t;

/* packet trace format function */
static u8 *
format_dns46_request_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dns46_request_trace_t *t = va_arg (*args, dns46_request_trace_t *);

  s = format (s, "DNS46_REPLY: pool index %d, disposition  %d",
	      t->pool_index, t->disposition);
  return s;
}

vlib_node_registration_t dns46_request_node;

static char *dns46_request_error_strings[] = {
#define _(sym,string) string,
  foreach_dns46_request_error
#undef _
};

typedef enum
{
  DNS46_REQUEST_NEXT_DROP,
  DNS46_REQUEST_NEXT_IP_LOOKUP,
  DNS46_REQUEST_NEXT_PUNT,
  DNS46_REQUEST_N_NEXT,
} dns46_request_next_t;

static uword
dns46_request_inline (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame,
		      int is_ip6)
{
  u32 n_left_from, *from, *to_next;
  dns46_request_next_t next_index;
  dns_main_t *dm = &dns_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = DNS46_REQUEST_NEXT_INTERFACE_OUTPUT;
	  u32 next1 = DNS46_REQUEST_NEXT_INTERFACE_OUTPUT;
	  u32 sw_if_index0, sw_if_index1;
	  u8 tmp0[6], tmp1[6];
	  ethernet_header_t *en0, *en1;
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* $$$$$ End of processing 2 x packets $$$$$ */

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  dns46_request_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  dns46_request_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
#endif

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = DNS46_REQUEST_NEXT_DROP;
	  u32 error0 = DNS46_REQUEST_ERROR_NONE;
	  udp_header_t *u0;
	  dns_header_t *d0;
	  dns_query_t *q0;
	  ip4_header_t *ip40 = 0;
	  ip6_header_t *ip60 = 0;
	  dns_cache_entry_t *ep0;
	  dns_pending_request_t _t0, *t0 = &_t0;
	  u16 flags0;
	  u32 pool_index0 = ~0;
	  u8 *name0;
	  u8 *label0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  d0 = vlib_buffer_get_current (b0);
	  u0 = (udp_header_t *) ((u8 *) d0 - sizeof (*u0));

	  if (PREDICT_FALSE (dm->is_enabled == 0))
	    {
	      next0 = DNS46_REQUEST_NEXT_PUNT;
	      goto done0;
	    }

	  if (is_ip6)
	    {
	      ip60 = (ip6_header_t *) (((u8 *) u0) - sizeof (ip6_header_t));
	      next0 = DNS46_REQUEST_NEXT_DROP;
	      error0 = DNS46_REQUEST_ERROR_UNIMPLEMENTED;
	      goto done0;
	    }
	  else
	    {
	      ip40 = (ip4_header_t *) (((u8 *) u0) - sizeof (ip4_header_t));
	      if (ip40->ip_version_and_header_length != 0x45)
		{
		  error0 = DNS46_REQUEST_ERROR_IP_OPTIONS;
		  goto done0;
		}
	    }
	  /* Parse through the DNS request */
	  flags0 = clib_net_to_host_u16 (d0->flags);

	  /* Requests only */
	  if (flags0 & DNS_QR)
	    {
	      next0 = DNS46_REQUEST_NEXT_DROP;
	      error0 = DNS46_REQUEST_ERROR_BAD_REQUEST;
	      goto done0;
	    }
	  if (clib_net_to_host_u16 (d0->qdcount) != 1)
	    {
	      next0 = DNS46_REQUEST_NEXT_DROP;
	      error0 = DNS46_REQUEST_ERROR_TOO_MANY_REQUESTS;
	      goto done0;
	    }

	  label0 = (u8 *) (d0 + 1);

	  /*
	   * vnet_dns_labels_to_name produces a non NULL terminated vector
	   * vnet_dns_resolve_name expects a C-string.
	   */
	  name0 = vnet_dns_labels_to_name (label0, (u8 *) d0, (u8 **) & q0);
	  vec_add1 (name0, 0);
	  _vec_len (name0) -= 1;

	  t0->request_type = DNS_PEER_PENDING_NAME_TO_IP;

	  /*
	   * See if this is a reverse lookup. Both ip4 and ip6 reverse
	   * requests end with ".arpa"
	   */
	  if (PREDICT_TRUE (vec_len (name0) > 5))
	    {
	      u8 *aptr0 = name0 + vec_len (name0) - 5;

	      if (!memcmp (aptr0, ".arpa", 5))
		t0->request_type = DNS_PEER_PENDING_IP_TO_NAME;
	    }

	  t0->client_index = ~0;
	  t0->is_ip6 = is_ip6;
	  t0->dst_port = u0->src_port;
	  t0->id = d0->id;
	  t0->name = name0;
	  if (is_ip6)
	    clib_memcpy_fast (t0->dst_address, ip60->src_address.as_u8,
			      sizeof (ip6_address_t));
	  else
	    clib_memcpy_fast (t0->dst_address, ip40->src_address.as_u8,
			      sizeof (ip4_address_t));

	  vnet_dns_resolve_name (vm, dm, name0, t0, &ep0);

	  if (ep0)
	    {
	      if (is_ip6)
		vnet_send_dns6_reply (vm, dm, t0, ep0, b0);
	      else
		vnet_send_dns4_reply (vm, dm, t0, ep0, b0);
	      next0 = DNS46_REQUEST_NEXT_IP_LOOKUP;
	    }
	  else
	    {
	      error0 = DNS46_REQUEST_ERROR_RESOLUTION_REQUIRED;
	    }

	done0:
	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      dns46_request_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->disposition = error0;
	      t->pool_index = pool_index0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
dns4_request_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  return dns46_request_inline (vm, node, frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dns4_request_node) =
{
  .function = dns4_request_node_fn,
  .name = "dns4-request",
  .vector_size = sizeof (u32),
  .format_trace = format_dns46_request_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dns46_request_error_strings),
  .error_strings = dns46_request_error_strings,
  .n_next_nodes = DNS46_REQUEST_N_NEXT,
  .next_nodes = {
    [DNS46_REQUEST_NEXT_DROP] = "error-drop",
    [DNS46_REQUEST_NEXT_PUNT] = "error-punt",
    [DNS46_REQUEST_NEXT_IP_LOOKUP] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

static uword
dns6_request_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  return dns46_request_inline (vm, node, frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dns6_request_node) =
{
  .function = dns6_request_node_fn,
  .name = "dns6-request",
  .vector_size = sizeof (u32),
  .format_trace = format_dns46_request_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dns46_request_error_strings),
  .error_strings = dns46_request_error_strings,
  .n_next_nodes = DNS46_REQUEST_N_NEXT,
  .next_nodes = {
    [DNS46_REQUEST_NEXT_DROP] = "error-drop",
    [DNS46_REQUEST_NEXT_PUNT] = "error-punt",
    [DNS46_REQUEST_NEXT_IP_LOOKUP] = "ip6-lookup",
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
