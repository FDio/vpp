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

#include <vnet/dns/dns.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

vlib_node_registration_t dns46_reply_node;

typedef struct
{
  u32 pool_index;
  u32 disposition;
} dns46_reply_trace_t;

/* packet trace format function */
static u8 *
format_dns46_reply_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dns46_reply_trace_t *t = va_arg (*args, dns46_reply_trace_t *);

  s = format (s, "DNS46_REPLY: pool index %d, disposition  %d",
	      t->pool_index, t->disposition);
  return s;
}

vlib_node_registration_t dns46_reply_node;

static char *dns46_reply_error_strings[] = {
#define _(sym,string) string,
  foreach_dns46_reply_error
#undef _
};

typedef enum
{
  DNS46_REPLY_NEXT_DROP,
  DNS46_REPLY_N_NEXT,
} dns46_reply_next_t;

static uword
dns46_reply_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  dns46_reply_next_t next_index;

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
	  u32 next0 = DNS46_REPLY_NEXT_INTERFACE_OUTPUT;
	  u32 next1 = DNS46_REPLY_NEXT_INTERFACE_OUTPUT;
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
		  dns46_reply_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  dns46_reply_trace_t *t =
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
	  u32 next0 = DNS46_REPLY_NEXT_DROP;
	  dns_header_t *d0;
	  u32 pool_index0;
	  u32 error0;
	  u8 *resp0 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;

	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  d0 = vlib_buffer_get_current (b0);

	  pool_index0 = clib_host_to_net_u16 (d0->id);

	  /* Save the reply */
	  vec_validate (resp0, vlib_buffer_length_in_chain (vm, b0) - 1);
	  clib_memcpy (resp0, d0, vlib_buffer_length_in_chain (vm, b0));

	  /*
	   * Deal with everything in process ctx on the main thread
	   */
	  vlib_process_signal_event_mt (vm, dns_resolver_node.index,
					DNS_RESOLVER_EVENT_RESOLVED,
					(uword) resp0);
	  error0 = DNS46_REPLY_ERROR_PROCESSED;

	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      dns46_reply_trace_t *t =
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dns46_reply_node) =
{
  .function = dns46_reply_node_fn,
  .name = "dns46_reply",
  .vector_size = sizeof (u32),
  .format_trace = format_dns46_reply_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dns46_reply_error_strings),
  .error_strings = dns46_reply_error_strings,
  .n_next_nodes = DNS46_REPLY_N_NEXT,
  .next_nodes = {
    [DNS46_REPLY_NEXT_DROP] = "error-drop",
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
