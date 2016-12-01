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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <ioam/ipfixcollector/ipfixcollector.h>
#include <vnet/flow/ipfix_packet.h>

#define foreach_ipfix_collector_error \
_(PROCESSED, "Number of IP-Fix packets processed") \
_(NO_LISTENER, "Number of IP-Fix packets with no listener")

typedef enum
{
#define _(sym,str) IPFIX_COLLECTOR_ERROR_##sym,
  foreach_ipfix_collector_error
#undef _
    IPFIX_COLLECTOR_N_ERROR,
} flowperpkt_error_t;

static char *ipfix_collector_error_strings[] = {
#define _(sym,string) string,
  foreach_ipfix_collector_error
#undef _
};

typedef enum
{
  IPFIX_COLLECTOR_NEXT_DROP,
  IPFIX_COLLECTOR_N_NEXT,
} ipfix_collector_next_t;

typedef struct
{
  u32 next_node;
  u16 set_id;
  u16 pad;
} ipfix_collector_trace_t;

vlib_node_registration_t ipfix_collector_node;

/* packet trace format function */
static u8 *
format_ipfix_collector_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipfix_collector_trace_t *t = va_arg (*args, ipfix_collector_trace_t *);

  s = format (s,
	      "IPFIX_COLLECTOR: set_id %u, next_node %u", t->set_id,
	      t->next_node);
  return s;
}

/**
 * @brief Node to receive IP-Fix packets.
 * @node ipfix-collector
 *
 * This function receives IP-FIX packets and forwards them to other graph nodes
 * based on SetID field in IP-FIX.
 *
 * @param vm    vlib_main_t corresponding to the current thread.
 * @param node  vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer, next index usage
 *
 * <em>Uses:</em>
 * - <code>vlib_buffer_get_current(p0)</code>
 *     - Parses IP-Fix packet to extract SetId which will be used to decide
 *       next node where packets should be enqueued.
 *
 * <em>Next Index:</em>
 * - Dispatches the packet to other VPP graph nodes based on their registartion
 *   for the IP-Fix SetId using API ipfix_collector_reg_setid().
 */
uword
ipfix_collector_node_fn (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  word n_no_listener = 0;
  word n_listener = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  ipfix_message_header_t *ipfix0, *ipfix1;
	  ipfix_set_header_t *set0, *set1;
	  u16 set_id0, set_id1;
	  ipfix_client *client0, *client1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data,
			   (sizeof (ipfix_message_header_t) +
			    sizeof (ipfix_set_header_t)), LOAD);
	    CLIB_PREFETCH (p3->data,
			   (sizeof (ipfix_message_header_t) +
			    sizeof (ipfix_set_header_t)), LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  ipfix0 = vlib_buffer_get_current (b0);
	  ipfix1 = vlib_buffer_get_current (b1);

	  set0 = (ipfix_set_header_t *) (ipfix0 + 1);
	  set1 = (ipfix_set_header_t *) (ipfix1 + 1);

	  set_id0 = (u16) (clib_net_to_host_u32 (set0->set_id_length) >> 16);
	  set_id1 = (u16) (clib_net_to_host_u32 (set1->set_id_length) >> 16);

	  client0 = ipfix_collector_get_client (set_id0);
	  client1 = ipfix_collector_get_client (set_id1);

	  if (PREDICT_TRUE (NULL != client0))
	    {
	      next0 = client0->client_next_node;
	      n_listener++;
	    }
	  else
	    {
	      next0 = IPFIX_COLLECTOR_NEXT_DROP;
	      n_no_listener++;
	    }

	  if (PREDICT_TRUE (NULL != client1))
	    {
	      next1 = client1->client_next_node;
	      n_listener++;
	    }
	  else
	    {
	      next1 = IPFIX_COLLECTOR_NEXT_DROP;
	      n_no_listener++;
	    }

	  vlib_buffer_advance (b0,
			       (sizeof (ipfix_message_header_t)
				+ sizeof (ipfix_set_header_t)));
	  vlib_buffer_advance (b1,
			       (sizeof (ipfix_message_header_t)
				+ sizeof (ipfix_set_header_t)));

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipfix_collector_trace_t *tr = vlib_add_trace (vm, node,
							    b0, sizeof (*tr));
	      tr->next_node = (client0 ? client0->client_node : 0xFFFFFFFF);
	      tr->set_id = set_id0;
	    }
	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipfix_collector_trace_t *tr = vlib_add_trace (vm, node,
							    b1, sizeof (*tr));
	      tr->next_node = (client1 ? client1->client_node : 0xFFFFFFFF);
	      tr->set_id = set_id1;
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ipfix_message_header_t *ipfix0;
	  ipfix_set_header_t *set0;
	  u16 set_id0;
	  ipfix_client *client0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ipfix0 = vlib_buffer_get_current (b0);

	  set0 = (ipfix_set_header_t *) (ipfix0 + 1);

	  set_id0 = (u16) (clib_net_to_host_u32 (set0->set_id_length) >> 16);

	  client0 = ipfix_collector_get_client (set_id0);

	  if (PREDICT_TRUE (NULL != client0))
	    {
	      next0 = client0->client_next_node;
	      n_listener++;
	    }
	  else
	    {
	      next0 = IPFIX_COLLECTOR_NEXT_DROP;
	      n_no_listener++;
	    }

	  vlib_buffer_advance (b0,
			       (sizeof (ipfix_message_header_t)
				+ sizeof (ipfix_set_header_t)));
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipfix_collector_trace_t *tr = vlib_add_trace (vm, node,
							    b0, sizeof (*tr));
	      tr->next_node = (client0 ? client0->client_node : 0xFFFFFFFF);
	      tr->set_id = set_id0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_error_count (vm, node->node_index,
		    IPFIX_COLLECTOR_ERROR_NO_LISTENER, n_no_listener);
  vlib_error_count (vm, node->node_index,
		    IPFIX_COLLECTOR_ERROR_PROCESSED, n_listener);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipfix_collector_node) = {
  .function = ipfix_collector_node_fn,
  .name = "ipfix-collector",
  .vector_size = sizeof (u32),
  .format_trace = format_ipfix_collector_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipfix_collector_error_strings),
  .error_strings = ipfix_collector_error_strings,

  .n_next_nodes = IPFIX_COLLECTOR_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [IPFIX_COLLECTOR_NEXT_DROP] = "error-drop",
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
