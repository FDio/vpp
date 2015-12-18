/*
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} ip4_hop_by_hop_main_t;

ip4_hop_by_hop_main_t ip4_hop_by_hop_main;

vlib_node_registration_t ip4_hop_by_hop_node;

typedef struct {
  u32 next_index;
} ip4_hop_by_hop_trace_t;

/* packet trace format function */
static u8 * format_ip4_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_hop_by_hop_trace_t * t = va_arg (*args, ip4_hop_by_hop_trace_t *);
  
  s = format (s, "IP4_HOP_BY_HOP: next index %d",
              t->next_index);
  return s;
}

vlib_node_registration_t ip4_hop_by_hop_node;

#define foreach_ip4_hop_by_hop_error \
_(PROCESSED, "Pkts with ip4 hop-by-hop options")

typedef enum {
#define _(sym,str) IP4_HOP_BY_HOP_ERROR_##sym,
  foreach_ip4_hop_by_hop_error
#undef _
  IP4_HOP_BY_HOP_N_ERROR,
} ip4_hop_by_hop_error_t;

static char * ip4_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_hop_by_hop_error
#undef _
};

static uword
ip4_hop_by_hop_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 n_left_from, * from, * to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0 = IP4_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
          u32 next1 = IP4_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0, sw_if_index1;
          u8 tmp0[6], tmp1[6];
          ethernet_header_t *en0, *en1;
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;
            
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

          /* $$$$$ Dual loop: process 2 x packets here $$$$$ */
          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);
          
          ip0 = vlib_buffer_get_current (b0);
          ip1 = vlib_buffer_get_current (b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          /* $$$$$ End of processing 2 x packets $$$$$ */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    ip4_hop_by_hop_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    ip4_hop_by_hop_trace_t *t = 
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
	  vlib_buffer_t * b0;
          u32 next0;
          u32 adj_index0;
          ip_adjacency_t * adj0;
          
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
          adj0 = ip_get_adjacency (lm, adj_index0);

          /* $$$$$$$$$$$$ process one (or more) hop-by-hop header(s) here */
          
          
          /* $$$$$$$$$$$$ */

          /* Send the packet e.g. to ip4_rewrite */
          next0 = adj0->lookup_next_index;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              ip4_hop_by_hop_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->next_index = next0;
            }
            
          processed++;

          /* $$$$$ Done processing 1 packet here $$$$$ */

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ip4_hop_by_hop_node.index, 
                               IP4_HOP_BY_HOP_ERROR_PROCESSED, processed);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip4_hop_by_hop_node) = {
  .function = ip4_hop_by_hop_node_fn,
  .name = "ip4-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ip4_hop_by_hop_error_strings),
  .error_strings = ip4_hop_by_hop_error_strings,

  /* See ip/lookup.h */
  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = {
    [IP_LOOKUP_NEXT_MISS] = "ip4-miss",
    [IP_LOOKUP_NEXT_DROP] = "ip4-drop",
    [IP_LOOKUP_NEXT_PUNT] = "ip4-punt",
    [IP_LOOKUP_NEXT_LOCAL] = "ip4-local",
    [IP_LOOKUP_NEXT_ARP] = "ip4-arp",
    [IP_LOOKUP_NEXT_REWRITE] = "ip4-rewrite-transit",
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip4-classify",
    [IP_LOOKUP_NEXT_MAP] = "ip4-map",
    [IP_LOOKUP_NEXT_MAP_T] = "ip4-map-t",
    [IP_LOOKUP_NEXT_SIXRD] = "ip4-sixrd",
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip4-hop-by-hop", /* probably not */
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip4-add-hop-by-hop", 
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip4-pop-hop-by-hop", 
  },
};

VLIB_REGISTER_NODE (ip4_add_hop_by_hop_node) = {
  .function = ip4_hop_by_hop_node_fn,
  .name = "ip4-add-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ip4_hop_by_hop_error_strings),
  .error_strings = ip4_hop_by_hop_error_strings,

  /* See ip/lookup.h */
  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = {
    [IP_LOOKUP_NEXT_MISS] = "ip4-miss",
    [IP_LOOKUP_NEXT_DROP] = "ip4-drop",
    [IP_LOOKUP_NEXT_PUNT] = "ip4-punt",
    [IP_LOOKUP_NEXT_LOCAL] = "ip4-local",
    [IP_LOOKUP_NEXT_ARP] = "ip4-arp",
    [IP_LOOKUP_NEXT_REWRITE] = "ip4-rewrite-transit",
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip4-classify",
    [IP_LOOKUP_NEXT_MAP] = "ip4-map",
    [IP_LOOKUP_NEXT_MAP_T] = "ip4-map-t",
    [IP_LOOKUP_NEXT_SIXRD] = "ip4-sixrd",
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip4-hop-by-hop", /* probably not */
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip4-add-hop-by-hop", 
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip4-pop-hop-by-hop", 
  },
};

VLIB_REGISTER_NODE (ip4_pop_hop_by_hop_node) = {
  .function = ip4_hop_by_hop_node_fn,
  .name = "ip4-pop-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ip4_hop_by_hop_error_strings),
  .error_strings = ip4_hop_by_hop_error_strings,

  /* See ip/lookup.h */
  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = {
    [IP_LOOKUP_NEXT_MISS] = "ip4-miss",
    [IP_LOOKUP_NEXT_DROP] = "ip4-drop",
    [IP_LOOKUP_NEXT_PUNT] = "ip4-punt",
    [IP_LOOKUP_NEXT_LOCAL] = "ip4-local",
    [IP_LOOKUP_NEXT_ARP] = "ip4-arp",
    [IP_LOOKUP_NEXT_REWRITE] = "ip4-rewrite-transit",
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip4-classify",
    [IP_LOOKUP_NEXT_MAP] = "ip4-map",
    [IP_LOOKUP_NEXT_MAP_T] = "ip4-map-t",
    [IP_LOOKUP_NEXT_SIXRD] = "ip4-sixrd",
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip4-hop-by-hop", /* probably not */
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip4-add-hop-by-hop", 
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip4-pop-hop-by-hop", 
  },
};

static clib_error_t *
ip4_hop_by_hop_init (vlib_main_t * vm)
{
  ip4_hop_by_hop_main_t * hm = &ip4_hop_by_hop_main;

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (ip4_hop_by_hop_init);
