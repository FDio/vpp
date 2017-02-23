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
#include <vppinfra/error.h>

#include <vnet/lawful-intercept/lawful_intercept.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t li_hit_node;

typedef struct {
  u32 next_index;
} li_hit_trace_t;

/* packet trace format function */
static u8 * format_li_hit_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  li_hit_trace_t * t = va_arg (*args, li_hit_trace_t *);
  
  s = format (s, "LI_HIT: next index %d", t->next_index);

  return s;
}

vlib_node_registration_t li_hit_node;

#define foreach_li_hit_error                                    \
_(HITS, "LI packets processed")                                 \
_(NO_COLLECTOR, "No collector configured")                      \
_(BUFFER_ALLOCATION_FAILURE, "Buffer allocation failure")

typedef enum {
#define _(sym,str) LI_HIT_ERROR_##sym,
  foreach_li_hit_error
#undef _
  LI_HIT_N_ERROR,
} li_hit_error_t;

static char * li_hit_error_strings[] = {
#define _(sym,string) string,
  foreach_li_hit_error
#undef _
};

typedef enum {
  LI_HIT_NEXT_ETHERNET,
  LI_HIT_N_NEXT,
} li_hit_next_t;

static uword
li_hit_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  li_hit_next_t next_index;
  vlib_frame_t * int_frame = 0;
  u32 * to_int_next = 0;
  li_main_t * lm = &li_main;
  
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (PREDICT_FALSE (vec_len (lm->collectors) == 0))
    {
      vlib_node_increment_counter (vm, li_hit_node.index, 
                                   LI_HIT_ERROR_NO_COLLECTOR, 
                                   n_left_from);
    }
  else
    {
      /* The intercept frame... */
      int_frame = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      to_int_next = vlib_frame_vector_args (int_frame);
    }
  
  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0 = LI_HIT_NEXT_INTERFACE_OUTPUT;
          u32 next1 = LI_HIT_NEXT_INTERFACE_OUTPUT;
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
          
          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sw_if_index1;

          /* $$$$$ End of processing 2 x packets $$$$$ */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    li_hit_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    li_hit_trace_t *t = 
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
#endif /* $$$ dual-loop off */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          vlib_buffer_t * c0;
          ip4_udp_header_t * iu0;
          ip4_header_t * ip0;
          udp_header_t * udp0;
          u32 next0 = LI_HIT_NEXT_ETHERNET;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          if (PREDICT_TRUE(to_int_next != 0))
            {
              /* Make an intercept copy. This can fail. */
              c0 = vlib_buffer_copy (vm, b0);

              if (PREDICT_FALSE (c0 == 0))
                {
                  vlib_node_increment_counter 
                    (vm, node->node_index, 
                     LI_HIT_ERROR_BUFFER_ALLOCATION_FAILURE, 1);
                  goto skip;
                }
              
              vlib_buffer_advance(c0, -sizeof(*iu0));

              iu0 = vlib_buffer_get_current(c0);
              ip0 = &iu0->ip4;
              
              ip0->ip_version_and_header_length = 0x45;
              ip0->ttl = 254;
              ip0->protocol = IP_PROTOCOL_UDP;
              
              ip0->src_address.as_u32 = lm->src_addrs[0].as_u32;
              ip0->dst_address.as_u32 = lm->collectors[0].as_u32;
              ip0->length = vlib_buffer_length_in_chain (vm, c0);
              ip0->checksum = ip4_header_checksum (ip0);
              
              udp0 = &iu0->udp;
              udp0->src_port = udp0->dst_port = 
                  clib_host_to_net_u16(lm->ports[0]);
              udp0->checksum = 0;
              udp0->length = 
                  clib_net_to_host_u16 (vlib_buffer_length_in_chain (vm , b0));
              
              to_int_next [0] = vlib_get_buffer_index (vm, c0);
              to_int_next++;
            }

        skip:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              li_hit_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->next_index = next0;
            }
            
          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (int_frame)
    {
      int_frame->n_vectors = frame->n_vectors;
      vlib_put_frame_to_node (vm, ip4_lookup_node.index, int_frame);
    }

  vlib_node_increment_counter (vm, li_hit_node.index, 
                               LI_HIT_ERROR_HITS, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (li_hit_node) = {
  .function = li_hit_node_fn,
  .name = "li-hit",
  .vector_size = sizeof (u32),
  .format_trace = format_li_hit_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(li_hit_error_strings),
  .error_strings = li_hit_error_strings,

  .n_next_nodes = LI_HIT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [LI_HIT_NEXT_ETHERNET] = "ethernet-input-not-l2",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (li_hit_node, li_hit_node_fn)

