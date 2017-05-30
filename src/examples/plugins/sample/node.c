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
#include <sample/sample.h>

typedef struct {
  u32 next_index;
  u32 sw_if_index;
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} sample_trace_t;

static u8 *
format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* packet trace format function */
static u8 * format_sample_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sample_trace_t * t = va_arg (*args, sample_trace_t *);
  
  s = format (s, "SAMPLE: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);
  s = format (s, "  new src %U -> new dst %U",
              format_mac_address, t->new_src_mac, 
              format_mac_address, t->new_dst_mac);

  return s;
}

vlib_node_registration_t sample_node;

#define foreach_sample_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum {
#define _(sym,str) SAMPLE_ERROR_##sym,
  foreach_sample_error
#undef _
  SAMPLE_N_ERROR,
} sample_error_t;

static char * sample_error_strings[] = {
#define _(sym,string) string,
  foreach_sample_error
#undef _
};

typedef enum {
  SAMPLE_NEXT_INTERFACE_OUTPUT,
  SAMPLE_N_NEXT,
} sample_next_t;

#define foreach_mac_address_offset              \
_(0)                                            \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)

static uword
sample_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  sample_next_t next_index;
  u32 pkts_swapped = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0 = SAMPLE_NEXT_INTERFACE_OUTPUT;
          u32 next1 = SAMPLE_NEXT_INTERFACE_OUTPUT;
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

          ASSERT (b0->current_data == 0);
          ASSERT (b1->current_data == 0);
          
          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1);

          /* This is not the fastest way to swap src + dst mac addresses */
#define _(a) tmp0[a] = en0->src_address[a];
          foreach_mac_address_offset;
#undef _
#define _(a) en0->src_address[a] = en0->dst_address[a];
          foreach_mac_address_offset;
#undef _
#define _(a) en0->dst_address[a] = tmp0[a];
          foreach_mac_address_offset;
#undef _

#define _(a) tmp1[a] = en1->src_address[a];
          foreach_mac_address_offset;
#undef _
#define _(a) en1->src_address[a] = en1->dst_address[a];
          foreach_mac_address_offset;
#undef _
#define _(a) en1->dst_address[a] = tmp1[a];
          foreach_mac_address_offset;
#undef _



          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sw_if_index1;

          pkts_swapped += 2;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    sample_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                    clib_memcpy (t->new_src_mac, en0->src_address,
                                 sizeof (t->new_src_mac));
                    clib_memcpy (t->new_dst_mac, en0->dst_address,
                                 sizeof (t->new_dst_mac));
                    
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    sample_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->next_index = next1;
                    clib_memcpy (t->new_src_mac, en1->src_address,
                                 sizeof (t->new_src_mac));
                    clib_memcpy (t->new_dst_mac, en1->dst_address,
                                 sizeof (t->new_dst_mac));
                  }
              }
            
            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0 = SAMPLE_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0;
          u8 tmp0[6];
          ethernet_header_t *en0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          /* 
           * Direct from the driver, we should be at offset 0
           * aka at &b0->data[0]
           */
          ASSERT (b0->current_data == 0);
          
          en0 = vlib_buffer_get_current (b0);

          /* This is not the fastest way to swap src + dst mac addresses */
#define _(a) tmp0[a] = en0->src_address[a];
          foreach_mac_address_offset;
#undef _
#define _(a) en0->src_address[a] = en0->dst_address[a];
          foreach_mac_address_offset;
#undef _
#define _(a) en0->dst_address[a] = tmp0[a];
          foreach_mac_address_offset;
#undef _

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          /* Send pkt back out the RX interface */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            sample_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->sw_if_index = sw_if_index0;
            t->next_index = next0;
            clib_memcpy (t->new_src_mac, en0->src_address,
                         sizeof (t->new_src_mac));
            clib_memcpy (t->new_dst_mac, en0->dst_address,
                         sizeof (t->new_dst_mac));
            }
            
          pkts_swapped += 1;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sample_node.index, 
                               SAMPLE_ERROR_SWAPPED, pkts_swapped);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sample_node) = {
  .function = sample_node_fn,
  .name = "sample",
  .vector_size = sizeof (u32),
  .format_trace = format_sample_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(sample_error_strings),
  .error_strings = sample_error_strings,

  .n_next_nodes = SAMPLE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [SAMPLE_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};
