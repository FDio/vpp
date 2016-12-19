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
#include <vnet/mcast/mcast.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/ip4.h>

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 group_index;
} mcast_prep_trace_t;

/* packet trace format function */
static u8 * format_mcast_prep_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mcast_prep_trace_t * t = va_arg (*args, mcast_prep_trace_t *);
  
  s = format (s, "MCAST_PREP: group %d, next index %d, tx_sw_if_index %d",
              t->group_index, t->next_index, t->sw_if_index);
  return s;
}

mcast_main_t mcast_main;
vlib_node_registration_t mcast_prep_node;
vlib_node_registration_t mcast_recycle_node;

#define foreach_mcast_prep_error \
_(MCASTS, "Multicast Packets")

typedef enum {
#define _(sym,str) MCAST_PREP_ERROR_##sym,
  foreach_mcast_prep_error
#undef _
  MCAST_PREP_N_ERROR,
} mcast_prep_error_t;

static char * mcast_prep_error_strings[] = {
#define _(sym,string) string,
  foreach_mcast_prep_error
#undef _
};

typedef enum {
  MCAST_PREP_NEXT_DROP,
  MCAST_PREP_N_NEXT,
} mcast_prep_next_t;

static uword
mcast_prep_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  mcast_prep_next_t next_index;
  mcast_main_t * mcm = &mcast_main;
  vlib_node_t *n = vlib_get_node (vm, mcast_prep_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t * em = &vm->error_main;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (0 && n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          
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

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          next0 = 0;
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
          next1 = 0;

          /* $$$$ your message in this space. Process 2 x pkts */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    mcast_prep_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    mcast_prep_trace_t *t = 
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
      
      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0, adj_index0;
          mcast_group_t * g0;
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
          vnet_buffer(b0)->mcast.mcast_group_index = adj0->mcast_group_index;
          g0 = pool_elt_at_index (mcm->groups, adj0->mcast_group_index);

          /* 
           * Handle the degenerate single-copy case 
           * If we don't change the freelist, the packet will never
           * make it to the recycle node...
           */
          if (PREDICT_TRUE(vec_len (g0->members) > 1))
            {
              /* Save the original free list index */
              vnet_buffer(b0)->mcast.original_free_list_index =
                b0->free_list_index;
              
              /* Swap in the multicast recycle list */
              b0->free_list_index = mcm->mcast_recycle_list_index;
              
              /* 
               * Make sure that intermediate "frees" don't screw up 
               */
              b0->recycle_count = vec_len (g0->members);
              b0->flags |= VLIB_BUFFER_RECYCLE;

              /* Set up for the recycle node */
              vnet_buffer(b0)->mcast.mcast_current_index = 1;
            }

          /* Transmit the pkt on the first interface */
          next0 = g0->members[0].prep_and_recycle_node_next_index;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = 
            g0->members[0].tx_sw_if_index;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            mcast_prep_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->next_index = next0;
            t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_TX];
            t->group_index = vnet_buffer(b0)->mcast.mcast_group_index;
            }
            
          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  em->counters[node_counter_base_index + MCAST_PREP_ERROR_MCASTS] += 
      frame->n_vectors;

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (mcast_prep_node) = {
  .function = mcast_prep_node_fn,
  .name = "mcast_prep",
  .vector_size = sizeof (u32),
  .format_trace = format_mcast_prep_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(mcast_prep_error_strings),
  .error_strings = mcast_prep_error_strings,

  .n_next_nodes = MCAST_PREP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [MCAST_PREP_NEXT_DROP] = "error-drop",
  },
};

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 current_member;
  u32 group_index;
} mcast_recycle_trace_t;

static u8 * format_mcast_recycle_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mcast_recycle_trace_t * t = va_arg (*args, mcast_recycle_trace_t *);
  
  s = format (s, 
"MCAST_R: group %d, current member %d next (node) index %d, tx_sw_if_index %d",
              t->group_index, t->current_member, t->next_index, t->sw_if_index);
  return s;
}

#define foreach_mcast_recycle_error \
_(RECYCLES, "Multicast Recycles")

typedef enum {
#define _(sym,str) MCAST_RECYCLE_ERROR_##sym,
  foreach_mcast_recycle_error
#undef _
  MCAST_RECYCLE_N_ERROR,
} mcast_recycle_error_t;

static char * mcast_recycle_error_strings[] = {
#define _(sym,string) string,
  foreach_mcast_recycle_error
#undef _
};

typedef enum {
  MCAST_RECYCLE_NEXT_DROP,
  MCAST_RECYCLE_N_NEXT,
} mcast_recycle_next_t;

static uword
mcast_recycle_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  mcast_recycle_next_t next_index;
  mcast_main_t * mcm = &mcast_main;
  vlib_node_t *n = vlib_get_node (vm, mcast_recycle_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t * em = &vm->error_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (0 && n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          
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

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          next0 = 0;
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
          next1 = 0;

          /* $$$$ your message in this space. Process 2 x pkts */

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    mcast_recycle_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    mcast_recycle_trace_t *t = 
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
      
      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;
          u32 current_member0;
          mcast_group_t * g0;
          
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          g0 = pool_elt_at_index (mcm->groups, 
                                  vnet_buffer(b0)->mcast.mcast_group_index);

          /* No more replicas? */
          if (b0->recycle_count == 1)
            {
              /* Restore the original free list index */
              b0->free_list_index = 
                vnet_buffer(b0)->mcast.original_free_list_index;
              b0->flags &= ~(VLIB_BUFFER_RECYCLE);
            }
          current_member0 = vnet_buffer(b0)->mcast.mcast_current_index;
          
          next0 = 
            g0->members[current_member0].prep_and_recycle_node_next_index;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = 
            g0->members[current_member0].tx_sw_if_index;
          
          vnet_buffer(b0)->mcast.mcast_current_index = 
            current_member0 + 1;
          
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            mcast_recycle_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->next_index = next0;
            t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_TX];
            t->group_index = vnet_buffer(b0)->mcast.mcast_group_index;
            t->current_member = current_member0;
            }
            
          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  em->counters[node_counter_base_index + MCAST_RECYCLE_ERROR_RECYCLES] += 
      frame->n_vectors;

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (mcast_recycle_node) = {
  .function = mcast_recycle_node_fn,
  .name = "mcast-recycle",
  .vector_size = sizeof (u32),
  .format_trace = format_mcast_recycle_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(mcast_recycle_error_strings),
  .error_strings = mcast_recycle_error_strings,

  .n_next_nodes = MCAST_RECYCLE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [MCAST_RECYCLE_NEXT_DROP] = "error-drop",
  },
};

/*
 * fish pkts back from the recycle queue/freelist
 * un-flatten the context chains
 */
static void mcast_recycle_callback (vlib_main_t *vm, 
                                    vlib_buffer_free_list_t * fl)
{
  vlib_frame_t * f = 0;
  u32 n_left_from;
  u32 n_left_to_next = 0;
  u32 n_this_frame = 0;
  u32 * from;
  u32 * to_next;
  u32 bi0, pi0;
  vlib_buffer_t *b0;
  vlib_buffer_t *bnext0;
  int i;

  /* aligned, unaligned buffers */
  for (i = 0; i < 2; i++) 
    {
      if (i == 0)
        {
          from = fl->aligned_buffers;
          n_left_from = vec_len (from);
        }
      else
        {
          from = fl->unaligned_buffers;
          n_left_from = vec_len (from);
        }
    
      while (n_left_from > 0)
        {
          if (PREDICT_FALSE(n_left_to_next == 0)) 
            {
              if (f)
                {
                  f->n_vectors = n_this_frame;
                  vlib_put_frame_to_node (vm, mcast_recycle_node.index, f);
                }
              
              f = vlib_get_frame_to_node (vm, mcast_recycle_node.index);
              to_next = vlib_frame_vector_args (f);
              n_left_to_next = VLIB_FRAME_SIZE;
              n_this_frame = 0;
            }
          
          bi0 = from[0];
          if (PREDICT_TRUE(n_left_from > 1))
            {
              pi0 = from[1];
              vlib_prefetch_buffer_with_index(vm,pi0,LOAD);
            }
        
          bnext0 = b0 = vlib_get_buffer (vm, bi0);
          
          while (bnext0->flags & VLIB_BUFFER_NEXT_PRESENT)
            {
              from += 1;
              n_left_from -= 1;
              bnext0 = vlib_get_buffer (vm, bnext0->next_buffer);
            }
          to_next[0] = bi0;

          if (CLIB_DEBUG > 0)
            vlib_buffer_set_known_state (vm, bi0, VLIB_BUFFER_KNOWN_ALLOCATED);

          from++;
          to_next++;
          n_this_frame++;
          n_left_to_next--;
          n_left_from--;
        }
    }
  
  vec_reset_length (fl->aligned_buffers);
  vec_reset_length (fl->unaligned_buffers);

  if (f)
    {
      ASSERT(n_this_frame);
      f->n_vectors = n_this_frame;
      vlib_put_frame_to_node (vm, mcast_recycle_node.index, f);
    }
}

clib_error_t *mcast_init (vlib_main_t *vm)
{
  mcast_main_t * mcm = &mcast_main;
  vlib_buffer_main_t * bm = vm->buffer_main;
  vlib_buffer_free_list_t * fl;
    
  mcm->vlib_main = vm;
  mcm->vnet_main = vnet_get_main();
  mcm->mcast_recycle_list_index = 
    vlib_buffer_create_free_list (vm, 1024 /* fictional */, "mcast-recycle");

  fl = pool_elt_at_index (bm->buffer_free_list_pool, 
                          mcm->mcast_recycle_list_index);

  fl->buffers_added_to_freelist_function = mcast_recycle_callback;

  return 0;
}

VLIB_INIT_FUNCTION (mcast_init);


