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

#include <vnet/ip/ip6_hop_by_hop.h>

/* Timestamp precision multipliers for seconds, milliseconds, microseconds
 * and nanoseconds respectively.
 */
static f64 trace_tsp_mul[4] = {1, 1e3, 1e6, 1e9};

char *ppc_state[] = {"None", "Encap", "Decap"};

ip6_hop_by_hop_main_t ip6_hop_by_hop_main;

/*
 * ip6 hop-by-hop option handling. We push pkts with h-b-h options to
 * ip6_hop_by_hop_node_fn from ip6-lookup at a cost of ~2 clocks/pkt in
 * the speed path.
 * 
 * We parse through the h-b-h option TLVs, specifically looking for
 * HBH_OPTION_TYPE_IOAM_DATA_LIST. [Someone needs to get bananas from
 * IANA, aka to actually allocate the option TLV codes.]
 * 
 * If we find the indicated option type, and we have remaining list
 * elements in the trace list, allocate and populate the trace list
 * element. 
 *
 * At the ingress edge: punch in the h-b-h rewrite, then visit the
 * standard h-b-h option handler. We have to be careful in the standard 
 * h-b-h handler, to avoid looping until we run out of rewrite space.
 * Ask me how I know that.
 * 
 * Remaining work:
 *  decide on egress point "pop and count" scheme
 *  time stamp handling: usec since the top of the hour?
 *  configure the node id
 *  trace list application data support
 *  cons up analysis / steering plug-in(s)
 *  add configuration binary APIs, vpp_api_test_support, yang models and
 *  orca code
 *  perf tune: dual loop, replace memcpy w/ N x 8-byte load/stores
 *  
 */

/* 
 * primary h-b-h handler trace support
 * We work pretty hard on the problem for obvious reasons
 */
typedef struct {
  u32 next_index;
  u32 trace_len;
  u32 timestamp_msbs; /* Store the top set of bits of timestamp */
  u8 option_data[256];
} ip6_hop_by_hop_trace_t;

typedef union {
    u64 as_u64;
    u32 as_u32[2];
} time_u64_t;

static inline u8
fetch_trace_data_size(u8 trace_type)
{
  u8 trace_data_size = 0;

  if (trace_type == TRACE_TYPE_IF_TS_APP)   
      trace_data_size = sizeof(ioam_trace_if_ts_app_t);
  else if(trace_type == TRACE_TYPE_IF)      
      trace_data_size = sizeof(ioam_trace_if_t);
  else if(trace_type == TRACE_TYPE_TS)      
      trace_data_size = sizeof(ioam_trace_ts_t);
  else if(trace_type == TRACE_TYPE_APP)     
      trace_data_size = sizeof(ioam_trace_app_t);
  else if(trace_type == TRACE_TYPE_TS_APP)  
      trace_data_size = sizeof(ioam_trace_ts_app_t);

  return trace_data_size;
}

static u8 * format_ioam_data_list_element (u8 * s, va_list * args)
{ 
  u32 *elt = va_arg (*args, u32 *);
  u8  *trace_type_p = va_arg (*args, u8 *);
  u8  trace_type = *trace_type_p;


  if (trace_type & BIT_TTL_NODEID)
    {
      u32 ttl_node_id_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, "ttl 0x%x node id 0x%x ",
              ttl_node_id_host_byte_order>>24,
              ttl_node_id_host_byte_order & 0x00FFFFFF);

      elt++;
    }
 
  if (trace_type & BIT_ING_INTERFACE && trace_type & BIT_ING_INTERFACE)
    {
        u32 ingress_host_byte_order = clib_net_to_host_u32(*elt);
        s = format (s, "ingress 0x%x egress 0x%x ", 
                   ingress_host_byte_order >> 16, 
                   ingress_host_byte_order &0xFFFF);
        elt++;
    }
 
  if (trace_type & BIT_TIMESTAMP)
    {
        u32 ts_in_host_byte_order = clib_net_to_host_u32 (*elt);
        s = format (s, "ts 0x%x \n", ts_in_host_byte_order);
        elt++;
    }
 
  if (trace_type & BIT_APPDATA)
    {
        u32 appdata_in_host_byte_order = clib_net_to_host_u32 (*elt);
        s = format (s, "app 0x%x ", appdata_in_host_byte_order);
        elt++;
    }
 
  return s;
}

static u8 * format_ip6_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_hop_by_hop_trace_t * t = va_arg (*args, ip6_hop_by_hop_trace_t *);
  ip6_hop_by_hop_header_t *hbh0;
  ip6_hop_by_hop_option_t *opt0, *limit0;
  ioam_trace_option_t * trace0;
  u8 trace_data_size_in_words = 0;
  u32 * elt0;
  int elt_index;
  u8 type0;
  
  hbh0 = (ip6_hop_by_hop_header_t *)t->option_data;

  s = format (s, "IP6_HOP_BY_HOP: next index %d len %d traced %d\n",
              t->next_index, (hbh0->length+1)<<3, t->trace_len);
  
  opt0 = (ip6_hop_by_hop_option_t *) (hbh0+1);
  limit0 = (ip6_hop_by_hop_option_t *) ((u8 *)hbh0) + t->trace_len;

  while (opt0 < limit0)
    {
      type0 = opt0->type & HBH_OPTION_TYPE_MASK;
      elt_index = 0;
      switch (type0)
        {
        case HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST:
          trace0 = (ioam_trace_option_t *)opt0;
          s = format (s, "  Trace Type 0x%x , %d elts left ts msb(s) 0x%x\n", 
                      trace0->ioam_trace_type, trace0->data_list_elts_left,
                      t->timestamp_msbs);
          trace_data_size_in_words = 
            fetch_trace_data_size(trace0->ioam_trace_type)/4;
          elt0 = &trace0->elts[0];
          while ((u8 *) elt0 < 
                 ((u8 *)(&trace0->elts[0]) + trace0->hdr.length - 2 
                  /* -2 accounts for ioam_trace_type,elts_left */))
            {
              s = format (s, "    [%d] %U\n",elt_index,  
                          format_ioam_data_list_element, 
                          elt0, &trace0->ioam_trace_type);
              elt_index++;
              elt0 += trace_data_size_in_words;
            }
          
          opt0 = (ip6_hop_by_hop_option_t *) 
            (((u8 *)opt0) + opt0->length 
             + sizeof (ip6_hop_by_hop_option_t));
          break;

        case HBH_OPTION_TYPE_IOAM_PROOF_OF_WORK:
          s = format (s, "    POW opt present\n");
          opt0 = (ip6_hop_by_hop_option_t *) 
            (((u8 *)opt0) + sizeof (ioam_pow_option_t));
          break;
          
        case 0: /* Pad, just stop */
          opt0 = (ip6_hop_by_hop_option_t *) ((u8 *)opt0) + 1;
          break;

        default:
          s = format (s, "Unknown %d", type0);
          opt0 = (ip6_hop_by_hop_option_t *) 
            (((u8 *)opt0) + opt0->length 
             + sizeof (ip6_hop_by_hop_option_t));
          break;
        }
    }
  return s;
}

vlib_node_registration_t ip6_hop_by_hop_node;

#define foreach_ip6_hop_by_hop_error \
_(PROCESSED, "Pkts with ip6 hop-by-hop options")

typedef enum {
#define _(sym,str) IP6_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_hop_by_hop_error
#undef _
  IP6_HOP_BY_HOP_N_ERROR,
} ip6_hop_by_hop_error_t;

static char * ip6_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_hop_by_hop_error
#undef _
};

static uword
ip6_hop_by_hop_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;
  u32 n_left_from, * from, * to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0;
  u8 elt_index = 0;
  time_u64_t time_u64;

  time_u64.as_u64 = 0;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0 /* $$$ DUAL-LOOP ME */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 next0 = IP6_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
          u32 next1 = IP6_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
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
                    ip6_hop_by_hop_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    ip6_hop_by_hop_trace_t *t = 
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
          ip6_header_t * ip0;
          ip_adjacency_t * adj0;
          ip6_hop_by_hop_header_t *hbh0;
          ip6_hop_by_hop_option_t *opt0, *limit0;
          ioam_trace_option_t * trace0;
          u32 * elt0;
          u8 type0;
         
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          ip0 = vlib_buffer_get_current (b0);
          adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
          adj0 = ip_get_adjacency (lm, adj_index0);
          hbh0 = (ip6_hop_by_hop_header_t *)(ip0+1);
          opt0 = (ip6_hop_by_hop_option_t *)(hbh0+1);
          limit0 = (ip6_hop_by_hop_option_t *)
            ((u8 *)hbh0 + ((hbh0->length+1)<<3));
          
          /* Scan the set of h-b-h options, process ones that we understand */
          while (opt0 < limit0)
            {
              type0 = opt0->type & HBH_OPTION_TYPE_MASK;
              switch (type0)
                {
                case HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST:
                  trace0 = (ioam_trace_option_t *)opt0;
                  if (PREDICT_TRUE (trace0->data_list_elts_left))
                    {
                      trace0->data_list_elts_left--;
                      /* fetch_trace_data_size returns in bytes. Convert it to 4-bytes
                       * to skip to this node's location.
                       */
                      elt_index = trace0->data_list_elts_left *
                                  fetch_trace_data_size(trace0->ioam_trace_type)/4;
                      elt0 = &trace0->elts[elt_index];
                      if (trace0->ioam_trace_type & BIT_TTL_NODEID) 
                        {
                          *elt0 = 
                            clib_host_to_net_u32 ((ip0->hop_limit<<24) 
                                              | hm->node_id);
                          elt0++;
                        }

                      if (trace0->ioam_trace_type & BIT_ING_INTERFACE) 
                        {
                          *elt0 =
                          (vnet_buffer(b0)->sw_if_index[VLIB_RX]&0xFFFF) << 16 |                           (adj0->rewrite_header.sw_if_index & 0xFFFF);
                          *elt0 = clib_host_to_net_u32(*elt0);
                          elt0++;
                        }
                 
                      if (trace0->ioam_trace_type & BIT_TIMESTAMP)
                        {
                            /* Send least significant 32 bits */
                            f64 time_f64 = (f64)(((f64)hm->unix_time_0) +
                              (vlib_time_now(hm->vlib_main) - hm->vlib_time_0));

                            time_u64.as_u64 = 
                               time_f64 * trace_tsp_mul[hm->trace_tsp];
                            *elt0 = clib_host_to_net_u32(time_u64.as_u32[0]);
                            elt0++;
                        }

                      if (trace0->ioam_trace_type & BIT_APPDATA)
                        {
                          /* $$$ set elt0->app_data */
                          *elt0 = clib_host_to_net_u32(hm->app_data);
                          elt0++;
                        }
                    }

                  opt0 = (ip6_hop_by_hop_option_t *) 
                    (((u8 *)opt0) + opt0->length 
                     + sizeof (ip6_hop_by_hop_option_t));
                  break;

                case HBH_OPTION_TYPE_IOAM_PROOF_OF_WORK:
                  opt0 = (ip6_hop_by_hop_option_t *) 
                    (((u8 *)opt0) + sizeof (ioam_pow_option_t));
                  break;

                case 0: /* Pad */
                  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *)opt0) + 1;
                  goto out0;

                default:
                  opt0 = (ip6_hop_by_hop_option_t *)
                  (((u8 *)opt0) + opt0->length
                  + sizeof (ip6_hop_by_hop_option_t));
                  break;
                }
            }

        out0:

          /* 
           * Since we push pkts here from the h-b-h header imposition code
           * we have to be careful what we wish for...
           */
          next0 = adj0->lookup_next_index != IP_LOOKUP_NEXT_ADD_HOP_BY_HOP ?
              adj0->lookup_next_index : adj0->saved_lookup_next_index;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              ip6_hop_by_hop_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              u32 trace_len = (hbh0->length+1)<<3;
              t->next_index = next0;
              /* Capture the h-b-h option verbatim */
              trace_len = trace_len < ARRAY_LEN(t->option_data) ? 
                trace_len : ARRAY_LEN(t->option_data);
              t->trace_len = trace_len;
              t->timestamp_msbs = time_u64.as_u32[1];
              memcpy (t->option_data, hbh0, trace_len);
            }
            
          processed++;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ip6_hop_by_hop_node.index, 
                               IP6_HOP_BY_HOP_ERROR_PROCESSED, processed);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_hop_by_hop_node) = {
  .function = ip6_hop_by_hop_node_fn,
  .name = "ip6-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ip6_hop_by_hop_error_strings),
  .error_strings = ip6_hop_by_hop_error_strings,

  /* See ip/lookup.h */
  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = {
    [IP_LOOKUP_NEXT_MISS] = "ip6-miss",
    [IP_LOOKUP_NEXT_DROP] = "ip6-drop",
    [IP_LOOKUP_NEXT_PUNT] = "ip6-punt",
    [IP_LOOKUP_NEXT_LOCAL] = "ip6-local",
    [IP_LOOKUP_NEXT_ARP] = "ip6-discover-neighbor",
    [IP_LOOKUP_NEXT_REWRITE] = "ip6-rewrite",
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip6-classify",
    [IP_LOOKUP_NEXT_MAP] = "ip6-map",
    [IP_LOOKUP_NEXT_MAP_T] = "ip6-map-t",
    [IP_LOOKUP_NEXT_SIXRD] = "ip6-sixrd",
    /* Next 3 arcs probably never used */
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip6-hop-by-hop",
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip6-add-hop-by-hop", 
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip6-pop-hop-by-hop", 
  },
};

/* The main h-b-h tracer will be invoked, no need to do much here */
typedef struct {
  u32 next_index;
} ip6_add_hop_by_hop_trace_t;

/* packet trace format function */
static u8 * format_ip6_add_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_add_hop_by_hop_trace_t * t = va_arg (*args, 
                                            ip6_add_hop_by_hop_trace_t *);
  
  s = format (s, "IP6_ADD_HOP_BY_HOP: next index %d",
              t->next_index);
  return s;
}

vlib_node_registration_t ip6_add_hop_by_hop_node;

#define foreach_ip6_add_hop_by_hop_error \
_(PROCESSED, "Pkts w/ added ip6 hop-by-hop options")

typedef enum {
#define _(sym,str) IP6_ADD_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_add_hop_by_hop_error
#undef _
  IP6_ADD_HOP_BY_HOP_N_ERROR,
} ip6_add_hop_by_hop_error_t;

static char * ip6_add_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_add_hop_by_hop_error
#undef _
};

static uword
ip6_add_hop_by_hop_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;
  u32 n_left_from, * from, * to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0;
  u8 * rewrite = hm->rewrite;
  u32 rewrite_length = vec_len (rewrite);

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
          u32 next0 = IP6_ADD_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
          u32 next1 = IP6_ADD_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
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
                    ip6_add_hop_by_hop_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    ip6_add_hop_by_hop_trace_t *t = 
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
          ip6_header_t * ip0;
          ip6_hop_by_hop_header_t * hbh0;
          u64 * copy_src0, * copy_dst0;
          u16 new_l0;
          
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          ip0 = vlib_buffer_get_current (b0);

          /* Copy the ip header left by the required amount */
          copy_dst0 = (u64 *)(((u8 *)ip0) - rewrite_length);
          copy_src0 = (u64 *) ip0;

          copy_dst0 [0] = copy_src0 [0];
          copy_dst0 [1] = copy_src0 [1];
          copy_dst0 [2] = copy_src0 [2];
          copy_dst0 [3] = copy_src0 [3];
          copy_dst0 [4] = copy_src0 [4];
          vlib_buffer_advance (b0, - (word)rewrite_length);
          ip0 = vlib_buffer_get_current (b0);

          hbh0 = (ip6_hop_by_hop_header_t *)(ip0 + 1);
          /* $$$ tune, rewrite_length is a multiple of 8 */
          memcpy (hbh0, rewrite, rewrite_length);
          /* Patch the protocol chain, insert the h-b-h (type 0) header */
          hbh0->protocol = ip0->protocol;
          ip0->protocol = 0;
          new_l0 = clib_net_to_host_u16 (ip0->payload_length) + rewrite_length;
          ip0->payload_length = clib_host_to_net_u16 (new_l0);
          
          /* Populate the (first) h-b-h list elt */
          next0 = IP_LOOKUP_NEXT_HOP_BY_HOP;

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              ip6_add_hop_by_hop_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->next_index = next0;
            }
            
          processed++;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ip6_add_hop_by_hop_node.index, 
                               IP6_ADD_HOP_BY_HOP_ERROR_PROCESSED, processed);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_add_hop_by_hop_node) = {
  .function = ip6_add_hop_by_hop_node_fn,
  .name = "ip6-add-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_add_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ip6_add_hop_by_hop_error_strings),
  .error_strings = ip6_add_hop_by_hop_error_strings,

  /* See ip/lookup.h */
  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = {
    [IP_LOOKUP_NEXT_MISS] = "ip6-miss",
    [IP_LOOKUP_NEXT_DROP] = "ip6-drop",
    [IP_LOOKUP_NEXT_PUNT] = "ip6-punt",
    [IP_LOOKUP_NEXT_LOCAL] = "ip6-local",
    [IP_LOOKUP_NEXT_ARP] = "ip6-discover-neighbor",
    [IP_LOOKUP_NEXT_REWRITE] = "ip6-rewrite",
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip6-classify",
    [IP_LOOKUP_NEXT_MAP] = "ip6-map",
    [IP_LOOKUP_NEXT_MAP_T] = "ip6-map-t",
    [IP_LOOKUP_NEXT_SIXRD] = "ip6-sixrd",
    /* Next 3 arcs probably never used */
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip6-hop-by-hop",
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip6-add-hop-by-hop", 
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip6-pop-hop-by-hop", 
  },
};


/* The main h-b-h tracer was already invoked, no need to do much here */
typedef struct {
  u32 next_index;
} ip6_pop_hop_by_hop_trace_t;

/* packet trace format function */
static u8 * format_ip6_pop_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_pop_hop_by_hop_trace_t * t = va_arg (*args, ip6_pop_hop_by_hop_trace_t *);
  
  s = format (s, "IP6_POP_HOP_BY_HOP: next index %d",
              t->next_index);
  return s;
}

vlib_node_registration_t ip6_pop_hop_by_hop_node;

#define foreach_ip6_pop_hop_by_hop_error                \
_(PROCESSED, "Pkts w/ removed ip6 hop-by-hop options")  \
_(NO_HOHO, "Pkts w/ no ip6 hop-by-hop options")

typedef enum {
#define _(sym,str) IP6_POP_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_pop_hop_by_hop_error
#undef _
  IP6_POP_HOP_BY_HOP_N_ERROR,
} ip6_pop_hop_by_hop_error_t;

static char * ip6_pop_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_pop_hop_by_hop_error
#undef _
};

static uword
ip6_pop_hop_by_hop_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 n_left_from, * from, * to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0;
  u32 no_header = 0;
  u32 (*ioam_end_of_path_cb) (vlib_main_t *, vlib_node_runtime_t *,
                              vlib_buffer_t *, ip6_header_t *, 
                              ip_adjacency_t *);
  
  ioam_end_of_path_cb = hm->ioam_end_of_path_cb;
  
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
          u32 next0 = IP6_POP_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
          u32 next1 = IP6_POP_HOP_BY_HOP_NEXT_INTERFACE_OUTPUT;
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
                    ip6_pop_hop_by_hop_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED) 
                  {
                    ip6_pop_hop_by_hop_trace_t *t = 
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
          ip6_header_t * ip0;
          ip_adjacency_t * adj0;
          ip6_hop_by_hop_header_t *hbh0;
          u64 * copy_dst0, * copy_src0;
          u16 new_l0;
          
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          ip0 = vlib_buffer_get_current (b0);
          adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
          adj0 = ip_get_adjacency (lm, adj_index0);

          /* Perfectly normal to end up here w/ out h-b-h header */
          if (PREDICT_TRUE (ip0->protocol == 0))
            {
              hbh0 = (ip6_hop_by_hop_header_t *)(ip0+1);
          
              /* Collect data from trace via callback */
              next0 = ioam_end_of_path_cb ? 
                ioam_end_of_path_cb (vm, node, b0, ip0, adj0) 
                : adj0->saved_lookup_next_index;
              
              
              /* Pop the trace data */
              vlib_buffer_advance (b0, (hbh0->length+1)<<3);
              new_l0 = clib_net_to_host_u16 (ip0->payload_length) -
                ((hbh0->length+1)<<3);
              ip0->payload_length = clib_host_to_net_u16 (new_l0);
              ip0->protocol = hbh0->protocol;
              copy_src0 = (u64 *)ip0;
              copy_dst0 = copy_src0 + (hbh0->length+1);
              copy_dst0 [4] = copy_src0[4];
              copy_dst0 [3] = copy_src0[3];
              copy_dst0 [2] = copy_src0[2];
              copy_dst0 [1] = copy_src0[1];
              copy_dst0 [0] = copy_src0[0];
              processed++;
            }
          else
            {
              next0 = adj0->saved_lookup_next_index;
              no_header++;
            }
              
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              ip6_pop_hop_by_hop_trace_t *t = 
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

  vlib_node_increment_counter (vm, ip6_pop_hop_by_hop_node.index, 
                               IP6_POP_HOP_BY_HOP_ERROR_PROCESSED, processed);
  vlib_node_increment_counter (vm, ip6_pop_hop_by_hop_node.index, 
                               IP6_POP_HOP_BY_HOP_ERROR_NO_HOHO, no_header);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_pop_hop_by_hop_node) = {
  .function = ip6_pop_hop_by_hop_node_fn,
  .name = "ip6-pop-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_pop_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ip6_pop_hop_by_hop_error_strings),
  .error_strings = ip6_pop_hop_by_hop_error_strings,

  /* See ip/lookup.h */
  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = {
    [IP_LOOKUP_NEXT_MISS] = "ip6-miss",
    [IP_LOOKUP_NEXT_DROP] = "ip6-drop",
    [IP_LOOKUP_NEXT_PUNT] = "ip6-punt",
    [IP_LOOKUP_NEXT_LOCAL] = "ip6-local",
    [IP_LOOKUP_NEXT_ARP] = "ip6-discover-neighbor",
    [IP_LOOKUP_NEXT_REWRITE] = "ip6-rewrite",
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip6-classify",
    [IP_LOOKUP_NEXT_MAP] = "ip6-map",
    [IP_LOOKUP_NEXT_MAP_T] = "ip6-map-t",
    [IP_LOOKUP_NEXT_SIXRD] = "ip6-sixrd",
    /* Next 3 arcs probably never used */
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip6-hop-by-hop",
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip6-add-hop-by-hop", 
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip6-pop-hop-by-hop", 
  },
};


static clib_error_t *
ip6_hop_by_hop_init (vlib_main_t * vm)
{
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main();
  hm->unix_time_0 = (u32) time (0); /* Store starting time */
  hm->vlib_time_0 = vlib_time_now (vm);
  hm->ioam_flag = IOAM_HBYH_MOD;
  hm->trace_tsp = TSP_MICROSECONDS; /* Micro seconds */

  return 0;
}

VLIB_INIT_FUNCTION (ip6_hop_by_hop_init);

int ip6_ioam_set_rewrite (u8 **rwp, u32 trace_type, u32 trace_option_elts, 
                          int has_pow_option, int has_ppc_option)
{
  u8 *rewrite = 0;
  u32 size, rnd_size;
  ip6_hop_by_hop_header_t *hbh;
  ioam_trace_option_t * trace_option;
  ioam_pow_option_t * pow_option;
  u8 *current;
  u8 trace_data_size = 0;  

  vec_free (*rwp);

  if (trace_option_elts == 0 && has_pow_option == 0)
    return -1;

  /* Work out how much space we need */
  size = sizeof (ip6_hop_by_hop_header_t);

  if (trace_option_elts)
    {
      size += sizeof (ip6_hop_by_hop_option_t);

      trace_data_size = fetch_trace_data_size(trace_type);
      if (trace_data_size == 0)
          return VNET_API_ERROR_INVALID_VALUE;

      if (trace_option_elts * trace_data_size > 254)
          return VNET_API_ERROR_INVALID_VALUE;
  
      size += trace_option_elts * trace_data_size;
    }
  if (has_pow_option)
    {
      size += sizeof (ip6_hop_by_hop_option_t);
      size += sizeof (ioam_pow_option_t);
    }

  /* Round to a multiple of 8 octets */
  rnd_size = (size + 7) & ~7;

  /* allocate it, zero-fill / pad by construction */
  vec_validate (rewrite, rnd_size-1);

  hbh = (ip6_hop_by_hop_header_t *) rewrite;
  /* Length of header in 8 octet units, not incl first 8 octets */
  hbh->length = (rnd_size>>3) - 1;
  current = (u8 *)(hbh+1);
  
  if (trace_option_elts)
    {
      trace_option = (ioam_trace_option_t *)current;
      trace_option->hdr.type = HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST
        | HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE;
      trace_option->hdr.length = 
               2 /*ioam_trace_type,data_list_elts_left */ + 
              trace_option_elts * trace_data_size;
      trace_option->ioam_trace_type = trace_type & TRACE_TYPE_MASK;
      trace_option->data_list_elts_left = trace_option_elts;
      current += sizeof (ioam_trace_option_t) + 
        trace_option_elts * trace_data_size;
    }
  if (has_pow_option)
    {
      pow_option = (ioam_pow_option_t *)current;
      pow_option->hdr.type = HBH_OPTION_TYPE_IOAM_PROOF_OF_WORK
        | HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE;
      pow_option->hdr.length = sizeof (ioam_pow_option_t) - 
        sizeof (ip6_hop_by_hop_option_t);
      current += sizeof (ioam_pow_option_t);
    }
  
  *rwp = rewrite;
  return 0;
}

clib_error_t *
clear_ioam_rewrite_fn(void)
{
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;

  vec_free(hm->rewrite);
  hm->rewrite = 0;
  hm->node_id = 0;
  hm->app_data = 0;
  hm->trace_type = 0;
  hm->trace_option_elts = 0;
  hm->has_pow_option = 0;
  hm->has_ppc_option = 0;
  hm->trace_tsp = TSP_MICROSECONDS; 

  return 0;
}

clib_error_t * clear_ioam_rewrite_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  return(clear_ioam_rewrite_fn());
}
  
VLIB_CLI_COMMAND (ip6_clear_ioam_trace_cmd, static) = {
  .path = "clear ioam rewrite",
  .short_help = "clear ioam rewrite",
  .function = clear_ioam_rewrite_command_fn,
};

clib_error_t *
ip6_ioam_trace_profile_set(u32 trace_option_elts, u32 trace_type, u32 node_id,
                           u32 app_data, int has_pow_option, u32 trace_tsp, 
                           int has_ppc_option)
{
  int rv;
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  rv = ip6_ioam_set_rewrite (&hm->rewrite, trace_type, trace_option_elts,
                             has_pow_option, has_ppc_option);

  switch (rv)
    {
    case 0:
      hm->node_id = node_id;
      hm->app_data = app_data;
      hm->trace_type = trace_type;
      hm->trace_option_elts = trace_option_elts;
      hm->has_pow_option = has_pow_option;
      hm->has_ppc_option = has_ppc_option;
      hm->trace_tsp = trace_tsp;
      break;

    default:
      return clib_error_return_code(0, rv, 0, "ip6_ioam_set_rewrite returned %d", rv);
    }

  return 0;
}


static clib_error_t *
ip6_set_ioam_rewrite_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  u32 trace_option_elts = 0;
  u32 trace_type = 0, node_id = 0; 
  u32 app_data = 0, trace_tsp = TSP_MICROSECONDS;
  int has_pow_option = 0;
  int has_ppc_option = 0;
  clib_error_t * rv = 0;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace-type 0x%x trace-elts %d "
                           "trace-tsp %d node-id 0x%x app-data 0x%x", 
                      &trace_type, &trace_option_elts, &trace_tsp,
                      &node_id, &app_data))
            ;
      else if (unformat (input, "pow"))
        has_pow_option = 1;
      else if (unformat (input, "ppc encap"))
        has_ppc_option = PPC_ENCAP;
      else if (unformat (input, "ppc decap"))
        has_ppc_option = PPC_DECAP;
      else if (unformat (input, "ppc none"))
        has_ppc_option = PPC_NONE;
      else
        break;
    }
  
    
    rv = ip6_ioam_trace_profile_set(trace_option_elts, trace_type, node_id,
                           app_data, has_pow_option, trace_tsp, has_ppc_option);

    return rv;
}


VLIB_CLI_COMMAND (ip6_set_ioam_rewrite_cmd, static) = {
  .path = "set ioam rewrite",
  .short_help = "set ioam rewrite trace-type <0x1f|0x3|0x9|0x11|0x19> trace-elts <nn> trace-tsp <0|1|2|3> node-id <node id in hex> app-data <app_data in hex> [pow] [ppc <encap|decap>]",
  .function = ip6_set_ioam_rewrite_command_fn,
};
  
static clib_error_t *
ip6_show_ioam_summary_cmd_fn (vlib_main_t * vm,
                      unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  u8 *s = 0;


  if (!is_zero_ip6_address(&hm->adj))
  {
  s = format(s, "              REWRITE FLOW CONFIGS - \n");
  s = format(s, "               Destination Address : %U\n",
            format_ip6_address, &hm->adj, sizeof(ip6_address_t));
  s = format(s, "                    Flow operation : %d (%s)\n", hm->ioam_flag,
           (hm->ioam_flag == IOAM_HBYH_ADD) ? "Add" : 
          ((hm->ioam_flag == IOAM_HBYH_MOD) ? "Mod" : "Pop"));
  } 
  else 
  {
  s = format(s, "              REWRITE FLOW CONFIGS - Not configured\n");
  }

  if (hm->trace_option_elts)
  {
  s = format(s, " HOP BY HOP OPTIONS - TRACE CONFIG - \n");
  s = format(s, "                        Trace Type : 0x%x (%d)\n", 
          hm->trace_type, hm->trace_type);
  s = format(s, "         Trace timestamp precision : %d (%s)\n", hm->trace_tsp,
       (hm->trace_tsp == TSP_SECONDS) ? "Seconds" : 
      ((hm->trace_tsp == TSP_MILLISECONDS) ? "Milliseconds" : 
     (((hm->trace_tsp == TSP_MICROSECONDS) ? "Microseconds" : "Nanoseconds"))));
  s = format(s, "                Num of trace nodes : %d\n", 
          hm->trace_option_elts);
  s = format(s, "                           Node-id : 0x%x (%d)\n", 
          hm->node_id, hm->node_id);
  s = format(s, "                          App Data : 0x%x (%d)\n", 
          hm->app_data, hm->app_data);
  }
  else
  {
  s = format(s, " HOP BY HOP OPTIONS - TRACE CONFIG - Not configured\n");
  }

  s = format(s, "                        POW OPTION - %d (%s)\n", 
          hm->has_pow_option, (hm->has_pow_option?"Enabled":"Disabled"));
  if (hm->has_pow_option)
    s = format(s, "Try 'show ioam sc-profile' for more information\n");

  s = format(s, "         EDGE TO EDGE - PPC OPTION - %d (%s)\n", 
         hm->has_ppc_option, ppc_state[hm->has_ppc_option]);
  if (hm->has_ppc_option)
    s = format(s, "Try 'show ioam ppc' for more information\n");

  vlib_cli_output(vm, "%v", s);
  vec_free(s);
  return 0;
}

VLIB_CLI_COMMAND (ip6_show_ioam_run_cmd, static) = {
  .path = "show ioam summary",
  .short_help = "Summary of IOAM configuration",
  .function = ip6_show_ioam_summary_cmd_fn,
};

int ip6_ioam_set_destination (ip6_address_t *addr, u32 mask_width, u32 vrf_id,
                              int is_add, int is_pop, int is_none)
{
  ip6_main_t * im = &ip6_main;
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_adjacency_t * adj;
  u32 fib_index;
  u32 len, adj_index;
  int i, rv;
  uword * p;
  BVT(clib_bihash_kv) kv, value;

  if ((is_add + is_pop + is_none) != 1)
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* Go find the adjacency we're supposed to tickle */
  p = hash_get (im->fib_index_by_table_id, vrf_id);

  if (p == 0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_index = p[0];

  len = vec_len (im->prefix_lengths_in_search_order);
  
  for (i = 0; i < len; i++)
    {
      int dst_address_length = im->prefix_lengths_in_search_order[i];
      ip6_address_t * mask = &im->fib_masks[dst_address_length];
      
      if (dst_address_length != mask_width)
        continue;

      kv.key[0] = addr->as_u64[0] & mask->as_u64[0];
      kv.key[1] = addr->as_u64[1] & mask->as_u64[1];
      kv.key[2] = ((u64)((fib_index))<<32) | dst_address_length;
      
      rv = BV(clib_bihash_search_inline_2)(&im->ip6_lookup_table, &kv, &value);
      if (rv == 0)
        goto found;

    }
  return VNET_API_ERROR_NO_SUCH_ENTRY;
  
 found:

  /* Got it, modify as directed... */
  adj_index = value.value;
  adj = ip_get_adjacency (lm, adj_index);

  /* Restore original lookup-next action */
  if (adj->saved_lookup_next_index)
    {
      adj->lookup_next_index = adj->saved_lookup_next_index;
      adj->saved_lookup_next_index = 0;
    }

  /* Save current action */
  if (is_add || is_pop)
    adj->saved_lookup_next_index = adj->lookup_next_index;

  if (is_add)
    adj->lookup_next_index = IP_LOOKUP_NEXT_ADD_HOP_BY_HOP;

  if (is_pop)
    adj->lookup_next_index = IP_LOOKUP_NEXT_POP_HOP_BY_HOP;

  hm->adj = *addr;
  hm->ioam_flag = (is_add ? IOAM_HBYH_ADD :
                  (is_pop ? IOAM_HBYH_POP : IOAM_HBYH_MOD));
  return 0;
}
                              
static clib_error_t *
ip6_set_ioam_destination_command_fn (vlib_main_t * vm,
                                     unformat_input_t * input,
                                     vlib_cli_command_t * cmd)
{
  ip6_address_t addr;
  u32 mask_width = ~0;
  int is_add = 0;
  int is_pop = 0;
  int is_none = 0;
  u32 vrf_id = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U/%d", 
                    unformat_ip6_address, &addr, &mask_width))
        ;
      else if (unformat (input, "vrf-id %d", &vrf_id))
        ;
      else if (unformat (input, "add"))
        is_add = 1;
      else if (unformat (input, "pop"))
        is_pop = 1;
      else if (unformat (input, "none"))
        is_none = 1;
      else
        break;
    }

  if ((is_add + is_pop + is_none) != 1)
    return clib_error_return (0, "One of (add, pop, none) required");
  if (mask_width == ~0)
    return clib_error_return (0, "<address>/<mask-width> required");

  rv = ip6_ioam_set_destination (&addr, mask_width, vrf_id, 
                                 is_add, is_pop, is_none);

  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "ip6_ioam_set_destination returned %d", rv);
    }
  
  return 0;
}

VLIB_CLI_COMMAND (ip6_set_ioam_destination_cmd, static) = {
  .path = "set ioam destination",
  .short_help = "set ioam destination <ip6-address>/<width> add | pop | none",
  .function = ip6_set_ioam_destination_command_fn,
};

void vnet_register_ioam_end_of_path_callback (void *cb)
{
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;

  hm->ioam_end_of_path_cb = cb;
}
                                             

