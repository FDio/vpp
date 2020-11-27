/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/fib/ip6_fib.h>
#include <vnet/classify/vnet_classify.h>

/**
 * @file
 * @brief In-band OAM (iOAM).
 *
 * In-band OAM (iOAM) is an implementation study to record operational
 * information in the packet while the packet traverses a path between
 * two points in the network.
 *
 * VPP can function as in-band OAM encapsulating, transit and
 * decapsulating node. In this version of VPP in-band OAM data is
 * transported as options in an IPv6 hop-by-hop extension header. Hence
 * in-band OAM can be enabled for IPv6 traffic.
 */

#ifndef CLIB_MARCH_VARIANT
ip6_hop_by_hop_ioam_main_t ip6_hop_by_hop_ioam_main;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_ip6_hbyh_ioam_input_next	\
  _(IP6_REWRITE, "ip6-rewrite")			\
  _(IP6_LOOKUP, "ip6-lookup")			\
  _(DROP, "ip6-drop")

typedef enum
{
#define _(s,n) IP6_HBYH_IOAM_INPUT_NEXT_##s,
  foreach_ip6_hbyh_ioam_input_next
#undef _
    IP6_HBYH_IOAM_INPUT_N_NEXT,
} ip6_hbyh_ioam_input_next_t;

#ifndef CLIB_MARCH_VARIANT
static uword
unformat_opaque_ioam (unformat_input_t * input, va_list * args)
{
  u64 *opaquep = va_arg (*args, u64 *);
  u8 *flow_name = NULL;
  uword ret = 0;

  if (unformat (input, "ioam-encap %s", &flow_name))
    {
      *opaquep = ioam_flow_add (1, flow_name);
      ret = 1;
    }
  else if (unformat (input, "ioam-decap %s", &flow_name))
    {
      *opaquep = ioam_flow_add (0, flow_name);
      ret = 1;
    }

  vec_free (flow_name);
  return ret;
}

u8 *
get_flow_name_from_flow_ctx (u32 flow_ctx)
{
  flow_data_t *flow = NULL;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  u32 index;

  index = IOAM_MASK_DECAP_BIT (flow_ctx);

  if (pool_is_free_index (hm->flows, index))
    return NULL;

  flow = pool_elt_at_index (hm->flows, index);
  return (flow->flow_name);
}

/* The main h-b-h tracer will be invoked, no need to do much here */
int
ip6_hbh_add_register_option (u8 option,
			     u8 size,
			     int rewrite_options (u8 * rewrite_string,
						  u8 * rewrite_size))
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->add_options));

  /* Already registered */
  if (hm->add_options[option])
    return (-1);

  hm->add_options[option] = rewrite_options;
  hm->options_size[option] = size;

  return (0);
}

int
ip6_hbh_add_unregister_option (u8 option)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->add_options));

  /* Not registered */
  if (!hm->add_options[option])
    return (-1);

  hm->add_options[option] = NULL;
  hm->options_size[option] = 0;
  return (0);
}

/* Config handler registration */
int
ip6_hbh_config_handler_register (u8 option,
				 int config_handler (void *data, u8 disable))
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->config_handler));

  /* Already registered  */
  if (hm->config_handler[option])
    return (VNET_API_ERROR_INVALID_REGISTRATION);

  hm->config_handler[option] = config_handler;

  return (0);
}

int
ip6_hbh_config_handler_unregister (u8 option)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->config_handler));

  /* Not registered */
  if (!hm->config_handler[option])
    return (VNET_API_ERROR_INVALID_REGISTRATION);

  hm->config_handler[option] = NULL;
  return (0);
}

/* Flow handler registration */
int
ip6_hbh_flow_handler_register (u8 option,
			       u32 ioam_flow_handler (u32 flow_ctx, u8 add))
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->flow_handler));

  /* Already registered */
  if (hm->flow_handler[option])
    return (VNET_API_ERROR_INVALID_REGISTRATION);

  hm->flow_handler[option] = ioam_flow_handler;

  return (0);
}

int
ip6_hbh_flow_handler_unregister (u8 option)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->flow_handler));

  /* Not registered */
  if (!hm->flow_handler[option])
    return (VNET_API_ERROR_INVALID_REGISTRATION);

  hm->flow_handler[option] = NULL;
  return (0);
}
#endif /* CLIB_MARCH_VARIANT */

typedef struct
{
  u32 next_index;
} ip6_add_hop_by_hop_trace_t;

/* packet trace format function */
static u8 *
format_ip6_add_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_add_hop_by_hop_trace_t *t = va_arg (*args,
					  ip6_add_hop_by_hop_trace_t *);

  s = format (s, "IP6_ADD_HOP_BY_HOP: next index %d", t->next_index);
  return s;
}

extern vlib_node_registration_t ip6_add_hop_by_hop_node;

#define foreach_ip6_add_hop_by_hop_error \
_(PROCESSED, "Pkts w/ added ip6 hop-by-hop options")

typedef enum
{
#define _(sym,str) IP6_ADD_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_add_hop_by_hop_error
#undef _
    IP6_ADD_HOP_BY_HOP_N_ERROR,
} ip6_add_hop_by_hop_error_t;

static char *ip6_add_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_add_hop_by_hop_error
#undef _
};

VLIB_NODE_FN (ip6_add_hop_by_hop_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  u32 n_left_from, *from, *to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0;
  u8 *rewrite = hm->rewrite;
  u32 rewrite_length = vec_len (rewrite);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
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
	  ip6_header_t *ip0, *ip1;
	  ip6_hop_by_hop_header_t *hbh0, *hbh1;
	  u64 *copy_src0, *copy_dst0, *copy_src1, *copy_dst1;
	  u16 new_l0, new_l1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data - rewrite_length,
			   2 * CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data - rewrite_length,
			   2 * CLIB_CACHE_LINE_BYTES, STORE);
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
	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);

	  /* Copy the ip header left by the required amount */
	  copy_dst0 = (u64 *) (((u8 *) ip0) - rewrite_length);
	  copy_dst1 = (u64 *) (((u8 *) ip1) - rewrite_length);
	  copy_src0 = (u64 *) ip0;
	  copy_src1 = (u64 *) ip1;

	  copy_dst0[0] = copy_src0[0];
	  copy_dst0[1] = copy_src0[1];
	  copy_dst0[2] = copy_src0[2];
	  copy_dst0[3] = copy_src0[3];
	  copy_dst0[4] = copy_src0[4];

	  copy_dst1[0] = copy_src1[0];
	  copy_dst1[1] = copy_src1[1];
	  copy_dst1[2] = copy_src1[2];
	  copy_dst1[3] = copy_src1[3];
	  copy_dst1[4] = copy_src1[4];

	  vlib_buffer_advance (b0, -(word) rewrite_length);
	  vlib_buffer_advance (b1, -(word) rewrite_length);
	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);

	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  hbh1 = (ip6_hop_by_hop_header_t *) (ip1 + 1);
	  /* $$$ tune, rewrite_length is a multiple of 8 */
	  clib_memcpy_fast (hbh0, rewrite, rewrite_length);
	  clib_memcpy_fast (hbh1, rewrite, rewrite_length);
	  /* Patch the protocol chain, insert the h-b-h (type 0) header */
	  hbh0->protocol = ip0->protocol;
	  hbh1->protocol = ip1->protocol;
	  ip0->protocol = 0;
	  ip1->protocol = 0;
	  new_l0 =
	    clib_net_to_host_u16 (ip0->payload_length) + rewrite_length;
	  new_l1 =
	    clib_net_to_host_u16 (ip1->payload_length) + rewrite_length;
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip1->payload_length = clib_host_to_net_u16 (new_l1);

	  /* Populate the (first) h-b-h list elt */
	  next0 = IP6_HBYH_IOAM_INPUT_NEXT_IP6_LOOKUP;
	  next1 = IP6_HBYH_IOAM_INPUT_NEXT_IP6_LOOKUP;


	  /* $$$$$ End of processing 2 x packets $$$$$ */

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_add_hop_by_hop_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_add_hop_by_hop_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->next_index = next1;
		}
	    }
	  processed += 2;
	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip6_header_t *ip0;
	  ip6_hop_by_hop_header_t *hbh0;
	  u64 *copy_src0, *copy_dst0;
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
	  copy_dst0 = (u64 *) (((u8 *) ip0) - rewrite_length);
	  copy_src0 = (u64 *) ip0;

	  copy_dst0[0] = copy_src0[0];
	  copy_dst0[1] = copy_src0[1];
	  copy_dst0[2] = copy_src0[2];
	  copy_dst0[3] = copy_src0[3];
	  copy_dst0[4] = copy_src0[4];
	  vlib_buffer_advance (b0, -(word) rewrite_length);
	  ip0 = vlib_buffer_get_current (b0);

	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  /* $$$ tune, rewrite_length is a multiple of 8 */
	  clib_memcpy_fast (hbh0, rewrite, rewrite_length);
	  /* Patch the protocol chain, insert the h-b-h (type 0) header */
	  hbh0->protocol = ip0->protocol;
	  ip0->protocol = 0;
	  new_l0 =
	    clib_net_to_host_u16 (ip0->payload_length) + rewrite_length;
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);

	  /* Populate the (first) h-b-h list elt */
	  next0 = IP6_HBYH_IOAM_INPUT_NEXT_IP6_LOOKUP;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_add_hop_by_hop_node) =	/* *INDENT-OFF* */
{
  .name = "ip6-add-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_add_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ip6_add_hop_by_hop_error_strings),
  .error_strings = ip6_add_hop_by_hop_error_strings,
  /* See ip/lookup.h */
  .n_next_nodes = IP6_HBYH_IOAM_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IP6_HBYH_IOAM_INPUT_NEXT_##s] = n,
    foreach_ip6_hbyh_ioam_input_next
#undef _
  },
};
/* *INDENT-ON* */

/* The main h-b-h tracer was already invoked, no need to do much here */
typedef struct
{
  u32 next_index;
} ip6_pop_hop_by_hop_trace_t;

/* packet trace format function */
static u8 *
format_ip6_pop_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_pop_hop_by_hop_trace_t *t =
    va_arg (*args, ip6_pop_hop_by_hop_trace_t *);

  s = format (s, "IP6_POP_HOP_BY_HOP: next index %d", t->next_index);
  return s;
}

#ifndef CLIB_MARCH_VARIANT
int
ip6_hbh_pop_register_option (u8 option,
			     int options (vlib_buffer_t * b,
					  ip6_header_t * ip,
					  ip6_hop_by_hop_option_t * opt))
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->pop_options));

  /* Already registered */
  if (hm->pop_options[option])
    return (-1);

  hm->pop_options[option] = options;

  return (0);
}

int
ip6_hbh_pop_unregister_option (u8 option)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->pop_options));

  /* Not registered */
  if (!hm->pop_options[option])
    return (-1);

  hm->pop_options[option] = NULL;
  return (0);
}
#endif /* CLIB_MARCH_VARIANT */

extern vlib_node_registration_t ip6_pop_hop_by_hop_node;

#define foreach_ip6_pop_hop_by_hop_error                \
_(PROCESSED, "Pkts w/ removed ip6 hop-by-hop options")  \
_(NO_HOHO, "Pkts w/ no ip6 hop-by-hop options")         \
_(OPTION_FAILED, "ip6 pop hop-by-hop failed to process")

typedef enum
{
#define _(sym,str) IP6_POP_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_pop_hop_by_hop_error
#undef _
    IP6_POP_HOP_BY_HOP_N_ERROR,
} ip6_pop_hop_by_hop_error_t;

static char *ip6_pop_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_pop_hop_by_hop_error
#undef _
};

static inline void
ioam_pop_hop_by_hop_processing (vlib_main_t * vm,
				ip6_header_t * ip0,
				ip6_hop_by_hop_header_t * hbh0,
				vlib_buffer_t * b)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  ip6_hop_by_hop_option_t *opt0, *limit0;
  u8 type0;

  if (!hbh0 || !ip0)
    return;

  opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
  limit0 = (ip6_hop_by_hop_option_t *)
    ((u8 *) hbh0 + ((hbh0->length + 1) << 3));

  /* Scan the set of h-b-h options, process ones that we understand */
  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad1 */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *) opt0) + 1;
	  continue;
	case 1:		/* PadN */
	  break;
	default:
	  if (hm->pop_options[type0])
	    {
	      if ((*hm->pop_options[type0]) (b, ip0, opt0) < 0)
		{
		  vlib_node_increment_counter (vm,
					       ip6_pop_hop_by_hop_node.index,
					       IP6_POP_HOP_BY_HOP_ERROR_OPTION_FAILED,
					       1);
		}
	    }
	}
      opt0 =
	(ip6_hop_by_hop_option_t *) (((u8 *) opt0) + opt0->length +
				     sizeof (ip6_hop_by_hop_option_t));
    }
}

VLIB_NODE_FN (ip6_pop_hop_by_hop_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0;
  u32 no_header = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
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
	  u32 adj_index0, adj_index1;
	  ip6_header_t *ip0, *ip1;
	  ip_adjacency_t *adj0, *adj1;
	  ip6_hop_by_hop_header_t *hbh0, *hbh1;
	  u64 *copy_dst0, *copy_src0, *copy_dst1, *copy_src1;
	  u16 new_l0, new_l1;

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

	  /* $$$$$ Dual loop: process 2 x packets here $$$$$ */
	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  adj_index0 = vnet_buffer (b0)->ip.adj_index;
	  adj_index1 = vnet_buffer (b1)->ip.adj_index;
	  adj0 = adj_get (adj_index0);
	  adj1 = adj_get (adj_index1);

	  next0 = adj0->lookup_next_index;
	  next1 = adj1->lookup_next_index;

	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  hbh1 = (ip6_hop_by_hop_header_t *) (ip1 + 1);

	  ioam_pop_hop_by_hop_processing (vm, ip0, hbh0, b0);
	  ioam_pop_hop_by_hop_processing (vm, ip1, hbh1, b1);

	  vlib_buffer_advance (b0, (hbh0->length + 1) << 3);
	  vlib_buffer_advance (b1, (hbh1->length + 1) << 3);

	  new_l0 = clib_net_to_host_u16 (ip0->payload_length) -
	    ((hbh0->length + 1) << 3);
	  new_l1 = clib_net_to_host_u16 (ip1->payload_length) -
	    ((hbh1->length + 1) << 3);

	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip1->payload_length = clib_host_to_net_u16 (new_l1);

	  ip0->protocol = hbh0->protocol;
	  ip1->protocol = hbh1->protocol;

	  copy_src0 = (u64 *) ip0;
	  copy_src1 = (u64 *) ip1;
	  copy_dst0 = copy_src0 + (hbh0->length + 1);
	  copy_dst0[4] = copy_src0[4];
	  copy_dst0[3] = copy_src0[3];
	  copy_dst0[2] = copy_src0[2];
	  copy_dst0[1] = copy_src0[1];
	  copy_dst0[0] = copy_src0[0];
	  copy_dst1 = copy_src1 + (hbh1->length + 1);
	  copy_dst1[4] = copy_src1[4];
	  copy_dst1[3] = copy_src1[3];
	  copy_dst1[2] = copy_src1[2];
	  copy_dst1[1] = copy_src1[1];
	  copy_dst1[0] = copy_src1[0];
	  processed += 2;
	  /* $$$$$ End of processing 2 x packets $$$$$ */

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_pop_hop_by_hop_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_pop_hop_by_hop_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
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
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 adj_index0;
	  ip6_header_t *ip0;
	  ip_adjacency_t *adj0;
	  ip6_hop_by_hop_header_t *hbh0;
	  u64 *copy_dst0, *copy_src0;
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
	  adj_index0 = vnet_buffer (b0)->ip.adj_index;
	  adj0 = adj_get (adj_index0);

	  /* Default use the next_index from the adjacency. */
	  next0 = adj0->lookup_next_index;

	  /* Perfectly normal to end up here w/ out h-b-h header */
	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);

	  /* TODO:Temporarily doing it here.. do this validation in end_of_path_cb */
	  ioam_pop_hop_by_hop_processing (vm, ip0, hbh0, b0);
	  /* Pop the trace data */
	  vlib_buffer_advance (b0, (hbh0->length + 1) << 3);
	  new_l0 = clib_net_to_host_u16 (ip0->payload_length) -
	    ((hbh0->length + 1) << 3);
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip0->protocol = hbh0->protocol;
	  copy_src0 = (u64 *) ip0;
	  copy_dst0 = copy_src0 + (hbh0->length + 1);
	  copy_dst0[4] = copy_src0[4];
	  copy_dst0[3] = copy_src0[3];
	  copy_dst0[2] = copy_src0[2];
	  copy_dst0[1] = copy_src0[1];
	  copy_dst0[0] = copy_src0[0];
	  processed++;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_pop_hop_by_hop_node) =
{
  .name = "ip6-pop-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_pop_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "ip6-lookup",
  .n_errors = ARRAY_LEN (ip6_pop_hop_by_hop_error_strings),
  .error_strings = ip6_pop_hop_by_hop_error_strings,
  /* See ip/lookup.h */
  .n_next_nodes = 0,
};
/* *INDENT-ON* */

typedef struct
{
  u32 protocol;
  u32 next_index;
} ip6_local_hop_by_hop_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_ip6_local_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_local_hop_by_hop_trace_t *t =
    va_arg (*args, ip6_local_hop_by_hop_trace_t *);

  s = format (s, "IP6_LOCAL_HOP_BY_HOP: protocol %d,  next index %d\n",
	      t->protocol, t->next_index);
  return s;
}

vlib_node_registration_t ip6_local_hop_by_hop_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_ip6_local_hop_by_hop_error                      \
_(UNKNOWN, "Unknown protocol ip6 local h-b-h packets dropped")  \
_(OK, "Good ip6 local h-b-h packets")

typedef enum
{
#define _(sym,str) IP6_LOCAL_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_local_hop_by_hop_error
#undef _
    IP6_LOCAL_HOP_BY_HOP_N_ERROR,
} ip6_local_hop_by_hop_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ip6_local_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_local_hop_by_hop_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  IP6_LOCAL_HOP_BY_HOP_NEXT_DROP,
  IP6_LOCAL_HOP_BY_HOP_N_NEXT,
} ip6_local_hop_by_hop_next_t;

always_inline uword
ip6_local_hop_by_hop_inline (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame,
			     int is_trace)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 ok = 0;
  u32 unknown_proto_error = node->errors[IP6_LOCAL_HOP_BY_HOP_ERROR_UNKNOWN];
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  /* Note: there is only one of these */
  ip6_local_hop_by_hop_runtime_t *rt = hm->ip6_local_hbh_runtime;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      ip6_header_t *ip0, *ip1, *ip2, *ip3;
      u8 *hbh0, *hbh1, *hbh2, *hbh3;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_header (b[6], STORE);
	  vlib_prefetch_buffer_header (b[7], STORE);
	  CLIB_PREFETCH (b[4]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[5]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[6]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[7]->data, CLIB_CACHE_LINE_BYTES, STORE);
	}

      /*
       * Leave current_data pointing at the IP header.
       * It's reasonably likely that any registered handler
       * will want to know where to find the ip6 header.
       */
      ip0 = vlib_buffer_get_current (b[0]);
      ip1 = vlib_buffer_get_current (b[1]);
      ip2 = vlib_buffer_get_current (b[2]);
      ip3 = vlib_buffer_get_current (b[3]);

      /* Look at hop-by-hop header */
      hbh0 = ip6_next_header (ip0);
      hbh1 = ip6_next_header (ip1);
      hbh2 = ip6_next_header (ip2);
      hbh3 = ip6_next_header (ip3);

      /*
       * ... to find the next header type and see if we
       * have a handler for it...
       */
      next[0] = rt->next_index_by_protocol[*hbh0];
      next[1] = rt->next_index_by_protocol[*hbh1];
      next[2] = rt->next_index_by_protocol[*hbh2];
      next[3] = rt->next_index_by_protocol[*hbh3];

      b[0]->error = unknown_proto_error;
      b[1]->error = unknown_proto_error;
      b[2]->error = unknown_proto_error;
      b[3]->error = unknown_proto_error;

      /* Account for non-drop pkts */
      ok += next[0] != 0;
      ok += next[1] != 0;
      ok += next[2] != 0;
      ok += next[3] != 0;

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ip6_local_hop_by_hop_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->protocol = *hbh0;
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ip6_local_hop_by_hop_trace_t *t =
		vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->next_index = next[1];
	      t->protocol = *hbh1;
	    }
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ip6_local_hop_by_hop_trace_t *t =
		vlib_add_trace (vm, node, b[2], sizeof (*t));
	      t->next_index = next[2];
	      t->protocol = *hbh2;
	    }
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ip6_local_hop_by_hop_trace_t *t =
		vlib_add_trace (vm, node, b[3], sizeof (*t));
	      t->next_index = next[3];
	      t->protocol = *hbh3;
	    }
	}

      b += 4;
      next += 4;
      n_left_from -= 4;
    }

  while (n_left_from > 0)
    {
      ip6_header_t *ip0;
      u8 *hbh0;

      ip0 = vlib_buffer_get_current (b[0]);

      hbh0 = ip6_next_header (ip0);

      next[0] = rt->next_index_by_protocol[*hbh0];

      b[0]->error = unknown_proto_error;
      ok += next[0] != 0;

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ip6_local_hop_by_hop_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->protocol = *hbh0;
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       IP6_LOCAL_HOP_BY_HOP_ERROR_OK, ok);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip6_local_hop_by_hop_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return ip6_local_hop_by_hop_inline (vm, node, frame, 1 /* is_trace */ );
  else
    return ip6_local_hop_by_hop_inline (vm, node, frame, 0 /* is_trace */ );
}

#ifndef CLIB_MARCH_VARIANT
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_local_hop_by_hop_node) =
{
  .name = "ip6-local-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_local_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ip6_local_hop_by_hop_error_strings),
  .error_strings = ip6_local_hop_by_hop_error_strings,

  .n_next_nodes = IP6_LOCAL_HOP_BY_HOP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes =
  {
    [IP6_LOCAL_HOP_BY_HOP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

clib_error_t *
show_ip6_hbh_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int i;
  u32 next_index;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  ip6_local_hop_by_hop_runtime_t *rt = hm->ip6_local_hbh_runtime;
  vlib_node_t *n = vlib_get_node (vm, ip6_local_hop_by_hop_node.index);

  vlib_cli_output (vm, "%-6s%s", "Proto", "Node Name");

  for (i = 0; i < ARRAY_LEN (rt->next_index_by_protocol); i++)
    {
      if ((next_index = rt->next_index_by_protocol[i]))
	{
	  u32 next_node_index = n->next_nodes[next_index];
	  vlib_node_t *next_n = vlib_get_node (vm, next_node_index);
	  vlib_cli_output (vm, "[%3d] %v", i, next_n->name);
	}
    }

  return 0;
}

/*?
 * Display the set of ip6 local hop-by-hop next protocol handler nodes
 *
 * @cliexpar
 * Display ip6 local hop-by-hop next protocol handler nodes
 * @cliexcmd{show ip6 hbh}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip6_hbh, static) = {
  .path = "show ip6 hbh",
  .short_help = "show ip6 hbh",
  .function = show_ip6_hbh_command_fn,
};
/* *INDENT-ON* */


#endif /* CLIB_MARCH_VARIANT */


#ifndef CLIB_MARCH_VARIANT
static clib_error_t *
ip6_hop_by_hop_ioam_init (vlib_main_t * vm)
{
  clib_error_t *error;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return (error);

  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main ();
  hm->unix_time_0 = (u32) time (0);	/* Store starting time */
  hm->vlib_time_0 = vlib_time_now (vm);
  hm->ioam_flag = IOAM_HBYH_MOD;
  clib_memset (hm->add_options, 0, sizeof (hm->add_options));
  clib_memset (hm->pop_options, 0, sizeof (hm->pop_options));
  clib_memset (hm->options_size, 0, sizeof (hm->options_size));

  vnet_classify_register_unformat_opaque_index_fn (unformat_opaque_ioam);
  hm->ip6_local_hbh_runtime = clib_mem_alloc_aligned
    (sizeof (ip6_local_hop_by_hop_runtime_t), CLIB_CACHE_LINE_BYTES);

  memset (hm->ip6_local_hbh_runtime, 0,
	  sizeof (ip6_local_hop_by_hop_runtime_t));

  ip6_register_protocol (IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
			 ip6_local_hop_by_hop_node.index);
  return (0);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ip6_hop_by_hop_ioam_init) =
{
  .runs_after = VLIB_INITS("ip_main_init", "ip6_lookup_init"),
};
/* *INDENT-ON* */

void
ip6_local_hop_by_hop_register_protocol (u32 protocol, u32 node_index)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  vlib_main_t *vm = hm->vlib_main;
  ip6_local_hop_by_hop_runtime_t *local_hbh_runtime
    = hm->ip6_local_hbh_runtime;
  u32 old_next_index;

  ASSERT (protocol < ARRAY_LEN (local_hbh_runtime->next_index_by_protocol));

  old_next_index = local_hbh_runtime->next_index_by_protocol[protocol];

  local_hbh_runtime->next_index_by_protocol[protocol] =
    vlib_node_add_next (vm, ip6_local_hop_by_hop_node.index, node_index);

  /* Someone will eventually do this. Trust me. */
  if (old_next_index &&
      (old_next_index != local_hbh_runtime->next_index_by_protocol[protocol]))
    clib_warning ("WARNING: replaced next index for protocol %d", protocol);
}

int
ip6_ioam_set_rewrite (u8 ** rwp, int has_trace_option,
		      int has_pot_option, int has_seqno_option)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  u8 *rewrite = NULL;
  u32 size, rnd_size;
  ip6_hop_by_hop_header_t *hbh;
  u8 *current;
  u8 *trace_data_size = NULL;
  u8 *pot_data_size = NULL;

  vec_free (*rwp);

  if (has_trace_option == 0 && has_pot_option == 0)
    return -1;

  /* Work out how much space we need */
  size = sizeof (ip6_hop_by_hop_header_t);

  //if (has_trace_option && hm->get_sizeof_options[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] != 0)
  if (has_trace_option
      && hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] != 0)
    {
      size += hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST];
    }
  if (has_pot_option
      && hm->add_options[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] != 0)
    {
      size += hm->options_size[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT];
    }

  if (has_seqno_option)
    {
      size += hm->options_size[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE];
    }

  /* Round to a multiple of 8 octets */
  rnd_size = (size + 7) & ~7;

  /* allocate it, zero-fill / pad by construction */
  vec_validate (rewrite, rnd_size - 1);

  hbh = (ip6_hop_by_hop_header_t *) rewrite;
  /* Length of header in 8 octet units, not incl first 8 octets */
  hbh->length = (rnd_size >> 3) - 1;
  current = (u8 *) (hbh + 1);

  if (has_trace_option
      && hm->add_options[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] != 0)
    {
      if (0 != (hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST]))
	{
	  trace_data_size =
	    &hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST];
	  if (0 ==
	      hm->add_options[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] (current,
								     trace_data_size))
	    current += *trace_data_size;
	}
    }
  if (has_pot_option
      && hm->add_options[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] != 0)
    {
      pot_data_size =
	&hm->options_size[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT];
      if (0 ==
	  hm->add_options[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] (current,
								  pot_data_size))
	current += *pot_data_size;
    }

  if (has_seqno_option &&
      (hm->add_options[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE] != 0))
    {
      if (0 == hm->add_options[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE] (current,
								   &
								   (hm->options_size
								    [HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE])))
	current += hm->options_size[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE];
    }

  *rwp = rewrite;
  return 0;
}

clib_error_t *
clear_ioam_rewrite_fn (void)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  vec_free (hm->rewrite);
  hm->rewrite = 0;
  hm->has_trace_option = 0;
  hm->has_pot_option = 0;
  hm->has_seqno_option = 0;
  hm->has_analyse_option = 0;
  if (hm->config_handler[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST])
    hm->config_handler[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] (NULL, 1);

  if (hm->config_handler[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT])
    hm->config_handler[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] (NULL, 1);

  if (hm->config_handler[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE])
    {
      hm->config_handler[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE] ((void *)
							     &hm->has_analyse_option,
							     1);
    }

  return 0;
}

clib_error_t *
clear_ioam_rewrite_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  return (clear_ioam_rewrite_fn ());
}

/*?
 * This command clears all the In-band OAM (iOAM) features enabled by
 * the '<em>set ioam rewrite</em>' command. Use '<em>show ioam summary</em>' to
 * verify the configured settings cleared.
 *
 * @cliexpar
 * Example of how to clear iOAM features:
 * @cliexcmd{clear ioam rewrite}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_clear_ioam_rewrite_cmd, static) = {
  .path = "clear ioam rewrite",
  .short_help = "clear ioam rewrite",
  .function = clear_ioam_rewrite_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
ip6_ioam_enable (int has_trace_option, int has_pot_option,
		 int has_seqno_option, int has_analyse_option)
{
  int rv;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  rv = ip6_ioam_set_rewrite (&hm->rewrite, has_trace_option,
			     has_pot_option, has_seqno_option);

  switch (rv)
    {
    case 0:
      if (has_trace_option)
	{
	  hm->has_trace_option = has_trace_option;
	  if (hm->config_handler[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST])
	    hm->config_handler[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] (NULL,
								      0);
	}

      if (has_pot_option)
	{
	  hm->has_pot_option = has_pot_option;
	  if (hm->config_handler[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT])
	    hm->config_handler[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] (NULL,
								       0);
	}
      hm->has_analyse_option = has_analyse_option;
      if (has_seqno_option)
	{
	  hm->has_seqno_option = has_seqno_option;
	  if (hm->config_handler[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE])
	    {
	      hm->config_handler[HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE] ((void *)
								     &has_analyse_option,
								     0);
	    }
	}
      break;

    default:
      return clib_error_return_code (0, rv, 0,
				     "ip6_ioam_set_rewrite returned %d", rv);
    }

  return 0;
}


static clib_error_t *
ip6_set_ioam_rewrite_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  int has_trace_option = 0;
  int has_pot_option = 0;
  int has_seqno_option = 0;
  int has_analyse_option = 0;
  clib_error_t *rv = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace"))
	has_trace_option = 1;
      else if (unformat (input, "pot"))
	has_pot_option = 1;
      else if (unformat (input, "seqno"))
	has_seqno_option = 1;
      else if (unformat (input, "analyse"))
	has_analyse_option = 1;
      else
	break;
    }


  rv = ip6_ioam_enable (has_trace_option, has_pot_option,
			has_seqno_option, has_analyse_option);

  return rv;
}

/*?
 * This command is used to enable In-band OAM (iOAM) features on IPv6.
 * '<em>trace</em>' is used to enable iOAM trace feature. '<em>pot</em>' is used to
 * enable the Proof Of Transit feature. '<em>ppc</em>' is used to indicate the
 * Per Packet Counter feature for Edge to Edge processing. '<em>ppc</em>' is
 * used to indicate if this node is an '<em>encap</em>' node (iOAM edge node
 * where packet enters iOAM domain), a '<em>decap</em>' node (iOAM edge node
 * where packet leaves iOAM domain) or '<em>none</em>' (iOAM node where packet
 * is in-transit through the iOAM domain). '<em>ppc</em>' can only be set if
 * '<em>trace</em>' or '<em>pot</em>' is enabled.
 *
 * Use '<em>clear ioam rewrite</em>' to disable all features enabled by this
 * command. Use '<em>show ioam summary</em>' to verify the configured settings.
 *
 * @cliexpar
 * Example of how to enable trace and pot with ppc set to encap:
 * @cliexcmd{set ioam rewrite trace pot ppc encap}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_set_ioam_rewrite_cmd, static) = {
  .path = "set ioam rewrite",
  .short_help = "set ioam [trace] [pot] [seqno] [analyse]",
  .function = ip6_set_ioam_rewrite_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ip6_show_ioam_summary_cmd_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  u8 *s = 0;


  if (!is_zero_ip6_address (&hm->adj))
    {
      s = format (s, "              REWRITE FLOW CONFIGS - \n");
      s = format (s, "               Destination Address : %U\n",
		  format_ip6_address, &hm->adj, sizeof (ip6_address_t));
      s =
	format (s, "                    Flow operation : %d (%s)\n",
		hm->ioam_flag,
		(hm->ioam_flag ==
		 IOAM_HBYH_ADD) ? "Add" : ((hm->ioam_flag ==
					    IOAM_HBYH_MOD) ? "Mod" : "Pop"));
    }
  else
    {
      s = format (s, "              REWRITE FLOW CONFIGS - Not configured\n");
    }


  s = format (s, "                        TRACE OPTION - %d (%s)\n",
	      hm->has_trace_option,
	      (hm->has_trace_option ? "Enabled" : "Disabled"));
  if (hm->has_trace_option)
    s =
      format (s,
	      "Try 'show ioam trace and show ioam-trace profile' for more information\n");


  s = format (s, "                        POT OPTION - %d (%s)\n",
	      hm->has_pot_option,
	      (hm->has_pot_option ? "Enabled" : "Disabled"));
  if (hm->has_pot_option)
    s =
      format (s,
	      "Try 'show ioam pot and show pot profile' for more information\n");

  s = format (s, "         EDGE TO EDGE - SeqNo OPTION - %d (%s)\n",
	      hm->has_seqno_option,
	      hm->has_seqno_option ? "Enabled" : "Disabled");
  if (hm->has_seqno_option)
    s = format (s, "Try 'show ioam e2e' for more information\n");

  s = format (s, "         iOAM Analyse OPTION - %d (%s)\n",
	      hm->has_analyse_option,
	      hm->has_analyse_option ? "Enabled" : "Disabled");

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/*?
 * This command displays the current configuration data for In-band
 * OAM (iOAM).
 *
 * @cliexpar
 * Example to show the iOAM configuration:
 * @cliexstart{show ioam summary}
 *               REWRITE FLOW CONFIGS -
 *                Destination Address : ff02::1
 *                     Flow operation : 2 (Pop)
 *                         TRACE OPTION - 1 (Enabled)
 * Try 'show ioam trace and show ioam-trace profile' for more information
 *                         POT OPTION - 1 (Enabled)
 * Try 'show ioam pot and show pot profile' for more information
 *          EDGE TO EDGE - PPC OPTION - 1 (Encap)
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_show_ioam_run_cmd, static) = {
  .path = "show ioam summary",
  .short_help = "show ioam summary",
  .function = ip6_show_ioam_summary_cmd_fn,
};
/* *INDENT-ON* */

void
vnet_register_ioam_end_of_path_callback (void *cb)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  hm->ioam_end_of_path_cb = cb;
}

#endif /* CLIB_MARCH_VARIANT */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
