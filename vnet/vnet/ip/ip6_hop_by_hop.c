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

char *ppc_state[] = { "None", "Encap", "Decap" };

ip6_hop_by_hop_ioam_main_t ip6_hop_by_hop_ioam_main;

#define foreach_ip6_hbyh_ioam_input_next	\
  _(IP6_REWRITE, "ip6-rewrite")			\
  _(IP6_LOOKUP, "ip6-lookup")			\
  _(DROP, "error-drop")

typedef enum
{
#define _(s,n) IP6_HBYH_IOAM_INPUT_NEXT_##s,
  foreach_ip6_hbyh_ioam_input_next
#undef _
    IP6_HBYH_IOAM_INPUT_N_NEXT,
} ip6_hbyh_ioam_input_next_t;



/* The main h-b-h tracer will be invoked, no need to do much here */
int
ip6_hbh_add_register_option (u8 option,
			     u8 size,
			     int rewrite_options (u8 * rewrite_string,
						  u8 * rewrite_size))
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT (option < ARRAY_LEN (hm->add_options));

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

  ASSERT (option < ARRAY_LEN (hm->add_options));

  /* Not registered */
  if (!hm->add_options[option])
    return (-1);

  hm->add_options[option] = NULL;
  hm->options_size[option] = 0;
  return (0);
}

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

vlib_node_registration_t ip6_add_hop_by_hop_node;

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

static uword
ip6_add_hop_by_hop_node_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
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
	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);

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
	  clib_memcpy (hbh0, rewrite, rewrite_length);
	  clib_memcpy (hbh1, rewrite, rewrite_length);
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
	  clib_memcpy (hbh0, rewrite, rewrite_length);
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

VLIB_REGISTER_NODE (ip6_add_hop_by_hop_node) =	/* *INDENT-OFF* */
{
  .function = ip6_add_hop_by_hop_node_fn,.name =
    "ip6-add-hop-by-hop",.vector_size = sizeof (u32),.format_trace =
    format_ip6_add_hop_by_hop_trace,.type =
    VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (ip6_add_hop_by_hop_error_strings),.error_strings =
    ip6_add_hop_by_hop_error_strings,
    /* See ip/lookup.h */
    .n_next_nodes = IP6_HBYH_IOAM_INPUT_N_NEXT,.next_nodes =
  {
#define _(s,n) [IP6_HBYH_IOAM_INPUT_NEXT_##s] = n,
    foreach_ip6_hbyh_ioam_input_next
#undef _
  }
,};

/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_add_hop_by_hop_node,
			      ip6_add_hop_by_hop_node_fn)
/* The main h-b-h tracer was already invoked, no need to do much here */
     typedef struct
     {
       u32 next_index;
     } ip6_pop_hop_by_hop_trace_t;

/* packet trace format function */
     static u8 *format_ip6_pop_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_pop_hop_by_hop_trace_t *t =
    va_arg (*args, ip6_pop_hop_by_hop_trace_t *);

  s = format (s, "IP6_POP_HOP_BY_HOP: next index %d", t->next_index);
  return s;
}

int
ip6_hbh_pop_register_option (u8 option,
			     int options (ip6_header_t * ip,
					  ip6_hop_by_hop_option_t * opt))
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  ASSERT (option < ARRAY_LEN (hm->pop_options));

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

  ASSERT (option < ARRAY_LEN (hm->pop_options));

  /* Not registered */
  if (!hm->pop_options[option])
    return (-1);

  hm->pop_options[option] = NULL;
  return (0);
}

vlib_node_registration_t ip6_pop_hop_by_hop_node;

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
				ip6_hop_by_hop_header_t * hbh0)
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
	      if ((*hm->pop_options[type0]) (ip0, opt0) < 0)
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

static uword
ip6_pop_hop_by_hop_node_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
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
	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	  adj_index1 = vnet_buffer (b1)->ip.adj_index[VLIB_TX];
	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);

	  next0 = adj0->lookup_next_index;
	  next1 = adj1->lookup_next_index;

	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  hbh1 = (ip6_hop_by_hop_header_t *) (ip1 + 1);

	  ioam_pop_hop_by_hop_processing (vm, ip0, hbh0);
	  ioam_pop_hop_by_hop_processing (vm, ip1, hbh1);

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
	  adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	  adj0 = ip_get_adjacency (lm, adj_index0);

	  /* Default use the next_index from the adjacency. */
	  next0 = adj0->lookup_next_index;

	  /* Perfectly normal to end up here w/ out h-b-h header */
	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);

	  /* TODO:Temporarily doing it here.. do this validation in end_of_path_cb */
	  ioam_pop_hop_by_hop_processing (vm, ip0, hbh0);
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
  .function = ip6_pop_hop_by_hop_node_fn,.name =
    "ip6-pop-hop-by-hop",.vector_size = sizeof (u32),.format_trace =
    format_ip6_pop_hop_by_hop_trace,.type =
    VLIB_NODE_TYPE_INTERNAL,.sibling_of = "ip6-lookup",.n_errors =
    ARRAY_LEN (ip6_pop_hop_by_hop_error_strings),.error_strings =
    ip6_pop_hop_by_hop_error_strings,
    /* See ip/lookup.h */
.n_next_nodes = 0,};

/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_pop_hop_by_hop_node,
			      ip6_pop_hop_by_hop_node_fn)
     static clib_error_t *ip6_hop_by_hop_ioam_init (vlib_main_t * vm)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main ();
  hm->unix_time_0 = (u32) time (0);	/* Store starting time */
  hm->vlib_time_0 = vlib_time_now (vm);
  hm->ioam_flag = IOAM_HBYH_MOD;
  memset (hm->add_options, 0, sizeof (hm->add_options));
  memset (hm->pop_options, 0, sizeof (hm->pop_options));
  memset (hm->options_size, 0, sizeof (hm->options_size));

  return (0);
}

VLIB_INIT_FUNCTION (ip6_hop_by_hop_ioam_init);

int
ip6_ioam_set_rewrite (u8 ** rwp, int has_trace_option,
		      int has_pot_option, int has_ppc_option)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  u8 *rewrite = 0;
  u32 size, rnd_size;
  ip6_hop_by_hop_header_t *hbh;
  u8 *current;
  u8 trace_data_size = 0;
  u8 pot_data_size = 0;

  vec_free (*rwp);

  if (has_trace_option == 0 && has_pot_option == 0)
    return -1;

  /* Work out how much space we need */
  size = sizeof (ip6_hop_by_hop_header_t);

  //if (has_trace_option && hm->get_sizeof_options[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] != 0)
  if (has_trace_option
      && hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] != 0)
    {
      size += sizeof (ip6_hop_by_hop_option_t);
      size += hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST];
    }
  if (has_pot_option
      && hm->add_options[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] != 0)
    {
      size += sizeof (ip6_hop_by_hop_option_t);
      size += hm->options_size[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT];
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
	    hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST];
	  if (0 ==
	      hm->add_options[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] (current,
								     &trace_data_size))
	    current += hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST];
	}
    }
  if (has_pot_option
      && hm->add_options[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] != 0)
    {
      pot_data_size = hm->options_size[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT];
      if (0 ==
	  hm->add_options[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] (current,
								  &pot_data_size))
	current +=
	  sizeof (hm->options_size[HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT]);
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
  hm->has_ppc_option = 0;

  return 0;
}

clib_error_t *
clear_ioam_rewrite_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  return (clear_ioam_rewrite_fn ());
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_clear_ioam_rewrite_cmd, static) =
{
.path = "clear ioam rewrite",.short_help = "clear ioam rewrite",.function =
    clear_ioam_rewrite_command_fn,};
/* *INDENT-ON* */

clib_error_t *
ip6_ioam_enable (int has_trace_option, int has_pot_option, int has_ppc_option)
{
  int rv;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  rv = ip6_ioam_set_rewrite (&hm->rewrite, has_trace_option,
			     has_pot_option, has_ppc_option);

  switch (rv)
    {
    case 0:
      hm->has_trace_option = has_trace_option;
      hm->has_pot_option = has_pot_option;
      hm->has_ppc_option = has_ppc_option;
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
  int has_ppc_option = 0;
  clib_error_t *rv = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace"))
	has_trace_option = 1;
      else if (unformat (input, "pot"))
	has_pot_option = 1;
      else if (unformat (input, "ppc encap"))
	has_ppc_option = PPC_ENCAP;
      else if (unformat (input, "ppc decap"))
	has_ppc_option = PPC_DECAP;
      else if (unformat (input, "ppc none"))
	has_ppc_option = PPC_NONE;
      else
	break;
    }


  rv = ip6_ioam_enable (has_trace_option, has_pot_option, has_ppc_option);

  return rv;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_set_ioam_rewrite_cmd, static) =
{
.path = "set ioam rewrite",.short_help =
    "set ioam [trace] [pot] [ppc <encap|decap>]",.function =
    ip6_set_ioam_rewrite_command_fn,};
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

  s = format (s, "         EDGE TO EDGE - PPC OPTION - %d (%s)\n",
	      hm->has_ppc_option, ppc_state[hm->has_ppc_option]);
  if (hm->has_ppc_option)
    s = format (s, "Try 'show ioam ppc' for more information\n");

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_show_ioam_run_cmd, static) =
{
.path = "show ioam summary",.short_help =
    "Summary of IOAM configuration",.function =
    ip6_show_ioam_summary_cmd_fn,};
/* *INDENT-ON* */

int
ip6_ioam_set_destination (ip6_address_t * addr, u32 mask_width, u32 vrf_id,
			  int is_add, int is_pop, int is_none)
{
  ip6_main_t *im = &ip6_main;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_adjacency_t *adj;
  u32 fib_index;
  u32 len, adj_index;
  int i, rv;
  uword *p;
  BVT (clib_bihash_kv) kv, value;

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
      ip6_address_t *mask = &im->fib_masks[dst_address_length];

      if (dst_address_length != mask_width)
	continue;

      kv.key[0] = addr->as_u64[0] & mask->as_u64[0];
      kv.key[1] = addr->as_u64[1] & mask->as_u64[1];
      kv.key[2] = ((u64) ((fib_index)) << 32) | dst_address_length;

      rv =
	BV (clib_bihash_search_inline_2) (&im->ip6_lookup_table, &kv, &value);
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
    adj->lookup_next_index =
      (ip_lookup_next_t) IP6_LOOKUP_NEXT_ADD_HOP_BY_HOP;

  if (is_pop)
    adj->lookup_next_index =
      (ip_lookup_next_t) IP6_LOOKUP_NEXT_POP_HOP_BY_HOP;

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
      if (unformat (input, "%U/%d", unformat_ip6_address, &addr, &mask_width))
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
      return clib_error_return (0, "ip6_ioam_set_destination returned %d",
				rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_set_ioam_destination_cmd, static) =
{
.path = "set ioam destination",.short_help =
    "set ioam destination <ip6-address>/<width> add | pop | none",.function
    = ip6_set_ioam_destination_command_fn,};
/* *INDENT-ON* */


void
vnet_register_ioam_end_of_path_callback (void *cb)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  hm->ioam_end_of_path_cb = cb;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
