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
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h>

/* Statistics (not really errors) */
#define foreach_vxlan_gpe_pop_ioam_v4_error    \
_(POPPED, "good packets popped")

static char *vxlan_gpe_pop_ioam_v4_error_strings[] = {
#define _(sym,string) string,
  foreach_vxlan_gpe_pop_ioam_v4_error
#undef _
};

typedef enum
{
#define _(sym,str) VXLAN_GPE_POP_IOAM_V4_ERROR_##sym,
  foreach_vxlan_gpe_pop_ioam_v4_error
#undef _
    VXLAN_GPE_POP_IOAM_V4_N_ERROR,
} vxlan_gpe_pop_ioam_v4_error_t;

typedef struct
{
  ioam_trace_t fmt_trace;
} vxlan_gpe_pop_ioam_v4_trace_t;


u8 *
format_vxlan_gpe_pop_ioam_v4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_gpe_pop_ioam_v4_trace_t *t1
    = va_arg (*args, vxlan_gpe_pop_ioam_v4_trace_t *);
  ioam_trace_t *t = &(t1->fmt_trace);
  vxlan_gpe_ioam_option_t *fmt_trace0;
  vxlan_gpe_ioam_option_t *opt0, *limit0;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  u8 type0;

  fmt_trace0 = (vxlan_gpe_ioam_option_t *) t->option_data;

  s = format (s, "VXLAN_GPE_IOAM_POP: next_index %d len %d traced %d",
	      t->next_index, fmt_trace0->length, t->trace_len);

  opt0 = (vxlan_gpe_ioam_option_t *) (fmt_trace0 + 1);
  limit0 = (vxlan_gpe_ioam_option_t *) ((u8 *) fmt_trace0) + t->trace_len;

  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad, just stop */
	  opt0 = (vxlan_gpe_ioam_option_t *) ((u8 *) opt0) + 1;
	  break;

	default:
	  if (hm->trace[type0])
	    {
	      s = (*hm->trace[type0]) (s, opt0);
	    }
	  else
	    {
	      s =
		format (s, "\n    unrecognized option %d length %d", type0,
			opt0->length);
	    }
	  opt0 =
	    (vxlan_gpe_ioam_option_t *) (((u8 *) opt0) + opt0->length +
					 sizeof (vxlan_gpe_ioam_option_t));
	  break;
	}
    }

  return s;
}

always_inline void
vxlan_gpe_ioam_pop_v4 (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_buffer_t * b0)
{
  ip4_header_t *ip0;
  udp_header_t *udp_hdr0;
  vxlan_gpe_header_t *gpe_hdr0;
  vxlan_gpe_ioam_hdr_t *gpe_ioam0;

  ip0 = vlib_buffer_get_current (b0);

  udp_hdr0 = (udp_header_t *) (ip0 + 1);
  gpe_hdr0 = (vxlan_gpe_header_t *) (udp_hdr0 + 1);
  gpe_ioam0 = (vxlan_gpe_ioam_hdr_t *) (gpe_hdr0 + 1);

  /* Pop the iOAM data */
  vlib_buffer_advance (b0,
		       (word) (sizeof (udp_header_t) +
			       sizeof (ip4_header_t) +
			       sizeof (vxlan_gpe_header_t) +
			       gpe_ioam0->length));

  return;
}



always_inline void
vxlan_gpe_pop_ioam_v4_one_inline (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vxlan_gpe_main_t * ngm,
				  vlib_buffer_t * b0, u32 * next0)
{
  CLIB_UNUSED (ip4_header_t * ip0);
  CLIB_UNUSED (udp_header_t * udp_hdr0);
  CLIB_UNUSED (vxlan_gpe_header_t * gpe_hdr0);
  CLIB_UNUSED (vxlan_gpe_ioam_hdr_t * gpe_ioam0);
  CLIB_UNUSED (vxlan_gpe_ioam_option_t * opt0);
  CLIB_UNUSED (vxlan_gpe_ioam_option_t * limit0);
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;


  /* Pop the iOAM header */
  ip0 = vlib_buffer_get_current (b0);
  udp_hdr0 = (udp_header_t *) (ip0 + 1);
  gpe_hdr0 = (vxlan_gpe_header_t *) (udp_hdr0 + 1);
  gpe_ioam0 = (vxlan_gpe_ioam_hdr_t *) (gpe_hdr0 + 1);
  opt0 = (vxlan_gpe_ioam_option_t *) (gpe_ioam0 + 1);
  limit0 = (vxlan_gpe_ioam_option_t *) ((u8 *) gpe_ioam0 + gpe_ioam0->length);

  /*
   * Basic validity checks
   */
  if (gpe_ioam0->length > clib_net_to_host_u16 (ip0->length))
    {
      *next0 = VXLAN_GPE_INPUT_NEXT_DROP;
      goto trace00;
    }

  /* Scan the set of h-b-h options, process ones that we understand */
  while (opt0 < limit0)
    {
      u8 type0;
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad1 */
	  opt0 = (vxlan_gpe_ioam_option_t *) ((u8 *) opt0) + 1;
	  continue;
	case 1:		/* PadN */
	  break;
	default:
	  if (hm->pop_options[type0])
	    {
	      if ((*hm->pop_options[type0]) (ip0, opt0) < 0)
		{
		  *next0 = VXLAN_GPE_INPUT_NEXT_DROP;
		  goto trace00;
		}
	    }
	  break;
	}
      opt0 =
	(vxlan_gpe_ioam_option_t *) (((u8 *) opt0) + opt0->length +
				     sizeof (vxlan_gpe_ioam_hdr_t));
    }


  *next0 =
    (gpe_ioam0->protocol < VXLAN_GPE_PROTOCOL_MAX) ?
    ngm->
    decap_next_node_list[gpe_ioam0->protocol] : VXLAN_GPE_INPUT_NEXT_DROP;

trace00:
  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      vxlan_gpe_pop_ioam_v4_trace_t *t =
	vlib_add_trace (vm, node, b0, sizeof (*t));
      u32 trace_len = gpe_ioam0->length;
      t->fmt_trace.next_index = *next0;
      /* Capture the h-b-h option verbatim */
      trace_len =
	trace_len <
	ARRAY_LEN (t->fmt_trace.
		   option_data) ? trace_len : ARRAY_LEN (t->fmt_trace.
							 option_data);
      t->fmt_trace.trace_len = trace_len;
      clib_memcpy (&(t->fmt_trace.option_data), gpe_ioam0, trace_len);
    }

  /* Remove the iOAM header inside the VxLAN-GPE header */
  vxlan_gpe_ioam_pop_v4 (vm, node, b0);
  return;
}

always_inline void
vxlan_gpe_pop_ioam_v4_two_inline (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vxlan_gpe_main_t * ngm,
				  vlib_buffer_t * b0, vlib_buffer_t * b1,
				  u32 * next0, u32 * next1)
{

  vxlan_gpe_pop_ioam_v4_one_inline (vm, node, ngm, b0, next0);
  vxlan_gpe_pop_ioam_v4_one_inline (vm, node, ngm, b1, next1);
}



static uword
vxlan_gpe_pop_ioam (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame, u8 is_ipv6)
{
  u32 n_left_from, next_index, *from, *to_next;
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;

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

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
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

	  vxlan_gpe_pop_ioam_v4_two_inline (vm, node, ngm, b0, b1, &next0,
					    &next1);


	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vxlan_gpe_pop_ioam_v4_one_inline (vm, node, ngm, b0, &next0);


	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}


static uword
vxlan_gpe_pop_ioam_v4 (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return vxlan_gpe_pop_ioam (vm, node, from_frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vxlan_gpe_pop_ioam_v4_node) = {
  .function = vxlan_gpe_pop_ioam_v4,
  .name = "vxlan-gpe-pop-ioam-v4",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_gpe_pop_ioam_v4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vxlan_gpe_pop_ioam_v4_error_strings),
  .error_strings = vxlan_gpe_pop_ioam_v4_error_strings,

  .n_next_nodes = VXLAN_GPE_INPUT_N_NEXT,

  .next_nodes = {
#define _(s,n) [VXLAN_GPE_INPUT_NEXT_##s] = n,
    foreach_vxlan_gpe_input_next
#undef _
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
