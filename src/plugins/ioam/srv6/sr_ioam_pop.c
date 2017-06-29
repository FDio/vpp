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
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <ioam/srv6/sr_ioam.h>
#include <ioam/srv6/sr_ioam_util.h>
#include <ioam/srv6/sr_ioam_trace.h>


/* Statistics (not really errors) */
#define foreach_sr_pop_ioam_error    \
_(POPPED, "good packets popped")

static char *sr_pop_ioam_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_pop_ioam_error
#undef _
};

typedef enum
{
#define _(sym,str) SR_POP_IOAM_ERROR_##sym,
  foreach_sr_pop_ioam_error
#undef _
    SR_POP_IOAM_N_ERROR,
} sr_pop_ioam_error_t;

typedef struct
{
  u32 tunnel_index;
  ioam_trace_t fmt_trace;
} sr_pop_ioam_trace_t;

typedef enum
{
  SR_IOAM_POP_NEXT_SR_INPUT,
  SR_IOAM_POP_N_NEXT,
} export_next_t;


u8 *
format_sr_pop_ioam_trace (u8 * s, va_list * args)
{

  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  sr_ioam_trace_t *t1 = va_arg (*args, sr_ioam_trace_t *);
  ioam_trace_t *t = &(t1->fmt_trace);
  ip6_sr_tlv_header_t *opt0, *limit0;
  ip6_sr_tlv_main_t *hm = &ip6_sr_tlv_main;
  ip6_sr_header_t *sr0;

  u8 type0;


  sr0 = (ip6_sr_header_t *) t->option_data;
  s = format (s, "SR-IOAM: next_index %d len %d traced %d",
	      t->next_index, sr0->length, t->trace_len);

  opt0 = (ip6_sr_tlv_header_t *) ((u8 *) sr0 +
				  sizeof (ip6_sr_header_t) +
				  (sr0->first_segment +
				   1) * sizeof (ip6_address_t));

  limit0 = (ip6_sr_tlv_header_t *) ((u8 *) sr0 + (t->trace_len << 3));


  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad, just stop */
	  opt0 = (ip6_sr_tlv_header_t *) ((u8 *) opt0) + 1;
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
	}
      opt0 =
	(ip6_sr_tlv_header_t *) (((u8 *) opt0) + opt0->length +
				 sizeof (ip6_sr_tlv_header_t));

      break;
    }

  s = format (s, "SR-IOAM: tunnel %d", t1->tunnel_index);
  return s;

}

always_inline void
sr_ioam_pop (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_buffer_t * b0)
{
  ip6_ext_header_t *prev0;
  ip6_sr_header_t *sr0;
  ip6_header_t *ip0;
  u32 iph_offset = 0;
  u32 new_l0, sr_len;
  u64 *copy_dst0, *copy_src0;
  int i;

  iph_offset = vnet_buffer (b0)->ip.save_rewrite_length;
  ip0 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) + iph_offset);

  ip6_ext_header_find_t (ip0, prev0, sr0, IP_PROTOCOL_IPV6_ROUTE);

  /* Pop the iOAM data */
  sr_len = ip6_ext_header_len (sr0);
  vlib_buffer_advance (b0, sr_len);
  new_l0 = clib_net_to_host_u16 (ip0->payload_length) - sr_len;
  ip0->payload_length = clib_host_to_net_u16 (new_l0);
  copy_src0 = (u64 *) ip0;
  copy_dst0 = copy_src0 + (sr0->length + 1);
  u32 copy_len_u64s0 = 0;

  /* number of 8 octet units to copy
   * By default in absence of extension headers it is equal to length of ip6 header
   * With extension headers it number of 8 octet units of ext headers preceding
   * SR header
   */
  copy_len_u64s0 = (((u8 *) sr0 - (u8 *) ip0) - sizeof (ip6_header_t)) >> 3;
  copy_dst0[4 + copy_len_u64s0] = copy_src0[4 + copy_len_u64s0];
  copy_dst0[3 + copy_len_u64s0] = copy_src0[3 + copy_len_u64s0];
  copy_dst0[2 + copy_len_u64s0] = copy_src0[2 + copy_len_u64s0];
  copy_dst0[1 + copy_len_u64s0] = copy_src0[1 + copy_len_u64s0];
  copy_dst0[0 + copy_len_u64s0] = copy_src0[0 + copy_len_u64s0];

  for (i = copy_len_u64s0 - 1; i >= 0; i--)
    {
      copy_dst0[i] = copy_src0[i];
    }

  return;
}



always_inline void
sr_pop_ioam_one_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			ip6_sr_tlv_main_t * ngm,
			vlib_buffer_t * b0, u32 * next0)
{
  ip6_sr_tlv_header_t *opt0 = NULL;
  ip6_sr_tlv_header_t *limit0 = NULL;
  ip6_sr_tlv_main_t *hm = &ip6_sr_tlv_main;
  ip6_ext_header_t *prev0;
  ip6_sr_header_t *sr0;
  ip6_header_t *ip0;
  u8 type0 = 0;
  u32 iph_offset = 0;

  iph_offset = vnet_buffer (b0)->ip.save_rewrite_length;
  ip0 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) + iph_offset);

  ip6_ext_header_find_t (ip0, prev0, sr0, IP_PROTOCOL_IPV6_ROUTE);

  if (PREDICT_FALSE (((sr0->first_segment + 1) * sizeof (ip6_address_t)) <
		     ip6_ext_header_len (sr0)))
    {
      /* Do TLV processing for SRH */
      opt0 =
	(ip6_sr_tlv_header_t *) ((u8 *) ip0 + sizeof (ip6_header_t) +
				 sizeof (ip6_sr_header_t) +
				 (sr0->first_segment +
				  1) * sizeof (ip6_address_t));

      limit0 = (ip6_sr_tlv_header_t *) ((u8 *) sr0 + (sr0->length << 3));

      while (opt0 < limit0)
	{
	  type0 = opt0->type;
	  switch (type0)
	    {
	    case 0:		/* Pad1 */
	      opt0 = (ip6_sr_tlv_header_t *) ((u8 *) opt0) + 1;
	      continue;
	    case 1:		/* PadN */
	      break;
	    default:
	      if (hm->options[type0])
		{
		  if ((*hm->pop_options[type0]) (b0, ip0, opt0) < 0)
		    {
		      b0->error = -1;
		      return;
		    }
		}
	      else
		{
		  b0->error = -1;
		  return;
		}
	    }
	  opt0 =
	    (ip6_sr_tlv_header_t *) (((u8 *) opt0) + opt0->length +
				     sizeof (ip6_sr_tlv_header_t));
	}
    }


  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      sr_pop_ioam_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
      u32 trace_len = sr0->length << 3;
      t->fmt_trace.next_index = *next0;
      /* Capture the ioam option verbatim */
      trace_len =
	trace_len <
	ARRAY_LEN (t->fmt_trace.
		   option_data) ? trace_len : ARRAY_LEN (t->fmt_trace.
							 option_data);
      t->fmt_trace.trace_len = trace_len;
      clib_memcpy (&(t->fmt_trace.option_data), sr0, trace_len);
    }
  /* Remove the iOAM header inside the VxLAN-GPE header */
  sr_ioam_pop (vm, node, b0);
  return;
}

always_inline void
sr_pop_ioam_two_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			ip6_sr_tlv_main_t * ngm,
			vlib_buffer_t * b0, vlib_buffer_t * b1,
			u32 * next0, u32 * next1)
{

  sr_pop_ioam_one_inline (vm, node, ngm, b0, next0);
  sr_pop_ioam_one_inline (vm, node, ngm, b1, next1);
}



static uword
_sr_pop_ioam (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame, u8 is_ipv6)
{
  u32 n_left_from, next_index, *from, *to_next;
  ip6_sr_tlv_main_t *ngm = &ip6_sr_tlv_main;

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
	  next0 = next1 = SR_IOAM_POP_NEXT_SR_INPUT;

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

	  sr_pop_ioam_two_inline (vm, node, ngm, b0, b1, &next0, &next1);


	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SR_IOAM_POP_NEXT_SR_INPUT;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sr_pop_ioam_one_inline (vm, node, ngm, b0, &next0);


	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}


static uword
sr_pop_ioam (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return _sr_pop_ioam (vm, node, from_frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_pop_ioam_node) = {
  .function = sr_pop_ioam,
  .name = "sr-pop-ioam",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_ioam_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(sr_pop_ioam_error_strings),
  .error_strings = sr_pop_ioam_error_strings,
  .n_next_nodes = SR_IOAM_POP_N_NEXT,
  .next_nodes = 
  {[SR_IOAM_POP_NEXT_SR_INPUT] = "ip6-lookup"},
};
/* *INDENT-ON* */



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
