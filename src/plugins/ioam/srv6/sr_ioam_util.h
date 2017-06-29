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
#ifndef __included_sr_ioam_util_h__
#define __included_sr_ioam_util_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/srv6/sr.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/ip/ip6_packet.h>

/*
 * Primary h-b-h handler trace support
 */
typedef struct
{
  u32 next_index;
  u32 trace_len;
  u8 option_data[256];
} ioam_trace_t;


typedef struct
{
  u32 tunnel_index;
  ioam_trace_t fmt_trace;
} sr_ioam_trace_t;


static u8 *
format_sr_ioam_trace (u8 * s, va_list * args)
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
sr_ioam_one_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_buffer_t * b0, u32 * next0, u32 drop_node_val)
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
		  if ((*hm->options[type0]) (b0, ip0, opt0) < 0)
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


  *next0 = (sr0->segments_left > 0) ? (*next0) : hm->decap_sr_next_override;

  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      sr_ioam_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
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
  return;
}


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
