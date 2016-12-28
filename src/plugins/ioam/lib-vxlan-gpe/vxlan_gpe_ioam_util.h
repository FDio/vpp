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
#ifndef __included_vxlan_gpe_ioam_util_h__
#define __included_vxlan_gpe_ioam_util_h__

#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/ip.h>


typedef struct
{
  u32 tunnel_index;
  ioam_trace_t fmt_trace;
} vxlan_gpe_ioam_v4_trace_t;


static u8 *
format_vxlan_gpe_ioam_v4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_gpe_ioam_v4_trace_t *t1 = va_arg (*args, vxlan_gpe_ioam_v4_trace_t *);
  ioam_trace_t *t = &(t1->fmt_trace);
  vxlan_gpe_ioam_option_t *fmt_trace0;
  vxlan_gpe_ioam_option_t *opt0, *limit0;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  u8 type0;

  fmt_trace0 = (vxlan_gpe_ioam_option_t *) t->option_data;

  s = format (s, "VXLAN-GPE-IOAM: next_index %d len %d traced %d",
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

  s = format (s, "VXLAN-GPE-IOAM: tunnel %d", t1->tunnel_index);
  return s;
}


always_inline void
vxlan_gpe_encap_decap_ioam_v4_one_inline (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_buffer_t * b0,
					  u32 * next0, u32 drop_node_val,
					  u8 use_adj)
{
  ip4_header_t *ip0;
  udp_header_t *udp_hdr0;
  vxlan_gpe_header_t *gpe_hdr0;
  vxlan_gpe_ioam_hdr_t *gpe_ioam0;
  vxlan_gpe_ioam_option_t *opt0;
  vxlan_gpe_ioam_option_t *limit0;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  /* Populate the iOAM header */
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
      *next0 = drop_node_val;
      return;
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
	  if (hm->options[type0])
	    {
	      if ((*hm->options[type0]) (b0, opt0, 1 /* is_ipv4 */ ,
					 use_adj) < 0)
		{
		  *next0 = drop_node_val;
		  return;
		}
	    }
	  break;
	}
      opt0 =
	(vxlan_gpe_ioam_option_t *) (((u8 *) opt0) + opt0->length +
				     sizeof (vxlan_gpe_ioam_hdr_t));
    }


  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      vxlan_gpe_ioam_v4_trace_t *t =
	vlib_add_trace (vm, node, b0, sizeof (*t));
      u32 trace_len = gpe_ioam0->length;
      t->fmt_trace.next_index = *next0;
      /* Capture the ioam option verbatim */
      trace_len =
	trace_len <
	ARRAY_LEN (t->fmt_trace.
		   option_data) ? trace_len : ARRAY_LEN (t->fmt_trace.
							 option_data);
      t->fmt_trace.trace_len = trace_len;
      clib_memcpy (&(t->fmt_trace.option_data), gpe_ioam0, trace_len);
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
