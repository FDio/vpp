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
#ifndef __included_nsh_md2_ioam_util_h__
#define __included_nsh_md2_ioam_util_h__

#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_packet.h>
#include <vnet/ip/ip.h>
#include <nsh/nsh.h>
#include <nsh/nsh-md2-ioam/nsh_md2_ioam.h>
#include <nsh/nsh_packet.h>


extern nsh_option_map_t *nsh_md2_lookup_option (u16 class, u8 type);


typedef struct
{
  u8 trace_data[256];
} nsh_transit_trace_t;

always_inline void
nsh_md2_ioam_encap_decap_ioam_v4_one_inline (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_buffer_t * b0,
					     u32 * next0, u32 drop_node_val,
					     u8 use_adj)
{
  ip4_header_t *ip0;
  udp_header_t *udp_hdr0;
  lisp_gpe_header_t *lisp_gpe_hdr0;
  nsh_base_header_t *nsh_hdr;
  nsh_tlv_header_t *opt0;
  nsh_tlv_header_t *limit0;
  nsh_main_t *hm = &nsh_main;
  nsh_option_map_t *nsh_option;

  /* Populate the iOAM header */
  ip0 = vlib_buffer_get_current (b0);
  udp_hdr0 = (udp_header_t *) (ip0 + 1);
  lisp_gpe_hdr0 = (lisp_gpe_header_t *) (udp_hdr0 + 1);
  nsh_hdr = (nsh_base_header_t *) (lisp_gpe_hdr0 + 1);
  opt0 = (nsh_tlv_header_t *) (nsh_hdr + 1);
  limit0 =
    (nsh_tlv_header_t *) ((u8 *) opt0 + (nsh_hdr->length * 4) -
			  sizeof (nsh_base_header_t));

  /*
   * Basic validity checks
   */
  if ((nsh_hdr->length * 4) > clib_net_to_host_u16 (ip0->length))
    {
      *next0 = drop_node_val;
      return;
    }

  if (nsh_hdr->md_type != 2)
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
	  opt0 = (nsh_tlv_header_t *) ((u8 *) opt0) + 1;
	  continue;
	case 1:		/* PadN */
	  break;
	default:
	  nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
	  if ((nsh_option != NULL) && (hm->options[nsh_option->option_id]))
	    {
	      if ((*hm->options[nsh_option->option_id]) (b0, opt0) < 0)
		{
		  *next0 = drop_node_val;
		  return;
		}
	    }
	  break;
	}
      opt0 =
	(nsh_tlv_header_t *) (((u8 *) opt0) + opt0->length +
			      sizeof (nsh_tlv_header_t));
    }


  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
    {
      nsh_transit_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
      clib_memcpy_fast (&(tr->trace_data), nsh_hdr, (nsh_hdr->length * 4));
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
