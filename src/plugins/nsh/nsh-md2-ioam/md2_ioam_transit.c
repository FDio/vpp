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
#include <vnet/udp/udp.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_packet.h>
#include <nsh/nsh.h>
#include <nsh/nsh_packet.h>
#include <nsh/nsh-md2-ioam/nsh_md2_ioam.h>
#include <nsh/nsh-md2-ioam/nsh_md2_ioam_util.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>

/* Statistics (not really errors) */
#define foreach_nsh_md2_ioam_encap_transit_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char *nsh_md2_ioam_encap_transit_error_strings[] = {
#define _(sym,string) string,
  foreach_nsh_md2_ioam_encap_transit_error
#undef _
};

typedef enum
{
#define _(sym,str) NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_ERROR_##sym,
  foreach_nsh_md2_ioam_encap_transit_error
#undef _
    NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_N_ERROR,
} nsh_md2_ioam_encap_transit_error_t;

typedef enum
{
  NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_NEXT_OUTPUT,
  NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_NEXT_DROP,
  NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_N_NEXT
} nsh_md2_ioam_encap_transit_next_t;


/* *INDENT-OFF* */
VNET_FEATURE_INIT (nsh_md2_ioam_encap_transit, static) =
{
  .arc_name = "ip4-output",
  .node_name = "nsh-md2-ioam-encap-transit",
  .runs_before = VNET_FEATURES ("adj-midchain-tx"),
};
/* *INDENT-ON* */


static uword
nsh_md2_ioam_encap_transit (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);


      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_NEXT_OUTPUT;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  ip4_header_t *ip0;
	  u32 iph_offset = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  iph_offset = vnet_buffer (b0)->ip.save_rewrite_length;
	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0)
				  + iph_offset);

	  /* just forward non ipv4 packets */
	  if (PREDICT_FALSE
	      ((ip0->ip_version_and_header_length & 0xF0) == 0x40))
	    {
	      /* ipv4 packets */
	      udp_header_t *udp_hdr0 = (udp_header_t *) (ip0 + 1);
	      if (PREDICT_FALSE
		  ((ip0->protocol == IP_PROTOCOL_UDP) &&
		   (clib_net_to_host_u16 (udp_hdr0->dst_port) ==
		    UDP_DST_PORT_lisp_gpe)))
		{

		  /* Check the iOAM header */
		  lisp_gpe_header_t *lisp_gpe_hdr0 =
		    (lisp_gpe_header_t *) (udp_hdr0 + 1);
		  nsh_base_header_t *nsh_hdr =
		    (nsh_base_header_t *) (lisp_gpe_hdr0 + 1);

		  if (PREDICT_FALSE
		      (lisp_gpe_hdr0->next_protocol ==
		       LISP_GPE_NEXT_PROTO_NSH) && (nsh_hdr->md_type == 2))
		    {
		      uword *t = NULL;
		      nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
		      fib_prefix_t key4;
		      memset (&key4, 0, sizeof (key4));
		      key4.fp_proto = FIB_PROTOCOL_IP4;
		      key4.fp_addr.ip4.as_u32 = ip0->dst_address.as_u32;
		      t = hash_get_mem (hm->dst_by_ip4, &key4);
		      if (t)
			{
			  vlib_buffer_advance (b0,
					       (word) (sizeof
						       (ethernet_header_t)));
			  nsh_md2_ioam_encap_decap_ioam_v4_one_inline (vm,
								       node,
								       b0,
								       &next0,
								       NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_NEXT_DROP,
								       1
								       /* use_adj */
			    );
			  vlib_buffer_advance (b0,
					       -(word) (sizeof
							(ethernet_header_t)));
			}
		    }
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

extern u8 *format_nsh_node_map_trace (u8 * s, va_list * args);
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nsh_md2_ioam_encap_transit_node) = {
  .function = nsh_md2_ioam_encap_transit,
  .name = "nsh-md2-ioam-encap-transit",
  .vector_size = sizeof (u32),
  .format_trace = format_nsh_node_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nsh_md2_ioam_encap_transit_error_strings),
  .error_strings = nsh_md2_ioam_encap_transit_error_strings,

  .n_next_nodes = NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_N_NEXT,

  .next_nodes = {
        [NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_NEXT_OUTPUT] = "interface-output",
        [NSH_MD2_IOAM_ENCAP_TRANSIT_IOAM_NEXT_DROP] = "error-drop",
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
