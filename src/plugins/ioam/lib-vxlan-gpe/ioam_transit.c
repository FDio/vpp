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
#include <vnet/udp/udp.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam_packet.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam_util.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>

/* Statistics (not really errors) */
#define foreach_vxlan_gpe_transit_ioam_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char *vxlan_gpe_transit_ioam_error_strings[] = {
#define _(sym,string) string,
  foreach_vxlan_gpe_transit_ioam_error
#undef _
};

typedef enum
{
#define _(sym,str) VXLAN_GPE_TRANSIT_IOAM_ERROR_##sym,
  foreach_vxlan_gpe_transit_ioam_error
#undef _
    VXLAN_GPE_TRANSIT_IOAM_N_ERROR,
} vxlan_gpe_transit_ioam_error_t;

typedef enum
{
  VXLAN_GPE_TRANSIT_IOAM_NEXT_OUTPUT,
  VXLAN_GPE_TRANSIT_IOAM_NEXT_DROP,
  VXLAN_GPE_TRANSIT_IOAM_N_NEXT
} vxlan_gpe_transit_ioam_next_t;


/* *INDENT-OFF* */
VNET_FEATURE_INIT (vxlan_gpe_transit_ioam, static) =
{
  .arc_name = "ip4-output",
  .node_name = "vxlan-gpe-transit-ioam",
  .runs_before = VNET_FEATURES ("interface-output"),
};
/* *INDENT-ON* */

static uword
vxlan_gpe_transit_ioam (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * from_frame)
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
	  u32 next0 = VXLAN_GPE_TRANSIT_IOAM_NEXT_OUTPUT;

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
		    UDP_DST_PORT_VXLAN_GPE)))
		{

		  /* Check the iOAM header */
		  vxlan_gpe_header_t *gpe_hdr0 =
		    (vxlan_gpe_header_t *) (udp_hdr0 + 1);

		  if (PREDICT_FALSE
		      (gpe_hdr0->protocol == VXLAN_GPE_PROTOCOL_IOAM))
		    {
		      uword *t = NULL;
		      vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
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
			  vxlan_gpe_encap_decap_ioam_v4_one_inline (vm, node,
								    b0,
								    &next0,
								    VXLAN_GPE_TRANSIT_IOAM_NEXT_DROP,
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vxlan_gpe_transit_ioam_node) = {
  .function = vxlan_gpe_transit_ioam,
  .name = "vxlan-gpe-transit-ioam",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_gpe_ioam_v4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vxlan_gpe_transit_ioam_error_strings),
  .error_strings = vxlan_gpe_transit_ioam_error_strings,

  .n_next_nodes = VXLAN_GPE_TRANSIT_IOAM_N_NEXT,

  .next_nodes = {
        [VXLAN_GPE_TRANSIT_IOAM_NEXT_OUTPUT] = "interface-output",
        [VXLAN_GPE_TRANSIT_IOAM_NEXT_DROP] = "error-drop",
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
