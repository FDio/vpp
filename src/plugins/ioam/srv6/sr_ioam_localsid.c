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

#include <vnet/ip/ip.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <ioam/srv6/sr_ioam.h>
#include <ioam/srv6/sr_ioam_util.h>
#include <ioam/srv6/sr_ioam_trace.h>

/* Statistics (not really errors) */
#define foreach_sr_ioam_localsid_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char *sr_ioam_localsid_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_ioam_localsid_error
#undef _
};

typedef enum
{
#define _(sym,str) SR_LOCALSID_IOAM_ERROR_##sym,
  foreach_sr_ioam_localsid_error
#undef _
    SR_LOCALSID_IOAM_N_ERROR,
} sr_ioam_localsid_error_t;

typedef enum
{
  SR_LOCALSID_IOAM_NEXT_IP6_LOOKUP,
  SR_LOCALSID_IOAM_NEXT_OUTPUT,
  SR_LOCALSID_IOAM_NEXT_DROP,
  SR_LOCALSID_IOAM_N_NEXT
} sr_ioam_localsid_next_t;


static uword
sr_ioam_localsid (vlib_main_t * vm,
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


      /* Quad - Loop */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 next0, next1, next2, next3;
	  next0 = next1 = next2 = next3 = SR_LOCALSID_IOAM_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  bi1 = from[1];
	  to_next[1] = bi1;
	  bi2 = from[2];
	  to_next[2] = bi2;
	  bi3 = from[3];
	  to_next[3] = bi3;
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  u32 iph_offset = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  iph_offset = vnet_buffer (b0)->ip.save_rewrite_length;
	  ip0 =
	    (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      iph_offset);


	  b1 = vlib_get_buffer (vm, bi1);
	  iph_offset = vnet_buffer (b1)->ip.save_rewrite_length;
	  ip1 =
	    (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b1) +
			      iph_offset);

	  b2 = vlib_get_buffer (vm, bi2);
	  iph_offset = vnet_buffer (b2)->ip.save_rewrite_length;
	  ip2 =
	    (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b2) +
			      iph_offset);


	  b3 = vlib_get_buffer (vm, bi3);
	  iph_offset = vnet_buffer (b3)->ip.save_rewrite_length;
	  ip3 =
	    (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b3) +
			      iph_offset);

	  /* just forward non ipv6 packets */
	  if (PREDICT_FALSE
	      ((ip0->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60))
	    {

	      sr_ioam_one_inline (vm, node, b0, &next0,
				  SR_LOCALSID_IOAM_NEXT_DROP);

	    }

	  if (PREDICT_FALSE
	      ((ip1->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60))
	    {

	      sr_ioam_one_inline (vm, node, b1, &next1,
				  SR_LOCALSID_IOAM_NEXT_DROP);

	    }

	  if (PREDICT_FALSE
	      ((ip2->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60))
	    {

	      sr_ioam_one_inline (vm, node, b2, &next2,
				  SR_LOCALSID_IOAM_NEXT_DROP);

	    }

	  if (PREDICT_FALSE
	      ((ip3->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60))
	    {

	      sr_ioam_one_inline (vm, node, b3, &next3,
				  SR_LOCALSID_IOAM_NEXT_DROP);

	    }

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);

	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SR_LOCALSID_IOAM_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  ip6_header_t *ip0;
	  u32 iph_offset = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  iph_offset = vnet_buffer (b0)->ip.save_rewrite_length;
	  ip0 =
	    (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      iph_offset);

	  /* just forward non ipv6 packets */
	  if (PREDICT_FALSE
	      ((ip0->ip_version_traffic_class_and_flow_label & 0xF0) == 0x60))
	    {

	      sr_ioam_one_inline (vm, node, b0, &next0,
				  SR_LOCALSID_IOAM_NEXT_DROP);

	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_ioam_localsid_node) = {
  .function = sr_ioam_localsid,
  .name = "sr-localsid-ioam",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_ioam_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(sr_ioam_localsid_error_strings),
  .error_strings = sr_ioam_localsid_error_strings,

  .n_next_nodes = SR_LOCALSID_IOAM_N_NEXT,

  .next_nodes = {
        [SR_LOCALSID_IOAM_NEXT_IP6_LOOKUP] = "ip6-lookup",
        [SR_LOCALSID_IOAM_NEXT_OUTPUT] = "interface-output",
        [SR_LOCALSID_IOAM_NEXT_DROP] = "error-drop",
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
