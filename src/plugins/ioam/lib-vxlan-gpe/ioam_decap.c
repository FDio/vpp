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
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam_packet.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam_util.h>

/* Statistics (not really errors) */
#define foreach_vxlan_gpe_decap_ioam_v4_error    \
_(DECAPSULATED, "good packets decapsulated")

static char *vxlan_gpe_decap_ioam_v4_error_strings[] = {
#define _(sym,string) string,
  foreach_vxlan_gpe_decap_ioam_v4_error
#undef _
};

typedef enum
{
#define _(sym,str) VXLAN_GPE_DECAP_IOAM_V4_ERROR_##sym,
  foreach_vxlan_gpe_decap_ioam_v4_error
#undef _
    VXLAN_GPE_DECAP_IOAM_V4_N_ERROR,
} vxlan_gpe_decap_ioam_v4_error_t;


always_inline void
vxlan_gpe_decap_ioam_v4_two_inline (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vxlan_gpe_main_t * ngm,
				    vlib_buffer_t * b0, vlib_buffer_t * b1,
				    u32 * next0, u32 * next1)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  *next0 = *next1 = hm->decap_v4_next_override;
  vxlan_gpe_encap_decap_ioam_v4_one_inline (vm, node, b0, next0,
					    VXLAN_GPE_DECAP_IOAM_V4_NEXT_DROP,
					    0 /* use_adj */ );
  vxlan_gpe_encap_decap_ioam_v4_one_inline (vm, node, b1, next1,
					    VXLAN_GPE_DECAP_IOAM_V4_NEXT_DROP,
					    0 /* use_adj */ );
}



static uword
vxlan_gpe_decap_ioam (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame, u8 is_ipv6)
{
  u32 n_left_from, next_index, *from, *to_next;
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

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

	  next0 = next1 = hm->decap_v4_next_override;

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


	  vlib_buffer_advance (b0,
			       -(word) (sizeof (udp_header_t) +
					sizeof (ip4_header_t) +
					sizeof (vxlan_gpe_header_t)));
	  vlib_buffer_advance (b1,
			       -(word) (sizeof (udp_header_t) +
					sizeof (ip4_header_t) +
					sizeof (vxlan_gpe_header_t)));

	  vxlan_gpe_decap_ioam_v4_two_inline (vm, node, ngm, b0, b1,
					      &next0, &next1);


	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gpe_ioam_v4_trace_t *tr = vlib_add_trace (vm, node, b0,
							      sizeof (*tr));
	    }
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = hm->decap_v4_next_override;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);


	  vlib_buffer_advance (b0,
			       -(word) (sizeof (udp_header_t) +
					sizeof (ip4_header_t) +
					sizeof (vxlan_gpe_header_t)));

	  next0 = hm->decap_v4_next_override;
	  vxlan_gpe_encap_decap_ioam_v4_one_inline (vm, node, b0,
						    &next0,
						    VXLAN_GPE_DECAP_IOAM_V4_NEXT_DROP,
						    0 /* use_adj */ );

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gpe_ioam_v4_trace_t *tr = vlib_add_trace (vm, node, b0,
							      sizeof (*tr));
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}


static uword
vxlan_gpe_decap_ioam_v4 (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  return vxlan_gpe_decap_ioam (vm, node, from_frame, 0);
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vxlan_gpe_decap_ioam_v4_node) = {
  .function = vxlan_gpe_decap_ioam_v4,
  .name = "vxlan-gpe-decap-ioam-v4",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_gpe_ioam_v4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vxlan_gpe_decap_ioam_v4_error_strings),
  .error_strings = vxlan_gpe_decap_ioam_v4_error_strings,

  .n_next_nodes = VXLAN_GPE_DECAP_IOAM_V4_N_NEXT,

  .next_nodes = {
    [VXLAN_GPE_DECAP_IOAM_V4_NEXT_POP] = "vxlan-gpe-pop-ioam-v4",
    [VXLAN_GPE_DECAP_IOAM_V4_NEXT_DROP] = "error-drop",
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
