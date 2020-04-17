/*
 * Copyright (c) 2018 Travelping GmbH
 *
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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_tdf_error		\
  _(TDF, "good packets tdf")

static char *upf_tdf_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_tdf_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_TDF_ERROR_##sym,
  foreach_upf_tdf_error
#undef _
    UPF_TDF_N_ERROR,
} upf_tdf_error_t;

typedef enum
{
  UPF_TDF_NEXT_DROP,
  UPF_TDF_NEXT_PROCESS,
  UPF_TDF_NEXT_IP_LOOKUP,
  UPF_TDF_N_NEXT,
} upf_tdf_next_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u32 pdr_idx;
  u32 next_index;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_tdf_trace_t;

static u8 *
format_upf_tdf_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_tdf_trace_t *t = va_arg (*args, upf_tdf_trace_t *);
  u32 indent = format_get_indent (s);

  s =
    format (s,
	    "upf_session%d cp-seid 0x%016" PRIx64
	    " pdr %d, next_index = %d\n%U%U", t->session_index, t->cp_seid,
	    t->pdr_idx, t->next_index, format_white_space, indent,
	    format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static uword
upf_tdf (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame,
	 int is_ip4)
{
  u32 n_left_from, *from, *to_next;
  upf_tdf_next_t next_index;
  /* u32 pkts_swapped = 0; */

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = UPF_TDF_NEXT_IP_LOOKUP;
	  /* u32 sw_if_index0; */
	  /* ethernet_header_t *en0; */

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /*
	   * Direct from the driver, we should be at offset 0
	   * aka at &b0->data[0]
	   */
	  ASSERT (b0->current_data != 0);
	  upf_debug ("Data Offset: %u\n", b0->current_data);

	  /* en0 = vlib_buffer_get_current (b0); */

	  /* pkts_swapped += 1; */

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_tdf_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      /* tr->session_index = sidx; */
	      /* tr->cp_seid = sess->cp_seid; */
	      tr->pdr_idx = upf_buffer_opaque (b0)->gtpu.pdr_idx;
	      tr->next_index = next0;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b0),
			   sizeof (tr->packet_data));
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* vlib_node_increment_counter (vm, upf_node.index, */
  /*                           UPF_TDF_ERROR_TDF, pkts_swapped); */
  return frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_tdf_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return upf_tdf (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_tdf_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return upf_tdf (vm, node, from_frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_tdf_node) =
{
  .name = "upf-ip4-tdf",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_tdf_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (upf_tdf_error_strings),
  .error_strings = upf_tdf_error_strings,
  .n_next_nodes = UPF_TDF_N_NEXT,
  .next_nodes = {
    [UPF_TDF_NEXT_DROP]    = "error-drop",
    [UPF_TDF_NEXT_PROCESS] = "upf-ip4-input",
    [UPF_TDF_NEXT_IP_LOOKUP] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_tdf_node) =
{
  .name = "upf-ip6-tdf",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_tdf_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (upf_tdf_error_strings),
  .error_strings = upf_tdf_error_strings,
  .n_next_nodes = UPF_TDF_N_NEXT,
  .next_nodes = {
    [UPF_TDF_NEXT_DROP]    = "error-drop",
    [UPF_TDF_NEXT_PROCESS] = "upf-ip6-input",
    [UPF_TDF_NEXT_IP_LOOKUP] = "ip6-lookup",
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
