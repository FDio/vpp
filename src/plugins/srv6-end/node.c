/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <srv6-end/srv6_end.h>

typedef struct {
  ip6_address_t src, dst;
  u32 teid;
} srv6_end_rewrite_trace_t;

static u8 *
format_srv6_end_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_end_rewrite_trace_t *t = va_arg (*args, srv6_end_rewrite_trace_t *);

  return format (s, "SRv6-END-rewrite: src %U dst %U\n TEID: 0x%x",
		 format_ip4_address, &t->src, format_ip4_address, &t->dst, t->teid);
}


/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip;
  ip6_sr_header_t sr;
}) ip6srv_combo_header_t;
/* *INDENT-ON* */

#define foreach_srv6_end_error \
  _(M_GTP4_E_PACKETS, "srv6 End.M.GTP4.E packets") \
  _(M_GTP4_E_BAD_PACKETS, "srv6 End.M.GTP4.E bad packets")


typedef enum
{
#define _(sym,str) SRV6_END_ERROR_##sym,
  foreach_srv6_end_error
#undef _
    SRV6_END_N_ERROR,
} srv6_end_error_t;

static char *srv6_end_error_strings[] = {
#define _(sym,string) string,
  foreach_srv6_end_error
#undef _
};

typedef enum
{
  SRV6_END_M_GTP4_E_NEXT_DROP,
  SRV6_END_M_GTP4_E_NEXT_LOOKUP,
  SRV6_END_M_GTP4_E_N_NEXT,
} srv6_end_m_gtp4_e_next_t;

VLIB_NODE_FN (srv6_end_m_gtp4_e) (vlib_main_t * vm,
                                  vlib_node_runtime_t * node,
                                  vlib_frame_t * frame)
{
  srv6_end_main_t *sm = &srv6_end_main;
  u32 n_left_from, next_index, *from, *to_next;

  u32 good_n = 0, bad_n = 0;

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

          ip6srv_combo_header_t *ip6srv0;
          ip6_address_t src0, dst0;

          ip4_gtpu_header_t *hdr0;
          uword len0;
          
	  u32 next0 = SRV6_END_M_GTP4_E_NEXT_LOOKUP;

          // defaults
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          //

          ip6srv0 = vlib_buffer_get_current (b0);
          src0 = ip6srv0->ip.src_address;
          dst0 = ip6srv0->ip.dst_address;

          len0 = vlib_buffer_length_in_chain (vm, b0);
          if ((len0 < sizeof (ip6srv_combo_header_t)) ||
              (len0 < sizeof (ip6srv_combo_header_t) + ip6srv0->sr.length))
            {
              next0 = SRV6_END_M_GTP4_E_NEXT_DROP;

              bad_n++;
            }
          else
            {
              vlib_buffer_advance (b0, (word) ip6srv0->sr.length);

              len0 = vlib_buffer_length_in_chain (vm, b0);
         
              clib_memcpy (vlib_buffer_get_current (b0) -
                           sizeof (ip4_gtpu_header_t), &sm->cache_hdr,
                           sizeof (ip4_gtpu_header_t));

              vlib_buffer_advance (b0, -(word) vlib_buffer_get_current (b0) -
                                   sizeof (ip4_gtpu_header_t));

              hdr0 = vlib_buffer_get_current (b0);

              hdr0->gtpu.teid = (u32) dst0.as_u8[9];
              hdr0->gtpu.length = len0;

              hdr0->udp.src_port = src0.as_u16[6];
              hdr0->udp.length = len0 + sizeof (udp_header_t);

              hdr0->ip4.src_address.as_u32 = src0.as_u32[2];
              hdr0->ip4.dst_address.as_u32 = dst0.as_u32[1];
              hdr0->ip4.length = len0 + sizeof (udp_header_t) +
                                 sizeof (ip4_header_t);
              hdr0->ip4.checksum = ip4_header_checksum (&hdr0->ip4);

	      good_n++;
            }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
              srv6_end_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy (tr->src.as_u8, hdr0->ip4.src_address.as_u8,
			   sizeof (tr->src.as_u8));
	      clib_memcpy (tr->dst.as_u8, hdr0->ip4.dst_address.as_u8,
			   sizeof (tr->dst.as_u8));
              tr->teid = hdr0->gtpu.teid;
	    }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp4_e_node_index,
                               SRV6_END_ERROR_M_GTP4_E_BAD_PACKETS,
			       bad_n);

  vlib_node_increment_counter (vm, sm->end_m_gtp4_e_node_index,
                               SRV6_END_ERROR_M_GTP4_E_PACKETS,
			       good_n);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_end_m_gtp4_e) = {
  .name = "srv6-end-m-gtp4-e",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_end_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (srv6_end_error_strings),
  .error_strings = srv6_end_error_strings,

  .n_next_nodes = SRV6_END_M_GTP4_E_N_NEXT,
  .next_nodes = {
    [SRV6_END_M_GTP4_E_NEXT_DROP] = "error-drop",
    [SRV6_END_M_GTP4_E_NEXT_LOOKUP] = "ip4-lookup",
  },
};

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
