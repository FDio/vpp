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

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip;
  ip6_sr_header_t sr;
}) ip6srv_combo_header_t;
/* *INDENT-ON* */

#define foreach_srv6_end_error \
  _(M_GTP4_E_PACKETS, "srv6 End.M.GTP4.E packets")

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

  u32 good_n = 0;

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

          ip4_gtpu_header_t hdr0 = sm->cache_hdr;
          
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

          hdr0.ip4.src_address = src0.as_u32[2];
          hdr0.ip4.dst_address = dst0.as_u32[1];
          hdr0.ip4.checksum = ip4_header_checksum (&hdr0.ip4);

          hdr0.udp.src_port = src0.as_u16[6];

          hdr0.gtpu.teid = (u32) dst0.as_u8[9];

          hdr0.udp.length =;
          hdr0.gtpu.length =;

          vlib_buffer_advance (b0, (word) ip6srv0->sr.length);
         
          clib_memcpy (vlib_buffer_get_current (b0) -
                       sizeof (ip4_gtpu_header_t), &hdr0,
                       sizeof (ip4_gtpu_header_t));

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  good_n++;
        }
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp4_e_node_index,
                               SRV6_END_ERROR_M_GTP4_E_PACKETS,
			       good_n);

  return frame->n_vectors;
}


VLIB_REGISTER_NODE (srv6_end_m_gtp4_e) = {
  .name = "srv6-end-m-gtp4-e",
  .vector_size = sizeof (u32),
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
