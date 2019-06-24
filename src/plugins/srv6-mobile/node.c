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
#include <vppinfra/hash.h>
#include <srv6-mobile/mobile.h>

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

static u8 *
format_srv6_end_rewrite_trace6 (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_end_rewrite_trace_t *t = va_arg (*args, srv6_end_rewrite_trace_t *);

  return format (s, "SRv6-END-rewrite: src %U dst %U\n TEID: 0x%x",
		 format_ip6_address, &t->src, format_ip6_address, &t->dst, t->teid);
}

#define foreach_srv6_end_v4_error \
  _(M_GTP4_E_PACKETS, "srv6 End.M.GTP4.E packets") \
  _(M_GTP4_E_BAD_PACKETS, "srv6 End.M.GTP4.E bad packets")

#define foreach_srv6_end_v6_e_error \
  _(M_GTP6_E_PACKETS, "srv6 End.M.GTP6.E packets") \
  _(M_GTP6_E_BAD_PACKETS, "srv6 End.M.GTP6.E bad packets")

#define foreach_srv6_end_v6_d_error \
  _(M_GTP6_D_PACKETS, "srv6 End.M.GTP6.D packets") \
  _(M_GTP6_D_BAD_PACKETS, "srv6 End.M.GTP6.D bad packets")

#define foreach_srv6_end_v6_d_di_error \
  _(M_GTP6_D_PACKETS, "srv6 End.M.GTP6.D.DI packets") \
  _(M_GTP6_D_BAD_PACKETS, "srv6 End.M.GTP6.D.DI bad packets")

typedef enum
{
#define _(sym,str) SRV6_END_ERROR_##sym,
  foreach_srv6_end_v4_error
#undef _
    SRV6_END_N_V4_ERROR,
} srv6_end_error_v4_t;

typedef enum
{
#define _(sym,str) SRV6_END_ERROR_##sym,
  foreach_srv6_end_v6_e_error
#undef _
    SRV6_END_N_V6_E_ERROR,
} srv6_end_error_v6_e_t;

typedef enum
{
#define _(sym,str) SRV6_END_ERROR_##sym,
  foreach_srv6_end_v6_d_error
#undef _
    SRV6_END_N_V6_D_ERROR,
} srv6_end_error_v6_d_t;

typedef enum
{
#define _(sym,str) SRV6_END_ERROR_##sym,
  foreach_srv6_end_v6_d_di_error
#undef _
    SRV6_END_N_V6_D_DI_ERROR,
} srv6_end_error_v6_d_di_t;

static char *srv6_end_error_v4_strings[] = {
#define _(sym,string) string,
  foreach_srv6_end_v4_error
#undef _
};

static char *srv6_end_error_v6_e_strings[] = {
#define _(sym,string) string,
  foreach_srv6_end_v6_e_error
#undef _
};

static char *srv6_end_error_v6_d_strings[] = {
#define _(sym,string) string,
  foreach_srv6_end_v6_d_error
#undef _
};

static char *srv6_end_error_v6_d_di_strings[] = {
#define _(sym,string) string,
  foreach_srv6_end_v6_d_di_error
#undef _
};

typedef enum
{
  SRV6_END_M_GTP4_E_NEXT_DROP,
  SRV6_END_M_GTP4_E_NEXT_LOOKUP,
  SRV6_END_M_GTP4_E_N_NEXT,
} srv6_end_m_gtp4_e_next_t;

typedef enum
{
  SRV6_END_M_GTP6_E_NEXT_DROP,
  SRV6_END_M_GTP6_E_NEXT_LOOKUP,
  SRV6_END_M_GTP6_E_N_NEXT,
} srv6_end_m_gtp6_e_next_t;

typedef enum
{
  SRV6_END_M_GTP6_D_NEXT_DROP,
  SRV6_END_M_GTP6_D_NEXT_LOOKUP,
  SRV6_END_M_GTP6_D_N_NEXT,
} srv6_end_m_gtp6_d_next_t;

typedef enum
{
  SRV6_END_M_GTP6_D_DI_NEXT_DROP,
  SRV6_END_M_GTP6_D_DI_NEXT_LOOKUP,
  SRV6_END_M_GTP6_D_DI_N_NEXT,
} srv6_end_m_gtp6_d_di_next_t;

// Function for SRv6 GTP4.E function.
VLIB_NODE_FN (srv6_end_m_gtp4_e) (vlib_main_t * vm,
                                  vlib_node_runtime_t * node,
                                  vlib_frame_t * frame)
{
  srv6_end_main_v4_t *sm = &srv6_end_main_v4;
  ip6_sr_main_t *sm2 = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 thread_index = vm->thread_index;

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
	  ip6_sr_localsid_t *ls0;

          ip6srv_combo_header_t *ip6srv0;
          ip6_address_t src0, dst0;

          ip4_gtpu_header_t *hdr0 = NULL;
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
	  ls0 =
            pool_elt_at_index (sm2->localsids,
                               vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

          ip6srv0 = vlib_buffer_get_current (b0);
          src0 = ip6srv0->ip.src_address;
          dst0 = ip6srv0->ip.dst_address;

          len0 = vlib_buffer_length_in_chain (vm, b0);

	  if ((ip6srv0->ip.protocol == IPPROTO_IPV6_ROUTE
	    && len0 < sizeof(ip6srv_combo_header_t) + ip6srv0->sr.length * 8)
	   || (len0 < sizeof (ip6_header_t)))
            {
              next0 = SRV6_END_M_GTP4_E_NEXT_DROP;

              bad_n++;
            }
          else
            {
              // we need to be sure there is enough space before 
              // ip6srv0 header, there is some extra space
              // in the pre_data area for this kind of
              // logic

              // jump over variable length data
              // not sure about the length
	      if (ip6srv0->ip.protocol == IPPROTO_IPV6_ROUTE)
	        {
                  vlib_buffer_advance (b0, (word) sizeof (ip6srv_combo_header_t) +
                                       ip6srv0->sr.length * 8);
		}
	      else
		{
	          vlib_buffer_advance (b0, (word) sizeof (ip6_header_t));
		}

              // get length of encapsulated IPv6 packet (the remaining part)
              len0 = vlib_buffer_length_in_chain (vm, b0);

              // jump back to data[0] or pre_data if required
              vlib_buffer_advance (b0, -(word) sizeof (ip4_gtpu_header_t));

              hdr0 = vlib_buffer_get_current (b0);

              clib_memcpy (hdr0, &sm->cache_hdr, sizeof (ip4_gtpu_header_t));

              u32 teid;
              u8 *teid8p = (u8 *)&teid;
              teid8p[0] = dst0.as_u8[9];
              teid8p[1] = dst0.as_u8[10];
              teid8p[2] = dst0.as_u8[11];
              teid8p[3] = dst0.as_u8[12];
              hdr0->gtpu.teid = teid;
              hdr0->gtpu.length = clib_host_to_net_u16 (len0);

              hdr0->udp.src_port = src0.as_u16[6];
              hdr0->udp.length = clib_host_to_net_u16 (len0 +
                  sizeof (udp_header_t) + sizeof (gtpu_header_t));

              hdr0->ip4.src_address.as_u32 = src0.as_u32[2];
              hdr0->ip4.dst_address.as_u32 = dst0.as_u32[1];
              hdr0->ip4.length = clib_host_to_net_u16 (len0 +
                  sizeof (ip4_gtpu_header_t));

              hdr0->ip4.checksum = ip4_header_checksum (&hdr0->ip4);

              good_n++;

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
	    }

          vlib_increment_combined_counter
            (((next0 ==
               SRV6_END_M_GTP4_E_NEXT_DROP) ? &(sm2->sr_ls_invalid_counters) :
              &(sm2->sr_ls_valid_counters)), thread_index, ls0 - sm2->localsids,
             1, vlib_buffer_length_in_chain (vm, b0));

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

  .n_errors = ARRAY_LEN (srv6_end_error_v4_strings),
  .error_strings = srv6_end_error_v4_strings,

  .n_next_nodes = SRV6_END_M_GTP4_E_N_NEXT,
  .next_nodes = {
    [SRV6_END_M_GTP4_E_NEXT_DROP] = "error-drop",
    [SRV6_END_M_GTP4_E_NEXT_LOOKUP] = "ip4-lookup",
  },
};

static inline u16
hash_uword_to_u16 (uword *key)
{
  u16 *val;
  val = key;
#if uword bits == 64
  return val[0] ^ val[1] ^ val[3] ^ val[4];
#else
  return val[0] ^ val[1];
#endif
}

// Function for SRv6 GTP6.E function
VLIB_NODE_FN (srv6_end_m_gtp6_e) (vlib_main_t * vm,
                                  vlib_node_runtime_t * node,
                                  vlib_frame_t * frame)
{
  srv6_end_main_v6_t *sm = &srv6_end_main_v6;
  ip6_sr_main_t *sm2 = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 thread_index = vm->thread_index;

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
	  ip6_sr_localsid_t *ls0;

          ip6srv_combo_header_t *ip6srv0;
          ip6_address_t src0, dst0, seg0;

          ip6_gtpu_header_t *hdr0 = NULL;
          uword len0;
	  uword key;
	  u16 port;
	  void *p;
          
	  u32 next0 = SRV6_END_M_GTP6_E_NEXT_LOOKUP;

          // defaults
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
	  ls0 =
            pool_elt_at_index (sm2->localsids,
                               vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

          ip6srv0 = vlib_buffer_get_current (b0);
          src0 = ip6srv0->ip.src_address;
          dst0 = ip6srv0->ip.dst_address;
	  seg0 = ip6srv0->sr.segments[0];

          len0 = vlib_buffer_length_in_chain (vm, b0);

          if ((ip6srv0->ip.protocol != IPPROTO_IPV6_ROUTE)
	   || (len0 < sizeof (ip6srv_combo_header_t) + 8 * ip6srv0->sr.length))
            {
              next0 = SRV6_END_M_GTP6_E_NEXT_DROP;

              bad_n++;
            }
          else
            {
              // we need to be sure there is enough space before 
              // ip6srv0 header, there is some extra space
              // in the pre_data area for this kind of
              // logic

              // jump over variable length data
              // not sure about the length
              vlib_buffer_advance (b0, (word) sizeof (ip6srv_combo_header_t) +
                  ip6srv0->sr.length * 8);

              // get length of encapsulated IPv6 packet (the remaining part)
              len0 = vlib_buffer_length_in_chain (vm, b0);

	      p = vlib_buffer_get_current (b0);

              // jump back to data[0] or pre_data if required
              vlib_buffer_advance (b0, -(word) sizeof (ip6_gtpu_header_t));

              hdr0 = vlib_buffer_get_current (b0);

              clib_memcpy (hdr0, &sm->cache_hdr, sizeof (ip6_gtpu_header_t));

              u32 teid;
              u8 *teid8p = (u8 *)&teid;
	      u16 index;
	      u16 offset, shift;

	      index = sl0->localsid_len;
	      index += 8;
	      offset = index / 8;
	      shift = index % 8;

	      if (PREDICT_TRUE (shift == 0)) {
                teid8p[0] = dst0.as_u8[offset];
                teid8p[1] = dst0.as_u8[offset+1];
                teid8p[2] = dst0.as_u8[offset+2];
                teid8p[3] = dst0.as_u8[offset+3];
	      } else {
		for (index = offset; index < offset + 4; index++)	      
		  {
		    *teid8p = dst0.as_u8[index] << shift;
		    *teid8p |= dst0.as_u8[index+1] >> (8 - shift);
		    teid8p++;
		  }
	      }

              hdr0->gtpu.teid = teid;
              hdr0->gtpu.length = clib_host_to_net_u16 (len0);

              hdr0->udp.length = clib_host_to_net_u16 (len0 +
                  sizeof (udp_header_t) + sizeof (gtpu_header_t));

	      clib_memcpy (hdr0->ip6.src_address.as_u8, dst0.as_u8,
			   sizeof(ip6_address_t));
	      clib_memcpy (hdr0->ip6.dst_address.as_u8, &seg0.as_u8,
			   sizeof(ip6_address_t));

              hdr0->ip6.payload_length = clib_host_to_net_u16 (len0 +
                  sizeof (udp_header_t) + sizeof(gtpu_header_t));

	      // UDP source port.
	      key = hash_memory(p, len0, 0);
	      port = hash_uword_to_u16(&key);
	      hdr0->udp.src_port = port;

              good_n++;

 	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	          PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	        {
                  srv6_end_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
	          clib_memcpy (tr->src.as_u8, hdr0->ip6.src_address.as_u8,
			       sizeof (ip6_address_t));
	          clib_memcpy (tr->dst.as_u8, hdr0->ip6.dst_address.as_u8,
			       sizeof (ip6_address_t));
                  tr->teid = hdr0->gtpu.teid;
	        }
	    }

          vlib_increment_combined_counter
            (((next0 ==
               SRV6_END_M_GTP6_E_NEXT_DROP) ? &(sm2->sr_ls_invalid_counters) :
              &(sm2->sr_ls_valid_counters)), thread_index, ls0 - sm2->localsids,
             1, vlib_buffer_length_in_chain (vm, b0));

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp6_e_node_index,
                               SRV6_END_ERROR_M_GTP6_E_BAD_PACKETS,
			       bad_n);

  vlib_node_increment_counter (vm, sm->end_m_gtp6_e_node_index,
                               SRV6_END_ERROR_M_GTP6_E_PACKETS,
			       good_n);

  return frame->n_vectors;
}

// Function for SRv6 GTP6.D function
VLIB_NODE_FN (srv6_end_m_gtp6_d) (vlib_main_t * vm,
                                  vlib_node_runtime_t * node,
                                  vlib_frame_t * frame)
{
  // XXX
   
  return frame->n_vectors;
}

// Function for SRv6 GTP6.D.DI function
VLIB_NODE_FN (srv6_end_m_gtp6_d_di) (vlib_main_t * vm,
                                  vlib_node_runtime_t * node,
                                  vlib_frame_t * frame)
{
  // XXX
   
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_end_m_gtp6_e) = {
  .name = "srv6-end-m-gtp6-e",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_end_rewrite_trace6,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (srv6_end_error_v6_e_strings),
  .error_strings = srv6_end_error_v6_e_strings,

  .n_next_nodes = SRV6_END_M_GTP6_E_N_NEXT,
  .next_nodes = {
    [SRV6_END_M_GTP6_E_NEXT_DROP] = "error-drop",
    [SRV6_END_M_GTP6_E_NEXT_LOOKUP] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (srv6_end_m_gtp6_d) = {
  .name = "srv6-end-m-gtp6-d",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_end_rewrite_trace6,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (srv6_end_error_v6_d_strings),
  .error_strings = srv6_end_error_v6_d_strings,

  .n_next_nodes = SRV6_END_M_GTP6_D_N_NEXT,
  .next_nodes = {
    [SRV6_END_M_GTP6_D_NEXT_DROP] = "error-drop",
    [SRV6_END_M_GTP6_D_NEXT_LOOKUP] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (srv6_end_m_gtp6_d_di) = {
  .name = "srv6-end-m-gtp6-d-di",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_end_rewrite_trace6,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (srv6_end_error_v6_d_di_strings),
  .error_strings = srv6_end_error_v6_d_di_strings,

  .n_next_nodes = SRV6_END_M_GTP6_D_DI_N_NEXT,
  .next_nodes = {
    [SRV6_END_M_GTP6_D_DI_NEXT_DROP] = "error-drop",
    [SRV6_END_M_GTP6_D_DI_NEXT_LOOKUP] = "ip6-lookup",
  },
};

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
