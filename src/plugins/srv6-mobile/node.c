/*
 * Copyright (c) 2019 Arrcus Inc and/or its affiliates.
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

extern ip6_address_t sr_pr_encaps_src;

typedef struct
{
  ip6_address_t src, dst;
  ip6_address_t sr_prefix;
  u16 sr_prefixlen;
  u32 teid;
} srv6_end_rewrite_trace_t;

static u16 srh_tagfield[256] = {
  /* 0 */
  0x0,
  /* 1 : Echo Request */
  0x0004,
  /* 2 : Echo Reply */
  0x0008,
  /* 3 - 7 */
  0x0, 0x0, 0x0, 0x0, 0x0,
  /* 8 - 15 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 16 - 23 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 24 - 25 */
  0x0, 0x0,
  /* 26 : Error Indication */
  0x0002,
  /* 27 - 31 */
  0x0, 0x0, 0x0, 0x0, 0x0,
  /* 32 - 247 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 248 - 253 */
  0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  /* 254 : End Maker */
  0x0001,
  /* 255 : G_PDU */
  0x0
};

static u8 *
format_srv6_end_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_end_rewrite_trace_t *t = va_arg (*args, srv6_end_rewrite_trace_t *);

  return format (s, "SRv6-END-rewrite: src %U dst %U\n\tTEID: 0x%x",
		 format_ip4_address, &t->src, format_ip4_address, &t->dst,
		 clib_net_to_host_u32 (t->teid));
}

static u8 *
format_srv6_end_rewrite_trace6 (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_end_rewrite_trace_t *t = va_arg (*args, srv6_end_rewrite_trace_t *);

  return format (s,
		 "SRv6-END-rewrite: src %U dst %U\n\tTEID: 0x%x\n\tsr_prefix: %U/%d",
		 format_ip6_address, &t->src, format_ip6_address, &t->dst,
		 clib_net_to_host_u32 (t->teid), format_ip6_address,
		 &t->sr_prefix, t->sr_prefixlen);
}

#define foreach_srv6_end_v4_error \
  _(M_GTP4_E_PACKETS, "srv6 End.M.GTP4.E packets") \
  _(M_GTP4_E_BAD_PACKETS, "srv6 End.M.GTP4.E bad packets")

#define foreach_srv6_t_v4_d_error \
  _(M_GTP4_D_PACKETS, "srv6 T.M.GTP4.D packets") \
  _(M_GTP4_D_BAD_PACKETS, "srv6 T.M.GTP4.D bad packets")

#define foreach_srv6_end_v6_e_error \
  _(M_GTP6_E_PACKETS, "srv6 End.M.GTP6.E packets") \
  _(M_GTP6_E_BAD_PACKETS, "srv6 End.M.GTP6.E bad packets")

#define foreach_srv6_end_v6_d_error \
  _(M_GTP6_D_PACKETS, "srv6 End.M.GTP6.D packets") \
  _(M_GTP6_D_BAD_PACKETS, "srv6 End.M.GTP6.D bad packets")

#define foreach_srv6_end_v6_d_di_error \
  _(M_GTP6_D_DI_PACKETS, "srv6 End.M.GTP6.D.DI packets") \
  _(M_GTP6_D_DI_BAD_PACKETS, "srv6 End.M.GTP6.D.DI bad packets")

#define foreach_srv6_end_v6_dt_error \
  _(M_GTP6_DT_PACKETS, "srv6 End.M.GTP6.DT packets") \
  _(M_GTP6_DT_BAD_PACKETS, "srv6 End.M.GTP6.DT bad packets")

#define foreach_srv6_t_v4_dt_error \
  _(M_GTP4_DT_PACKETS, "srv6 T.M.GTP4.DT packets") \
  _(M_GTP4_DT_BAD_PACKETS, "srv6 T.M.GTP4.DT bad packets")

typedef enum
{
#define _(sym,str) SRV6_END_ERROR_##sym,
  foreach_srv6_end_v4_error
#undef _
    SRV6_END_N_V4_ERROR,
} srv6_end_error_v4_t;

typedef enum
{
#define _(sym,str) SRV6_T_ERROR_##sym,
  foreach_srv6_t_v4_d_error
#undef _
    SRV6_T_N_V4_D_ERROR,
} srv6_t_error_v4_d_t;

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

typedef enum
{
#define _(sym,str) SRV6_END_ERROR_##sym,
  foreach_srv6_end_v6_dt_error
#undef _
    SRV6_END_N_V6_DT_ERROR,
} srv6_end_error_v6_dt_t;

typedef enum
{
#define _(sym,str) SRV6_T_ERROR_##sym,
  foreach_srv6_t_v4_dt_error
#undef _
    SRV6_T_N_V4_DT_ERROR,
} srv6_t_error_v4_dt_t;

static char *srv6_end_error_v4_strings[] = {
#define _(sym,string) string,
  foreach_srv6_end_v4_error
#undef _
};

static char *srv6_t_error_v4_d_strings[] = {
#define _(sym,string) string,
  foreach_srv6_t_v4_d_error
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

static char *srv6_end_error_v6_dt_strings[] = {
#define _(sym,string) string,
  foreach_srv6_end_v6_dt_error
#undef _
};

static char *srv6_t_error_v4_dt_strings[] = {
#define _(sym,string) string,
  foreach_srv6_t_v4_dt_error
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
  SRV6_T_M_GTP4_D_NEXT_DROP,
  SRV6_T_M_GTP4_D_NEXT_LOOKUP,
  SRV6_T_M_GTP4_D_N_NEXT,
} srv6_T_m_gtp4_d_next_t;

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

typedef enum
{
  SRV6_END_M_GTP6_DT_NEXT_DROP,
  SRV6_END_M_GTP6_DT_NEXT_LOOKUP4,
  SRV6_END_M_GTP6_DT_NEXT_LOOKUP6,
  SRV6_END_M_GTP6_DT_N_NEXT,
} srv6_end_m_gtp6_dt_next_t;

typedef enum
{
  SRV6_T_M_GTP4_DT_NEXT_DROP,
  SRV6_T_M_GTP4_DT_NEXT_LOOKUP4,
  SRV6_T_M_GTP4_DT_NEXT_LOOKUP6,
  SRV6_T_M_GTP4_DT_N_NEXT,
} srv6_t_m_gtp4_dt_next_t;

static inline u16
hash_uword_to_u16 (uword * key)
{
  u16 *val;
  val = (u16 *) key;
#if uword_bits == 64
  return val[0] ^ val[1] ^ val[2] ^ val[3];
#else
  return val[0] ^ val[1];
#endif
}

static inline u8
gtpu_type_get (u16 tag)
{
  u16 val;

  val = clib_net_to_host_u16 (tag);
  if (val & SRH_TAG_ECHO_REPLY)
    return GTPU_TYPE_ECHO_REPLY;
  else if (val & SRH_TAG_ECHO_REQUEST)
    return GTPU_TYPE_ECHO_REQUEST;
  else if (val & SRH_TAG_ERROR_INDICATION)
    return GTPU_TYPE_ERROR_INDICATION;
  else if (val & SRH_TAG_END_MARKER)
    return GTPU_TYPE_END_MARKER;

  return GTPU_TYPE_GTPU;
}

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
	  srv6_end_gtp4_param_t *ls_param;

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
			       vnet_buffer (b0)->ip.adj_index);

	  ls_param = (srv6_end_gtp4_param_t *) ls0->plugin_mem;

	  ip6srv0 = vlib_buffer_get_current (b0);
	  src0 = ip6srv0->ip.src_address;
	  dst0 = ip6srv0->ip.dst_address;

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if ((ip6srv0->ip.protocol == IPPROTO_IPV6_ROUTE
	       && len0 <
	       sizeof (ip6srv_combo_header_t) + ip6srv0->sr.length * 8)
	      || (len0 < sizeof (ip6_header_t)))
	    {
	      next0 = SRV6_END_M_GTP4_E_NEXT_DROP;

	      bad_n++;
	    }
	  else
	    {
	      u8 gtpu_type = 0;
	      u16 tag = 0;
	      u32 teid = 0;
	      u8 *teid8p = (u8 *) & teid;
	      u8 qfi = 0;
	      u16 seq = 0;
	      u32 index;
	      u32 offset, shift;
	      u32 hdrlen = 0;
	      uword key;
	      u16 port;
	      ip4_address_t dst4;
	      u16 ie_size = 0;
	      u8 ie_buf[GTPU_IE_MAX_SIZ];
	      void *p;
	      uword plen;

	      if (ip6srv0->ip.protocol == IPPROTO_IPV6_ROUTE)
		{
		  tag = ip6srv0->sr.tag;
		}

	      offset = ls0->localsid_prefix_len / 8;
	      shift = ls0->localsid_prefix_len % 8;

	      gtpu_type = gtpu_type_get (tag);

	      if (PREDICT_TRUE (shift == 0))
		{
		  clib_memcpy_fast (&dst4.as_u8[0], &dst0.as_u8[offset], 4);

		  qfi = dst0.as_u8[offset + 4];

		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      clib_memcpy_fast (&seq, &dst0.as_u8[offset + 5], 2);
		    }
		  else
		    {
		      clib_memcpy_fast (teid8p, &dst0.as_u8[offset + 5], 4);
		    }
		}
	      else
		{
		  u8 *sp;

		  for (index = 0; index < 4; index++)
		    {
		      dst4.as_u8[index] = dst0.as_u8[offset + index] << shift;
		      dst4.as_u8[index] |=
			dst0.as_u8[offset + index + 1] >> (8 - shift);
		    }

		  qfi |= dst0.as_u8[offset + 4] << shift;
		  qfi |= dst0.as_u8[offset + 5] >> (8 - shift);

		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      sp = (u8 *) & seq;
		      for (index = 0; index < 2; index++)
			{
			  sp[index] = dst0.as_u8[offset + 5 + index] << shift;
			  sp[index] |=
			    dst0.as_u8[offset + 6 + index] >> (8 - shift);
			}
		    }
		  else
		    {
		      for (index = 0; index < 4; index++)
			{
			  *teid8p = dst0.as_u8[offset + 5 + index] << shift;
			  *teid8p |=
			    dst0.as_u8[offset + 6 + index] >> (8 - shift);
			  teid8p++;
			}
		    }
		}

	      if (qfi)
		{
		  hdrlen =
		    sizeof (gtpu_exthdr_t) + sizeof (gtpu_pdu_session_t);
		}
	      else if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		       || gtpu_type == GTPU_TYPE_ECHO_REPLY
		       || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		{
		  hdrlen = sizeof (gtpu_exthdr_t);
		}

	      if (PREDICT_FALSE (gtpu_type == GTPU_TYPE_ECHO_REPLY))
		{
		  hdrlen += sizeof (gtpu_recovery_ie);
		}

	      if (PREDICT_FALSE (gtpu_type == GTPU_TYPE_ERROR_INDICATION))
		{
		  ip6_sr_tlv_t *tlv;
		  u16 ext_len;

		  ext_len = ip6srv0->sr.length * 8;

		  if (ext_len >
		      sizeof (ip6_address_t) * (ip6srv0->sr.last_entry + 1))
		    {
		      tlv =
			(ip6_sr_tlv_t *) ((u8 *) & ip6srv0->sr +
					  sizeof (ip6_sr_header_t) +
					  sizeof (ip6_address_t) *
					  (ip6srv0->sr.last_entry + 1));

		      if (tlv->type == SRH_TLV_USER_PLANE_CONTAINER)
			{
			  user_plane_sub_tlv_t *sub_tlv;

			  sub_tlv = (user_plane_sub_tlv_t *) tlv->value;

			  ie_size = sub_tlv->length;
			  clib_memcpy_fast (ie_buf, sub_tlv->value, ie_size);

			  hdrlen += ie_size;
			}
		    }
		}

	      if (ip6srv0->ip.protocol == IPPROTO_IPV6_ROUTE)
		{
		  vlib_buffer_advance (b0,
				       (word) sizeof (ip6srv_combo_header_t) +
				       ip6srv0->sr.length * 8);
		}
	      else
		{
		  vlib_buffer_advance (b0, (word) sizeof (ip6_header_t));
		}

	      // get length of encapsulated IPv6 packet (the remaining part)
	      p = vlib_buffer_get_current (b0);

	      plen = len0 = vlib_buffer_length_in_chain (vm, b0);

	      len0 += hdrlen;

	      hdrlen += sizeof (ip4_gtpu_header_t);

	      // IPv4 GTP-U header creation.
	      vlib_buffer_advance (b0, -(word) hdrlen);

	      hdr0 = vlib_buffer_get_current (b0);

	      clib_memcpy_fast (hdr0, &sm->cache_hdr,
				sizeof (ip4_gtpu_header_t));

	      hdr0->ip4.dst_address.as_u32 = dst4.as_u32;

	      hdr0->gtpu.teid = teid;
	      hdr0->gtpu.length = clib_host_to_net_u16 (len0);

	      hdr0->gtpu.type = gtpu_type;

	      if (qfi)
		{
		  u8 type = 0;
		  gtpu_pdu_session_t *sess;

		  hdr0->gtpu.ver_flags |= GTPU_EXTHDR_FLAG;

		  hdr0->gtpu.ext->seq = 0;

		  hdr0->gtpu.ext->npdu_num = 0;
		  hdr0->gtpu.ext->nextexthdr = GTPU_EXTHDR_PDU_SESSION;

		  type = qfi & SRV6_PDU_SESSION_U_BIT_MASK;

		  qfi =
		    ((qfi & SRV6_PDU_SESSION_QFI_MASK) >> 2) |
		    ((qfi & SRV6_PDU_SESSION_R_BIT_MASK) << 5);

		  sess =
		    (gtpu_pdu_session_t *) (((char *) hdr0) +
					    sizeof (ip4_gtpu_header_t) +
					    sizeof (gtpu_exthdr_t));
		  sess->exthdrlen = 1;
		  sess->type = type;
		  sess->spare = 0;
		  sess->u.val = qfi;
		  sess->nextexthdr = 0;
		}

	      if (gtpu_type == GTPU_TYPE_ECHO_REPLY
		  || gtpu_type == GTPU_TYPE_ECHO_REQUEST
		  || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		{
		  hdr0->gtpu.ver_flags |= GTPU_SEQ_FLAG;
		  hdr0->gtpu.ext->seq = seq;
		  hdr0->gtpu.ext->npdu_num = 0;
		  hdr0->gtpu.ext->nextexthdr = 0;

		  if (gtpu_type == GTPU_TYPE_ECHO_REPLY)
		    {
		      gtpu_recovery_ie *recovery;

		      recovery =
			(gtpu_recovery_ie *) ((u8 *) hdr0 +
					      (hdrlen -
					       sizeof (gtpu_recovery_ie)));
		      recovery->type = GTPU_RECOVERY_IE_TYPE;
		      recovery->restart_counter = 0;
		    }
		  else if (gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      if (ie_size)
			{
			  u8 *ie_ptr;

			  ie_ptr = (u8 *) ((u8 *) hdr0 + (hdrlen - ie_size));
			  clib_memcpy_fast (ie_ptr, ie_buf, ie_size);
			}
		    }
		}

	      offset = ls_param->v4src_position / 8;
	      shift = ls_param->v4src_position % 8;

	      if (PREDICT_TRUE (shift == 0))
		{
		  for (index = 0; index < 4; index++)
		    {
		      hdr0->ip4.src_address.as_u8[index] =
			src0.as_u8[offset + index];
		    }
		}
	      else
		{
		  for (index = 0; index < 4; index++)
		    {
		      hdr0->ip4.src_address.as_u8[index] =
			src0.as_u8[offset + index] << shift;
		      hdr0->ip4.src_address.as_u8[index] |=
			src0.as_u8[offset + index + 1] >> (8 - shift);
		    }
		}

	      key = hash_memory (p, plen < 40 ? plen : 40, 0);
	      port = hash_uword_to_u16 (&key);
	      hdr0->udp.src_port = port;

	      hdr0->udp.length = clib_host_to_net_u16 (len0 +
						       sizeof (udp_header_t) +
						       sizeof
						       (gtpu_header_t));

	      hdr0->ip4.length = clib_host_to_net_u16 (len0 +
						       sizeof
						       (ip4_gtpu_header_t));

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
	      &(sm2->sr_ls_valid_counters)), thread_index,
	     ls0 - sm2->localsids, 1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp4_e_node_index,
			       SRV6_END_ERROR_M_GTP4_E_BAD_PACKETS, bad_n);

  vlib_node_increment_counter (vm, sm->end_m_gtp4_e_node_index,
			       SRV6_END_ERROR_M_GTP4_E_PACKETS, good_n);

  return frame->n_vectors;
}

// Function for SRv6 GTP4.D function.
VLIB_NODE_FN (srv6_t_m_gtp4_d) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  srv6_t_main_v4_decap_t *sm = &srv6_t_main_v4_decap;
  ip6_sr_main_t *sm2 = &sr_main;
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
	  ip6_sr_sl_t *sl0;
	  srv6_end_gtp4_param_t *ls_param;
	  ip4_header_t *ip4;

	  uword len0;

	  u32 next0 = SRV6_T_M_GTP4_D_NEXT_LOOKUP;

	  // defaults
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sl0 =
	    pool_elt_at_index (sm2->sid_lists,
			       vnet_buffer (b0)->ip.adj_index);

	  ls_param = (srv6_end_gtp4_param_t *) sl0->plugin_mem;

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  ip4 = vlib_buffer_get_current (b0);

	  if (ip4->protocol != IP_PROTOCOL_UDP
	      || len0 < sizeof (ip4_gtpu_header_t))
	    {
	      next0 = SRV6_T_M_GTP4_D_NEXT_DROP;

	      bad_n++;
	    }
	  else
	    {
	      uword *p;
	      ip6_sr_policy_t *sr_policy = NULL;
	      ip6_sr_sl_t *sl = NULL;
	      u32 *sl_index;
	      u32 hdr_len;

	      ip4_gtpu_header_t *hdr;
	      ip4_address_t src, dst;
	      u8 *srcp, *dstp;
	      ip6_header_t *encap = NULL;
	      ip6_address_t seg;
	      ip6_address_t src6;
	      u8 gtpu_type;
	      u32 teid;
	      u8 *teidp;
	      u8 qfi = 0;
	      u8 *qfip = NULL;
	      u16 seq = 0;
	      u8 *seqp;
	      u32 offset, shift, index;
	      ip6srv_combo_header_t *ip6srv;
	      gtpu_pdu_session_t *sess = NULL;
	      int ie_size = 0;
	      u16 tlv_siz = 0;
	      u8 ie_buf[GTPU_IE_MAX_SIZ];

	      // Decap from GTP-U.
	      hdr = (ip4_gtpu_header_t *) ip4;

	      hdr_len = sizeof (ip4_gtpu_header_t);

	      teid = hdr->gtpu.teid;
	      teidp = (u8 *) & teid;

	      seqp = (u8 *) & seq;

	      gtpu_type = hdr->gtpu.type;

	      if (hdr->gtpu.ver_flags & (GTPU_EXTHDR_FLAG | GTPU_SEQ_FLAG))
		{
		  // Extention header.
		  hdr_len += sizeof (gtpu_exthdr_t);

		  seq = hdr->gtpu.ext->seq;

		  if (hdr->gtpu.ext->nextexthdr == GTPU_EXTHDR_PDU_SESSION)
		    {
		      // PDU Session Container.
		      sess =
			(gtpu_pdu_session_t *) (((char *) hdr) + hdr_len);
		      qfi = sess->u.val & ~GTPU_PDU_SESSION_P_BIT_MASK;
		      qfip = (u8 *) & qfi;

		      hdr_len += sizeof (gtpu_pdu_session_t);

		      if (sess->u.val & GTPU_PDU_SESSION_P_BIT_MASK)
			{
			  hdr_len += sizeof (gtpu_paging_policy_t);
			}
		    }
		}

	      src = hdr->ip4.src_address;
	      srcp = (u8 *) & src;

	      dst = hdr->ip4.dst_address;
	      dstp = (u8 *) & dst;

	      seg = ls_param->sr_prefix;

	      offset = ls_param->sr_prefixlen / 8;
	      shift = ls_param->sr_prefixlen % 8;

	      if (PREDICT_TRUE (shift == 0))
		{
		  clib_memcpy_fast (&seg.as_u8[offset], dstp, 4);

		  if (qfip)
		    {
		      qfi =
			((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

		      if (sess->type)
			{
			  qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
			}

		      seg.as_u8[offset + 4] = qfi;
		    }

		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      clib_memcpy_fast (&seg.as_u8[offset + 5], seqp, 2);
		    }
		  else
		    {
		      clib_memcpy_fast (&seg.as_u8[offset + 5], teidp, 4);
		    }
		}
	      else
		{
		  for (index = 0; index < 4; index++)
		    {
		      seg.as_u8[offset + index] |= dstp[index] >> shift;
		      seg.as_u8[offset + index + 1] |=
			dstp[index] << (8 - shift);
		    }

		  if (qfip)
		    {
		      qfi =
			((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

		      if (sess->type)
			{
			  qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
			}

		      seg.as_u8[offset + 4] |= qfi >> shift;
		      seg.as_u8[offset + 5] |= qfi << (8 - shift);
		    }

		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      for (index = 0; index < 2; index++)
			{
			  seg.as_u8[offset + 5 + index] |=
			    seqp[index] >> shift;
			  seg.as_u8[offset + 6 + index] |=
			    seqp[index] << (8 - shift);
			}
		    }
		  else
		    {
		      for (index = 0; index < 4; index++)
			{
			  seg.as_u8[offset + index + 5] |=
			    teidp[index] >> shift;
			  seg.as_u8[offset + index + 6] |=
			    teidp[index] << (8 - shift);
			}
		    }
		}

	      if (PREDICT_FALSE (gtpu_type == GTPU_TYPE_ERROR_INDICATION))
		{
		  u16 payload_len;

		  payload_len = clib_net_to_host_u16 (hdr->gtpu.length);
		  if (payload_len != 0)
		    {
		      ie_size =
			payload_len - (hdr_len - sizeof (ip4_gtpu_header_t));
		      if (ie_size > 0)
			{
			  u8 *ies;

			  ies = (u8 *) ((u8 *) hdr + hdr_len);
			  clib_memcpy_fast (ie_buf, ies, ie_size);
			  hdr_len += ie_size;
			}
		    }
		}

	      src6 = ls_param->v6src_prefix;

	      offset = ls_param->v6src_prefixlen / 8;
	      shift = ls_param->v6src_prefixlen % 8;

	      if (PREDICT_TRUE (shift == 0))
		{
		  clib_memcpy_fast (&src6.as_u8[offset], srcp, 4);
		}
	      else
		{
		  for (index = 0; index < 4; index++)
		    {
		      src6.as_u8[offset + index] |= srcp[offset] >> shift;
		      src6.as_u8[offset + index + 1] |=
			srcp[offset] << (8 - shift);
		    }
		}

	      vlib_buffer_advance (b0, (word) hdr_len);

	      // Encap to SRv6.
	      if (PREDICT_TRUE (gtpu_type == GTPU_TYPE_GTPU))
		{
		  encap = vlib_buffer_get_current (b0);
		}

	      len0 = vlib_buffer_length_in_chain (vm, b0);

	      p =
		mhash_get (&sm2->sr_policies_index_hash,
			   &ls_param->sr_prefix);
	      if (p)
		{
		  sr_policy = pool_elt_at_index (sm2->sr_policies, p[0]);
		}

	      if (sr_policy)
		{
		  vec_foreach (sl_index, sr_policy->segments_lists)
		  {
		    sl = pool_elt_at_index (sm2->sid_lists, *sl_index);
		    if (sl != NULL)
		      break;
		  }
		}

	      if (sl)
		{
		  hdr_len = sizeof (ip6srv_combo_header_t);
		  hdr_len += vec_len (sl->segments) * sizeof (ip6_address_t);
		  hdr_len += sizeof (ip6_address_t);
		}
	      else
		{
		  hdr_len = sizeof (ip6_header_t);

		  if (PREDICT_FALSE (gtpu_type != GTPU_TYPE_GTPU))
		    {
		      hdr_len += sizeof (ip6_sr_header_t);
		      hdr_len += sizeof (ip6_address_t);
		    }
		}

	      if (ie_size)
		{
		  tlv_siz =
		    sizeof (ip6_sr_tlv_t) + sizeof (user_plane_sub_tlv_t) +
		    ie_size;

		  tlv_siz = (tlv_siz & ~0x07) + (tlv_siz & 0x07 ? 0x08 : 0x0);
		  hdr_len += tlv_siz;
		}

	      vlib_buffer_advance (b0, -(word) hdr_len);
	      ip6srv = vlib_buffer_get_current (b0);

	      if (sl)
		{
		  clib_memcpy_fast (ip6srv, sl->rewrite,
				    vec_len (sl->rewrite));

		  if (vec_len (sl->segments) > 1)
		    {
		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments_left += 1;
		      ip6srv->sr.last_entry += 1;

		      ip6srv->sr.length += sizeof (ip6_address_t) / 8;
		      ip6srv->sr.segments[0] = seg;

		      clib_memcpy_fast (&ip6srv->sr.segments[1],
					(u8 *) (sl->rewrite +
						sizeof (ip6_header_t) +
						sizeof (ip6_sr_header_t)),
					vec_len (sl->segments) *
					sizeof (ip6_address_t));
		    }
		  else
		    {
		      ip6srv->ip.protocol = IP_PROTOCOL_IPV6_ROUTE;

		      ip6srv->sr.type = ROUTING_HEADER_TYPE_SR;

		      ip6srv->sr.segments_left = 1;
		      ip6srv->sr.last_entry = 0;

		      ip6srv->sr.length =
			((sizeof (ip6_sr_header_t) +
			  sizeof (ip6_address_t)) / 8) - 1;
		      ip6srv->sr.flags = 0;

		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments[0] = seg;
		      if (vec_len (sl->segments))
			{
			  ip6srv->sr.segments[1] = sl->segments[0];
			  ip6srv->sr.length += sizeof (ip6_address_t) / 8;
			  ip6srv->sr.last_entry++;
			}
		    }

		  if (PREDICT_TRUE (encap != NULL))
		    {
		      if (ls_param->nhtype == SRV6_NHTYPE_NONE)
			{
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) == 6)
			    ip6srv->sr.protocol = IP_PROTOCOL_IPV6;
			  else
			    ip6srv->sr.protocol = IP_PROTOCOL_IP_IN_IP;
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV4)
			{
			  ip6srv->sr.protocol = IP_PROTOCOL_IP_IN_IP;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 4)
			    {
			      // Bad encap packet.
			      next0 = SRV6_T_M_GTP4_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV6)
			{
			  ip6srv->sr.protocol = IP_PROTOCOL_IPV6;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 6)
			    {
			      // Bad encap packet.
			      next0 = SRV6_T_M_GTP4_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_NON_IP)
			{
			  ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;
			}
		    }
		  else
		    {
		      ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;
		    }
		}
	      else
		{
		  clib_memcpy_fast (ip6srv, &sm->cache_hdr,
				    sizeof (ip6_header_t));

		  ip6srv->ip.dst_address = seg;

		  if (PREDICT_FALSE (gtpu_type != GTPU_TYPE_GTPU))
		    {
		      ip6srv->ip.protocol = IP_PROTOCOL_IPV6_ROUTE;

		      ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;

		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments_left = 0;
		      ip6srv->sr.last_entry = 0;

		      ip6srv->sr.length = sizeof (ip6_address_t) / 8;
		      ip6srv->sr.segments[0] = seg;
		    }
		  else
		    {
		      if (ls_param->nhtype == SRV6_NHTYPE_NONE)
			{
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) == 6)
			    ip6srv->ip.protocol = IP_PROTOCOL_IPV6;
			  else
			    ip6srv->ip.protocol = IP_PROTOCOL_IP_IN_IP;
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV4)
			{
			  ip6srv->ip.protocol = IP_PROTOCOL_IP_IN_IP;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 4)
			    {
			      // Bad encap packet.
			      next0 = SRV6_T_M_GTP4_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV6)
			{
			  ip6srv->ip.protocol = IP_PROTOCOL_IPV6;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 6)
			    {
			      // Bad encap packet.
			      next0 = SRV6_T_M_GTP4_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_NON_IP)
			{
			  ip6srv->ip.protocol = IP_PROTOCOL_IP6_ETHERNET;
			}
		    }
		}

	      ip6srv->ip.src_address = src6;

	      if (PREDICT_FALSE (ie_size))
		{
		  ip6_sr_tlv_t *tlv;
		  user_plane_sub_tlv_t *sub_tlv;

		  tlv =
		    (ip6_sr_tlv_t *) ((u8 *) ip6srv + (hdr_len - tlv_siz));
		  tlv->type = SRH_TLV_USER_PLANE_CONTAINER;
		  tlv->length = (u8) (tlv_siz - sizeof (ip6_sr_tlv_t));
		  clib_memset (tlv->value, 0, tlv->length);

		  sub_tlv = (user_plane_sub_tlv_t *) tlv->value;
		  sub_tlv->type = USER_PLANE_SUB_TLV_IE;
		  sub_tlv->length = (u8) ie_size;
		  clib_memcpy_fast (sub_tlv->value, ie_buf, ie_size);

		  ip6srv->sr.length += (u8) (tlv_siz / 8);
		}

	      ip6srv->ip.payload_length =
		clib_host_to_net_u16 (len0 + hdr_len - sizeof (ip6_header_t));

	      good_n++;

	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  srv6_end_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy (tr->src.as_u8, ip6srv->ip.src_address.as_u8,
			       sizeof (tr->src.as_u8));
		  clib_memcpy (tr->dst.as_u8, ip6srv->ip.dst_address.as_u8,
			       sizeof (tr->dst.as_u8));
		}
	    }

	DONE:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->t_m_gtp4_d_node_index,
			       SRV6_T_ERROR_M_GTP4_D_BAD_PACKETS, bad_n);

  vlib_node_increment_counter (vm, sm->t_m_gtp4_d_node_index,
			       SRV6_T_ERROR_M_GTP4_D_PACKETS, good_n);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_end_m_gtp4_e) =
{
  .name = "srv6-end-m-gtp4-e",.vector_size = sizeof (u32),.format_trace =
    format_srv6_end_rewrite_trace,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (srv6_end_error_v4_strings),.error_strings =
    srv6_end_error_v4_strings,.n_next_nodes =
    SRV6_END_M_GTP4_E_N_NEXT,.next_nodes =
  {
  [SRV6_END_M_GTP4_E_NEXT_DROP] =
      "error-drop",[SRV6_END_M_GTP4_E_NEXT_LOOKUP] = "ip4-lookup",}
,};

VLIB_REGISTER_NODE (srv6_t_m_gtp4_d) =
{
  .name = "srv6-t-m-gtp4-d",.vector_size = sizeof (u32),.format_trace =
    format_srv6_end_rewrite_trace,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (srv6_t_error_v4_d_strings),.error_strings =
    srv6_t_error_v4_d_strings,.n_next_nodes =
    SRV6_T_M_GTP4_D_N_NEXT,.next_nodes =
  {
  [SRV6_T_M_GTP4_D_NEXT_DROP] =
      "error-drop",[SRV6_T_M_GTP4_D_NEXT_LOOKUP] = "ip6-lookup",}
,};

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
	  ip6_address_t dst0, src0, seg0;

	  ip6_gtpu_header_t *hdr0 = NULL;
	  uword len0;
	  uword key;
	  u16 port;
	  u16 tag;
	  void *p;
	  uword plen;

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
			       vnet_buffer (b0)->ip.adj_index);

	  ip6srv0 = vlib_buffer_get_current (b0);
	  dst0 = ip6srv0->ip.dst_address;
	  src0 = ip6srv0->ip.src_address;
	  seg0 = ip6srv0->sr.segments[0];

	  tag = ip6srv0->sr.tag;

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if ((ip6srv0->ip.protocol != IPPROTO_IPV6_ROUTE)
	      || (len0 <
		  sizeof (ip6srv_combo_header_t) + 8 * ip6srv0->sr.length))
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

	      u32 teid = 0;
	      u8 *teid8p = (u8 *) & teid;
	      u8 qfi = 0;
	      u16 seq = 0;
	      u8 gtpu_type = 0;
	      u16 index;
	      u16 offset, shift;
	      u32 hdrlen = 0;
	      u16 ie_size = 0;
	      u8 ie_buf[GTPU_IE_MAX_SIZ];

	      index = ls0->localsid_prefix_len;
	      index += 8;
	      offset = index / 8;
	      shift = index % 8;

	      gtpu_type = gtpu_type_get (tag);

	      if (PREDICT_TRUE (shift == 0))
		{
		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      clib_memcpy_fast (&seq, &dst0.as_u8[offset], 2);
		    }
		  else
		    {
		      clib_memcpy_fast (teid8p, &dst0.as_u8[offset], 4);
		    }

		  qfi = dst0.as_u8[offset + 4];
		}
	      else
		{
		  u8 *sp;

		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      sp = (u8 *) & seq;
		      for (index = 0; index < 2; index++)
			{
			  sp[index] = dst0.as_u8[offset + index] << shift;
			  sp[index] |=
			    dst0.as_u8[offset + index + 1] >> (8 - shift);
			}
		    }
		  else
		    {
		      for (index = 0; index < 4; index++)
			{
			  *teid8p = dst0.as_u8[offset + index] << shift;
			  *teid8p |=
			    dst0.as_u8[offset + index + 1] >> (8 - shift);
			  teid8p++;
			}
		    }

		  qfi |= dst0.as_u8[offset + 4] << shift;
		  qfi |= dst0.as_u8[offset + 5] >> (8 - shift);
		}

	      if (qfi)
		{
		  hdrlen =
		    sizeof (gtpu_exthdr_t) + sizeof (gtpu_pdu_session_t);
		}
	      else if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		       || gtpu_type == GTPU_TYPE_ECHO_REPLY
		       || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		{
		  hdrlen = sizeof (gtpu_exthdr_t);
		}

	      if (gtpu_type == GTPU_TYPE_ECHO_REPLY)
		{
		  hdrlen += sizeof (gtpu_recovery_ie);
		}

	      if (PREDICT_FALSE (gtpu_type == GTPU_TYPE_ERROR_INDICATION))
		{
		  ip6_sr_tlv_t *tlv;
		  u16 ext_len;

		  ext_len = ip6srv0->sr.length * 8;

		  if (ext_len >
		      sizeof (ip6_address_t) * (ip6srv0->sr.last_entry + 1))
		    {
		      tlv =
			(ip6_sr_tlv_t *) ((u8 *) & ip6srv0->sr +
					  sizeof (ip6_sr_header_t) +
					  sizeof (ip6_address_t) *
					  (ip6srv0->sr.last_entry + 1));

		      if (tlv->type == SRH_TLV_USER_PLANE_CONTAINER)
			{
			  user_plane_sub_tlv_t *sub_tlv;

			  sub_tlv = (user_plane_sub_tlv_t *) tlv->value;

			  ie_size = sub_tlv->length;
			  clib_memcpy_fast (ie_buf, sub_tlv->value, ie_size);

			  hdrlen += ie_size;
			}
		    }
		}

	      vlib_buffer_advance (b0,
				   (word) sizeof (ip6srv_combo_header_t) +
				   ip6srv0->sr.length * 8);

	      // get length of encapsulated IPv6 packet (the remaining part)
	      p = vlib_buffer_get_current (b0);

	      plen = len0 = vlib_buffer_length_in_chain (vm, b0);

	      len0 += hdrlen;

	      hdrlen += sizeof (ip6_gtpu_header_t);

	      vlib_buffer_advance (b0, -(word) hdrlen);

	      hdr0 = vlib_buffer_get_current (b0);

	      clib_memcpy_fast (hdr0, &sm->cache_hdr,
				sizeof (ip6_gtpu_header_t));

	      hdr0->gtpu.teid = teid;
	      hdr0->gtpu.length = clib_host_to_net_u16 (len0);

	      hdr0->gtpu.type = gtpu_type;

	      if (qfi)
		{
		  u8 type = 0;
		  gtpu_pdu_session_t *sess;

		  hdr0->gtpu.ver_flags |= GTPU_EXTHDR_FLAG;

		  hdr0->gtpu.ext->seq = 0;
		  hdr0->gtpu.ext->npdu_num = 0;
		  hdr0->gtpu.ext->nextexthdr = GTPU_EXTHDR_PDU_SESSION;

		  type = qfi & SRV6_PDU_SESSION_U_BIT_MASK;

		  qfi =
		    ((qfi & SRV6_PDU_SESSION_QFI_MASK) >> 2) |
		    ((qfi & SRV6_PDU_SESSION_R_BIT_MASK) << 5);

		  sess =
		    (gtpu_pdu_session_t *) (((char *) hdr0) +
					    sizeof (ip6_gtpu_header_t) +
					    sizeof (gtpu_exthdr_t));
		  sess->exthdrlen = 1;
		  sess->type = type;
		  sess->spare = 0;
		  sess->u.val = qfi;
		  sess->nextexthdr = 0;
		}

	      if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		  || gtpu_type == GTPU_TYPE_ECHO_REPLY
		  || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		{
		  hdr0->gtpu.ver_flags |= GTPU_SEQ_FLAG;
		  hdr0->gtpu.ext->seq = seq;
		  hdr0->gtpu.ext->npdu_num = 0;
		  hdr0->gtpu.ext->nextexthdr = 0;

		  if (gtpu_type == GTPU_TYPE_ECHO_REPLY)
		    {
		      gtpu_recovery_ie *recovery;

		      recovery =
			(gtpu_recovery_ie *) ((u8 *) hdr0 +
					      (hdrlen -
					       sizeof (gtpu_recovery_ie)));
		      recovery->type = GTPU_RECOVERY_IE_TYPE;
		      recovery->restart_counter = 0;
		    }
		  else if (gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      if (ie_size)
			{
			  u8 *ie_ptr;

			  ie_ptr = (u8 *) ((u8 *) hdr0 + (hdrlen - ie_size));
			  clib_memcpy_fast (ie_ptr, ie_buf, ie_size);
			}
		    }
		}

	      hdr0->udp.length = clib_host_to_net_u16 (len0 +
						       sizeof (udp_header_t) +
						       sizeof
						       (gtpu_header_t));

	      clib_memcpy_fast (hdr0->ip6.src_address.as_u8, src0.as_u8,
				sizeof (ip6_address_t));
	      clib_memcpy_fast (hdr0->ip6.dst_address.as_u8, &seg0.as_u8,
				sizeof (ip6_address_t));

	      hdr0->ip6.payload_length = clib_host_to_net_u16 (len0 +
							       sizeof
							       (udp_header_t)
							       +
							       sizeof
							       (gtpu_header_t));

	      // UDP source port.
	      key = hash_memory (p, plen < 40 ? plen : 40, 0);
	      port = hash_uword_to_u16 (&key);
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
	      &(sm2->sr_ls_valid_counters)), thread_index,
	     ls0 - sm2->localsids, 1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp6_e_node_index,
			       SRV6_END_ERROR_M_GTP6_E_BAD_PACKETS, bad_n);

  vlib_node_increment_counter (vm, sm->end_m_gtp6_e_node_index,
			       SRV6_END_ERROR_M_GTP6_E_PACKETS, good_n);

  return frame->n_vectors;
}

// Function for SRv6 GTP6.D function
VLIB_NODE_FN (srv6_end_m_gtp6_d) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  srv6_end_main_v6_decap_t *sm = &srv6_end_main_v6_decap;
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
	  srv6_end_gtp6_param_t *ls_param;

	  ip6_gtpu_header_t *hdr0 = NULL;
	  uword len0;

	  ip6_address_t seg0, src0;
	  u32 teid = 0;
	  u8 *teidp;
	  u8 gtpu_type = 0;
	  u8 qfi;
	  u8 *qfip = NULL;
	  u16 seq = 0;
	  u8 *seqp;
	  u32 offset, shift;
	  u32 hdrlen;
	  ip6_header_t *encap = NULL;
	  gtpu_pdu_session_t *sess = NULL;
	  int ie_size = 0;
	  u16 tlv_siz = 0;
	  u8 ie_buf[GTPU_IE_MAX_SIZ];

	  u32 next0 = SRV6_END_M_GTP6_D_NEXT_LOOKUP;

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
			       vnet_buffer (b0)->ip.adj_index);

	  ls_param = (srv6_end_gtp6_param_t *) ls0->plugin_mem;

	  hdr0 = vlib_buffer_get_current (b0);

	  hdrlen = sizeof (ip6_gtpu_header_t);

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if ((hdr0->ip6.protocol != IP_PROTOCOL_UDP)
	      || (hdr0->udp.dst_port !=
		  clib_host_to_net_u16 (SRV6_GTP_UDP_DST_PORT))
	      || (len0 < sizeof (ip6_gtpu_header_t)))
	    {
	      next0 = SRV6_END_M_GTP6_D_NEXT_DROP;

	      bad_n++;
	    }
	  else
	    {
	      seg0 = ls_param->sr_prefix;
	      src0 = hdr0->ip6.src_address;

	      gtpu_type = hdr0->gtpu.type;

	      teid = hdr0->gtpu.teid;
	      teidp = (u8 *) & teid;

	      seqp = (u8 *) & seq;

	      if (hdr0->gtpu.ver_flags & (GTPU_EXTHDR_FLAG | GTPU_SEQ_FLAG))
		{
		  // Extention header.
		  hdrlen += sizeof (gtpu_exthdr_t);

		  seq = hdr0->gtpu.ext->seq;

		  if (hdr0->gtpu.ext->nextexthdr == GTPU_EXTHDR_PDU_SESSION)
		    {
		      // PDU Session Container.
		      sess =
			(gtpu_pdu_session_t *) (((char *) hdr0) +
						sizeof (ip6_gtpu_header_t) +
						sizeof (gtpu_exthdr_t));
		      qfi = sess->u.val & ~GTPU_PDU_SESSION_P_BIT_MASK;
		      qfip = (u8 *) & qfi;

		      hdrlen += sizeof (gtpu_pdu_session_t);

		      if (sess->u.val & GTPU_PDU_SESSION_P_BIT_MASK)
			{
			  hdrlen += sizeof (gtpu_paging_policy_t);
			}
		    }
		}

	      offset = ls_param->sr_prefixlen / 8;
	      shift = ls_param->sr_prefixlen % 8;

	      offset += 1;
	      if (PREDICT_TRUE (shift == 0))
		{
		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      clib_memcpy_fast (&seg0.as_u8[offset], seqp, 2);
		    }
		  else
		    {
		      clib_memcpy_fast (&seg0.as_u8[offset], teidp, 4);
		    }

		  if (qfip)
		    {
		      qfi =
			((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

		      if (sess->type)
			{
			  qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
			}

		      seg0.as_u8[offset + 4] = qfi;
		    }
		}
	      else
		{
		  int idx;

		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      for (idx = 0; idx < 2; idx++)
			{
			  seg0.as_u8[offset + idx] |= seqp[idx] >> shift;
			  seg0.as_u8[offset + idx + 1] |=
			    seqp[idx] << (8 - shift);
			}
		    }
		  else
		    {
		      for (idx = 0; idx < 4; idx++)
			{
			  seg0.as_u8[offset + idx] |= teidp[idx] >> shift;
			  seg0.as_u8[offset + idx + 1] |=
			    teidp[idx] << (8 - shift);
			}
		    }

		  if (qfip)
		    {
		      qfi =
			((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & ~GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

		      if (sess->type)
			{
			  qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
			}

		      seg0.as_u8[offset + 4] |= qfi >> shift;
		      seg0.as_u8[offset + 5] |= qfi << (8 - shift);
		    }
		}

	      if (PREDICT_FALSE (gtpu_type == GTPU_TYPE_ERROR_INDICATION))
		{
		  u16 payload_len;

		  payload_len = clib_net_to_host_u16 (hdr0->gtpu.length);
		  if (payload_len != 0)
		    {
		      ie_size =
			payload_len - (hdrlen - sizeof (ip6_gtpu_header_t));
		      if (ie_size > 0)
			{
			  u8 *ies;

			  ies = (u8 *) ((u8 *) hdr0 + hdrlen);
			  clib_memcpy_fast (ie_buf, ies, ie_size);
			  hdrlen += ie_size;
			}
		    }
		}

	      // jump over variable length data
	      vlib_buffer_advance (b0, (word) hdrlen);

	      // get length of encapsulated IPv6 packet (the remaining part)
	      len0 = vlib_buffer_length_in_chain (vm, b0);

	      if (PREDICT_TRUE (gtpu_type == GTPU_TYPE_GTPU))
		{
		  encap = vlib_buffer_get_current (b0);
		}

	      uword *p;
	      ip6srv_combo_header_t *ip6srv;
	      ip6_sr_policy_t *sr_policy = NULL;
	      ip6_sr_sl_t *sl = NULL;
	      u32 *sl_index;
	      u32 hdr_len;

	      p =
		mhash_get (&sm2->sr_policies_index_hash,
			   &ls_param->sr_prefix);
	      if (p)
		{
		  sr_policy = pool_elt_at_index (sm2->sr_policies, p[0]);
		}

	      if (sr_policy)
		{
		  vec_foreach (sl_index, sr_policy->segments_lists)
		  {
		    sl = pool_elt_at_index (sm2->sid_lists, *sl_index);
		    if (sl != NULL)
		      break;
		  }
		}

	      if (sl)
		{
		  hdr_len = sizeof (ip6srv_combo_header_t);
		  hdr_len += vec_len (sl->segments) * sizeof (ip6_address_t);
		  hdr_len += sizeof (ip6_address_t);
		}
	      else
		{
		  hdr_len = sizeof (ip6_header_t);
		  if (PREDICT_FALSE (gtpu_type) != GTPU_TYPE_GTPU)
		    {
		      hdr_len += sizeof (ip6_sr_header_t);
		      hdr_len += sizeof (ip6_address_t);
		    }
		}

	      if (ie_size)
		{
		  tlv_siz =
		    sizeof (ip6_sr_tlv_t) + sizeof (user_plane_sub_tlv_t) +
		    ie_size;

		  tlv_siz = (tlv_siz & ~0x07) + (tlv_siz & 0x07 ? 0x08 : 0x0);
		  hdr_len += tlv_siz;
		}

	      // jump back to data[0] or pre_data if required
	      vlib_buffer_advance (b0, -(word) hdr_len);

	      ip6srv = vlib_buffer_get_current (b0);

	      if (sl)
		{
		  clib_memcpy_fast (ip6srv, sl->rewrite,
				    vec_len (sl->rewrite));

		  if (vec_len (sl->segments) > 1)
		    {
		      ip6srv->ip.src_address = src0;

		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments_left += 1;
		      ip6srv->sr.last_entry += 1;

		      ip6srv->sr.length += sizeof (ip6_address_t) / 8;
		      ip6srv->sr.segments[0] = seg0;

		      clib_memcpy_fast (&ip6srv->sr.segments[1],
					(u8 *) (sl->rewrite +
						sizeof (ip6_header_t) +
						sizeof (ip6_sr_header_t)),
					vec_len (sl->segments) *
					sizeof (ip6_address_t));
		    }
		  else
		    {
		      ip6srv->ip.src_address = src0;
		      ip6srv->ip.protocol = IP_PROTOCOL_IPV6_ROUTE;

		      ip6srv->sr.type = ROUTING_HEADER_TYPE_SR;
		      ip6srv->sr.segments_left = 1;
		      ip6srv->sr.last_entry = 0;
		      ip6srv->sr.length =
			((sizeof (ip6_sr_header_t) +
			  sizeof (ip6_address_t)) / 8) - 1;
		      ip6srv->sr.flags = 0;

		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments[0] = seg0;

		      if (vec_len (sl->segments))
			{
			  ip6srv->sr.segments[1] = sl->segments[0];
			  ip6srv->sr.last_entry++;
			  ip6srv->sr.length += sizeof (ip6_address_t) / 8;
			}
		    }

		  if (PREDICT_TRUE (encap != NULL))
		    {
		      if (ls_param->nhtype == SRV6_NHTYPE_NONE)
			{
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) == 6)
			    ip6srv->sr.protocol = IP_PROTOCOL_IPV6;
			  else
			    ip6srv->sr.protocol = IP_PROTOCOL_IP_IN_IP;
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV4)
			{
			  ip6srv->sr.protocol = IP_PROTOCOL_IP_IN_IP;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 4)
			    {
			      // Bad encap packet.
			      next0 = SRV6_END_M_GTP6_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV6)
			{
			  ip6srv->sr.protocol = IP_PROTOCOL_IPV6;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 6)
			    {
			      // Bad encap packet.
			      next0 = SRV6_END_M_GTP6_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_NON_IP)
			{
			  ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;
			}
		    }
		  else
		    {
		      ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;
		    }
		}
	      else
		{
		  clib_memcpy_fast (ip6srv, &sm->cache_hdr,
				    sizeof (ip6_header_t));

		  ip6srv->ip.src_address = src0;
		  ip6srv->ip.dst_address = seg0;

		  if (PREDICT_FALSE (gtpu_type) != GTPU_TYPE_GTPU)
		    {
		      ip6srv->ip.protocol = IP_PROTOCOL_IPV6_ROUTE;

		      ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;

		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments_left = 0;
		      ip6srv->sr.last_entry = 0;

		      ip6srv->sr.length = sizeof (ip6_address_t) / 8;
		      ip6srv->sr.segments[0] = seg0;
		    }
		  else
		    {
		      if (ls_param->nhtype == SRV6_NHTYPE_NONE)
			{
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 6)
			    ip6srv->ip.protocol = IP_PROTOCOL_IP_IN_IP;
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV4)
			{
			  ip6srv->ip.protocol = IP_PROTOCOL_IP_IN_IP;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 4)
			    {
			      // Bad encap packet.
			      next0 = SRV6_END_M_GTP6_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_IPV6)
			{
			  ip6srv->ip.protocol = IP_PROTOCOL_IPV6;
			  if ((clib_net_to_host_u32
			       (encap->ip_version_traffic_class_and_flow_label)
			       >> 28) != 6)
			    {
			      // Bad encap packet.
			      next0 = SRV6_END_M_GTP6_D_NEXT_DROP;
			      bad_n++;
			      goto DONE;
			    }
			}
		      else if (ls_param->nhtype == SRV6_NHTYPE_NON_IP)
			{
			  ip6srv->ip.protocol = IP_PROTOCOL_IP6_ETHERNET;
			}
		    }
		}

	      if (PREDICT_FALSE (ie_size))
		{
		  ip6_sr_tlv_t *tlv;
		  user_plane_sub_tlv_t *sub_tlv;

		  tlv =
		    (ip6_sr_tlv_t *) ((u8 *) ip6srv + (hdr_len - tlv_siz));
		  tlv->type = SRH_TLV_USER_PLANE_CONTAINER;
		  tlv->length = (u8) (tlv_siz - sizeof (ip6_sr_tlv_t));
		  clib_memset (tlv->value, 0, tlv->length);

		  sub_tlv = (user_plane_sub_tlv_t *) tlv->value;
		  sub_tlv->type = USER_PLANE_SUB_TLV_IE;
		  sub_tlv->length = (u8) ie_size;
		  clib_memcpy_fast (sub_tlv->value, ie_buf, ie_size);

		  ip6srv->sr.length += (u8) (tlv_siz / 8);
		}

	      ip6srv->ip.payload_length =
		clib_host_to_net_u16 (len0 + hdr_len - sizeof (ip6_header_t));

	      good_n++;

	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  srv6_end_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy (tr->src.as_u8, ip6srv->ip.src_address.as_u8,
			       sizeof (ip6_address_t));
		  clib_memcpy (tr->dst.as_u8, ip6srv->ip.dst_address.as_u8,
			       sizeof (ip6_address_t));
		  tr->teid = teid;
		  clib_memcpy (tr->sr_prefix.as_u8, ls_param->sr_prefix.as_u8,
			       sizeof (ip6_address_t));
		  tr->sr_prefixlen = ls_param->sr_prefixlen;
		}
	    }

	DONE:
	  vlib_increment_combined_counter
	    (((next0 ==
	       SRV6_END_M_GTP6_D_NEXT_DROP) ? &(sm2->sr_ls_invalid_counters) :
	      &(sm2->sr_ls_valid_counters)), thread_index,
	     ls0 - sm2->localsids, 1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp6_d_node_index,
			       SRV6_END_ERROR_M_GTP6_D_BAD_PACKETS, bad_n);

  vlib_node_increment_counter (vm, sm->end_m_gtp6_d_node_index,
			       SRV6_END_ERROR_M_GTP6_D_PACKETS, good_n);

  return frame->n_vectors;
}

// Function for SRv6 GTP6.D.DI function
VLIB_NODE_FN (srv6_end_m_gtp6_d_di) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  srv6_end_main_v6_decap_di_t *sm = &srv6_end_main_v6_decap_di;
  ip6_sr_main_t *sm2 = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 thread_index = vm->thread_index;
  srv6_end_gtp6_param_t *ls_param;

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

	  ip6_gtpu_header_t *hdr0 = NULL;
	  uword len0;

	  ip6_address_t dst0;
	  ip6_address_t src0;
	  ip6_address_t seg0;
	  u32 teid = 0;
	  u8 *teidp;
	  u8 gtpu_type = 0;
	  u8 qfi = 0;
	  u8 *qfip = NULL;
	  u16 seq = 0;
	  u8 *seqp;
	  u32 offset, shift;
	  u32 hdrlen;
	  ip6_header_t *encap = NULL;
	  gtpu_pdu_session_t *sess;
	  int ie_size = 0;
	  u16 tlv_siz = 0;
	  u8 ie_buf[GTPU_IE_MAX_SIZ];

	  u32 next0 = SRV6_END_M_GTP6_D_DI_NEXT_LOOKUP;

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
			       vnet_buffer (b0)->ip.adj_index);

	  ls_param = (srv6_end_gtp6_param_t *) ls0->plugin_mem;

	  hdr0 = vlib_buffer_get_current (b0);

	  hdrlen = sizeof (ip6_gtpu_header_t);

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if ((hdr0->ip6.protocol != IP_PROTOCOL_UDP)
	      || (hdr0->udp.dst_port !=
		  clib_host_to_net_u16 (SRV6_GTP_UDP_DST_PORT))
	      || (len0 < sizeof (ip6_gtpu_header_t)))
	    {
	      next0 = SRV6_END_M_GTP6_D_DI_NEXT_DROP;

	      bad_n++;
	    }
	  else
	    {
	      dst0 = hdr0->ip6.dst_address;
	      src0 = hdr0->ip6.src_address;

	      gtpu_type = hdr0->gtpu.type;

	      seg0 = ls_param->sr_prefix;
	      teid = hdr0->gtpu.teid;
	      teidp = (u8 *) & teid;

	      seqp = (u8 *) & seq;

	      if (hdr0->gtpu.ver_flags & (GTPU_EXTHDR_FLAG | GTPU_SEQ_FLAG))
		{
		  // Extention header.
		  hdrlen += sizeof (gtpu_exthdr_t);

		  seq = hdr0->gtpu.ext->seq;

		  if (hdr0->gtpu.ext->nextexthdr == GTPU_EXTHDR_PDU_SESSION)
		    {
		      // PDU Session Container.
		      sess =
			(gtpu_pdu_session_t *) (((char *) hdr0) + hdrlen);
		      qfi = sess->u.val & ~GTPU_PDU_SESSION_P_BIT_MASK;
		      qfip = &qfi;

		      hdrlen += sizeof (gtpu_pdu_session_t);

		      if (sess->u.val & GTPU_PDU_SESSION_P_BIT_MASK)
			{
			  hdrlen += sizeof (gtpu_paging_policy_t);
			}
		    }
		}

	      offset = ls_param->sr_prefixlen / 8;
	      shift = ls_param->sr_prefixlen % 8;

	      offset += 1;
	      if (PREDICT_TRUE (shift == 0))
		{
		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      clib_memcpy_fast (&seg0.as_u8[offset], seqp, 2);
		    }
		  else
		    {
		      clib_memcpy_fast (&seg0.as_u8[offset], teidp, 4);
		    }

		  if (qfip)
		    {
		      qfi =
			((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

		      if (sess->type)
			{
			  qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
			}

		      seg0.as_u8[offset + 4] = qfi;
		    }
		}
	      else
		{
		  int idx;

		  if (gtpu_type == GTPU_TYPE_ECHO_REQUEST
		      || gtpu_type == GTPU_TYPE_ECHO_REPLY
		      || gtpu_type == GTPU_TYPE_ERROR_INDICATION)
		    {
		      for (idx = 0; idx < 2; idx++)
			{
			  seg0.as_u8[offset + idx] |= seqp[idx] >> shift;
			  seg0.as_u8[offset + idx + 1] |=
			    seqp[idx] << (8 - shift);
			}
		    }
		  else
		    {
		      for (idx = 0; idx < 4; idx++)
			{
			  seg0.as_u8[offset + idx] |= teidp[idx] >> shift;
			  seg0.as_u8[offset + idx + 1] |=
			    teidp[idx] << (8 - shift);
			}
		    }

		  if (qfip)
		    {
		      qfi =
			((qfi & GTPU_PDU_SESSION_QFI_MASK) << 2) |
			((qfi & GTPU_PDU_SESSION_R_BIT_MASK) >> 5);

		      if (sess->type)
			{
			  qfi |= SRV6_PDU_SESSION_U_BIT_MASK;
			}

		      seg0.as_u8[offset + 4] |= qfi >> shift;
		      seg0.as_u8[offset + 5] |= qfi << (8 - shift);
		    }
		}

	      if (PREDICT_FALSE (gtpu_type == GTPU_TYPE_ERROR_INDICATION))
		{
		  u16 payload_len;

		  payload_len = clib_net_to_host_u16 (hdr0->gtpu.length);
		  if (payload_len != 0)
		    {
		      ie_size =
			payload_len - (hdrlen - sizeof (ip6_gtpu_header_t));
		      if (ie_size > 0)
			{
			  u8 *ies;

			  ies = (u8 *) ((u8 *) hdr0 + hdrlen);
			  clib_memcpy_fast (ie_buf, ies, ie_size);
			  hdrlen += ie_size;
			}
		    }
		}

	      // jump over variable length data
	      vlib_buffer_advance (b0, (word) hdrlen);

	      // get length of encapsulated IPv6 packet (the remaining part)
	      len0 = vlib_buffer_length_in_chain (vm, b0);

	      if (PREDICT_TRUE (gtpu_type == GTPU_TYPE_GTPU))
		{
		  encap = vlib_buffer_get_current (b0);
		}

	      uword *p;
	      ip6srv_combo_header_t *ip6srv;
	      ip6_sr_policy_t *sr_policy = NULL;
	      ip6_sr_sl_t *sl = NULL;
	      u32 *sl_index;
	      u32 hdr_len;

	      p =
		mhash_get (&sm2->sr_policies_index_hash,
			   &ls_param->sr_prefix);
	      if (p)
		{
		  sr_policy = pool_elt_at_index (sm2->sr_policies, p[0]);
		}

	      if (sr_policy)
		{
		  vec_foreach (sl_index, sr_policy->segments_lists)
		  {
		    sl = pool_elt_at_index (sm2->sid_lists, *sl_index);
		    if (sl != NULL)
		      break;
		  }
		}

	      hdr_len = sizeof (ip6srv_combo_header_t);

	      if (sl)
		hdr_len += vec_len (sl->segments) * sizeof (ip6_address_t);

	      hdr_len += sizeof (ip6_address_t) * 2;

	      if (ie_size)
		{
		  tlv_siz =
		    sizeof (ip6_sr_tlv_t) + sizeof (user_plane_sub_tlv_t) +
		    ie_size;

		  tlv_siz = (tlv_siz & ~0x07) + (tlv_siz & 0x07 ? 0x08 : 0x0);
		  hdr_len += tlv_siz;
		}

	      // jump back to data[0] or pre_data if required
	      vlib_buffer_advance (b0, -(word) hdr_len);

	      ip6srv = vlib_buffer_get_current (b0);

	      if (sl)
		{
		  clib_memcpy_fast (ip6srv, sl->rewrite,
				    vec_len (sl->rewrite));

		  if (vec_len (sl->segments) > 1)
		    {
		      ip6srv->ip.src_address = src0;

		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments_left += 2;
		      ip6srv->sr.last_entry += 2;

		      ip6srv->sr.length += ((sizeof (ip6_address_t) * 2) / 8);

		      ip6srv->sr.segments[0] = dst0;
		      ip6srv->sr.segments[1] = seg0;

		      clib_memcpy_fast (&ip6srv->sr.segments[2],
					(u8 *) (sl->rewrite +
						sizeof (ip6_header_t) +
						sizeof (ip6_sr_header_t)),
					vec_len (sl->segments) *
					sizeof (ip6_address_t));
		    }
		  else
		    {
		      ip6srv->ip.src_address = src0;
		      ip6srv->ip.protocol = IP_PROTOCOL_IPV6_ROUTE;

		      ip6srv->sr.type = ROUTING_HEADER_TYPE_SR;
		      ip6srv->sr.segments_left = 2;
		      ip6srv->sr.last_entry = 1;
		      ip6srv->sr.length =
			((sizeof (ip6_sr_header_t) +
			  2 * sizeof (ip6_address_t)) / 8) - 1;
		      ip6srv->sr.flags = 0;

		      ip6srv->sr.tag =
			clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		      ip6srv->sr.segments[0] = dst0;
		      ip6srv->sr.segments[1] = seg0;

		      if (vec_len (sl->segments))
			{
			  ip6srv->sr.segments[2] = sl->segments[0];
			  ip6srv->sr.last_entry++;
			  ip6srv->sr.length += sizeof (ip6_address_t) / 8;
			}
		    }
		}
	      else
		{
		  clib_memcpy_fast (ip6srv, &sm->cache_hdr,
				    sizeof (ip6_header_t));

		  ip6srv->ip.src_address = src0;
		  ip6srv->ip.dst_address = seg0;

		  ip6srv->sr.type = ROUTING_HEADER_TYPE_SR;
		  ip6srv->sr.segments_left = 1;
		  ip6srv->sr.last_entry = 0;
		  ip6srv->sr.length =
		    ((sizeof (ip6_sr_header_t) +
		      sizeof (ip6_address_t)) / 8) - 1;
		  ip6srv->sr.flags = 0;

		  ip6srv->sr.tag =
		    clib_host_to_net_u16 (srh_tagfield[gtpu_type]);

		  ip6srv->sr.segments[0] = dst0;
		}

	      if (PREDICT_FALSE (ie_size))
		{
		  ip6_sr_tlv_t *tlv;
		  user_plane_sub_tlv_t *sub_tlv;

		  tlv =
		    (ip6_sr_tlv_t *) ((u8 *) ip6srv + (hdr_len - tlv_siz));
		  tlv->type = SRH_TLV_USER_PLANE_CONTAINER;
		  tlv->length = (u8) (tlv_siz - sizeof (ip6_sr_tlv_t));
		  clib_memset (tlv->value, 0, tlv->length);

		  sub_tlv = (user_plane_sub_tlv_t *) tlv->value;
		  sub_tlv->length = (u8) (ie_size);
		  clib_memcpy_fast (sub_tlv->value, ie_buf, ie_size);

		  ip6srv->sr.length += (u8) (tlv_siz / 8);
		}

	      ip6srv->ip.payload_length =
		clib_host_to_net_u16 (len0 + hdr_len - sizeof (ip6_header_t));
	      ip6srv->ip.protocol = IP_PROTOCOL_IPV6_ROUTE;

	      if (PREDICT_TRUE (encap != NULL))
		{
		  if (ls_param->nhtype == SRV6_NHTYPE_NONE)
		    {
		      if ((clib_net_to_host_u32
			   (encap->ip_version_traffic_class_and_flow_label) >>
			   28) == 6)
			ip6srv->sr.protocol = IP_PROTOCOL_IPV6;
		      else
			ip6srv->sr.protocol = IP_PROTOCOL_IP_IN_IP;
		    }
		  else if (ls_param->nhtype == SRV6_NHTYPE_IPV4)
		    {
		      ip6srv->sr.protocol = IP_PROTOCOL_IP_IN_IP;
		      if ((clib_net_to_host_u32
			   (encap->ip_version_traffic_class_and_flow_label) >>
			   28) != 4)
			{
			  // Bad encap packet.
			  next0 = SRV6_END_M_GTP6_D_DI_NEXT_DROP;
			  bad_n++;
			  goto DONE;
			}
		    }
		  else if (ls_param->nhtype == SRV6_NHTYPE_IPV6)
		    {
		      ip6srv->sr.protocol = IP_PROTOCOL_IPV6;
		      if ((clib_net_to_host_u32
			   (encap->ip_version_traffic_class_and_flow_label) >>
			   28) != 6)
			{
			  // Bad encap packet.
			  next0 = SRV6_END_M_GTP6_D_DI_NEXT_DROP;
			  bad_n++;
			  goto DONE;
			}
		    }
		  else if (ls_param->nhtype == SRV6_NHTYPE_NON_IP)
		    {
		      ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;
		    }
		}
	      else
		{
		  ip6srv->sr.protocol = IP_PROTOCOL_IP6_ETHERNET;
		}

	      good_n++;

	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  srv6_end_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy (tr->src.as_u8, ip6srv->ip.src_address.as_u8,
			       sizeof (ip6_address_t));
		  clib_memcpy (tr->dst.as_u8, ip6srv->ip.dst_address.as_u8,
			       sizeof (ip6_address_t));
		  tr->teid = teid;
		  clib_memcpy (tr->sr_prefix.as_u8, ls_param->sr_prefix.as_u8,
			       sizeof (ip6_address_t));
		  tr->sr_prefixlen = ls_param->sr_prefixlen;
		}
	    }

	DONE:
	  vlib_increment_combined_counter
	    (((next0 ==
	       SRV6_END_M_GTP6_D_DI_NEXT_DROP) ?
	      &(sm2->sr_ls_invalid_counters) : &(sm2->sr_ls_valid_counters)),
	     thread_index, ls0 - sm2->localsids, 1,
	     vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp6_d_di_node_index,
			       SRV6_END_ERROR_M_GTP6_D_DI_BAD_PACKETS, bad_n);

  vlib_node_increment_counter (vm, sm->end_m_gtp6_d_di_node_index,
			       SRV6_END_ERROR_M_GTP6_D_DI_PACKETS, good_n);

  return frame->n_vectors;
}

// Function for SRv6 GTP6.DT function
VLIB_NODE_FN (srv6_end_m_gtp6_dt) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  srv6_end_main_v6_dt_t *sm = &srv6_end_main_v6_dt;
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
	  srv6_end_gtp6_dt_param_t *ls_param;
	  ip6_sr_localsid_t *ls0;

	  ip6_gtpu_header_t *hdr0 = NULL;
	  ip4_header_t *ip4 = NULL;
	  ip6_header_t *ip6 = NULL;
	  ip6_address_t src, dst;
	  u32 teid;
	  u32 hdrlen;
	  u32 len0;

	  u32 next0 = SRV6_END_M_GTP6_DT_NEXT_DROP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ls0 =
	    pool_elt_at_index (sm2->localsids,
			       vnet_buffer (b0)->ip.adj_index);

	  ls_param = (srv6_end_gtp6_dt_param_t *) ls0->plugin_mem;

	  hdr0 = vlib_buffer_get_current (b0);

	  hdrlen = sizeof (ip6_gtpu_header_t);

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if ((hdr0->ip6.protocol != IP_PROTOCOL_UDP)
	      || (hdr0->udp.dst_port !=
		  clib_host_to_net_u16 (SRV6_GTP_UDP_DST_PORT))
	      || (len0 < sizeof (ip6_gtpu_header_t)))
	    {
	      next0 = SRV6_END_M_GTP6_DT_NEXT_DROP;

	      bad_n++;
	    }
	  else
	    {
	      clib_memcpy_fast (src.as_u8, hdr0->ip6.src_address.as_u8,
				sizeof (ip6_address_t));
	      clib_memcpy_fast (dst.as_u8, hdr0->ip6.dst_address.as_u8,
				sizeof (ip6_address_t));

	      teid = hdr0->gtpu.teid;

	      if (hdr0->gtpu.ver_flags & GTPU_EXTHDR_FLAG)
		{
		  hdrlen += sizeof (gtpu_exthdr_t);
		  if (hdr0->gtpu.ext->nextexthdr == GTPU_EXTHDR_PDU_SESSION)
		    {
		      gtpu_pdu_session_t *sess;

		      sess =
			(gtpu_pdu_session_t *) (((char *) hdr0) +
						sizeof (ip6_gtpu_header_t) +
						sizeof (gtpu_exthdr_t));

		      hdrlen += sizeof (gtpu_pdu_session_t);
		      if (sess->u.val & GTPU_PDU_SESSION_P_BIT_MASK)
			{
			  hdrlen += sizeof (gtpu_paging_policy_t);
			}
		    }
		}

	      if (ls_param->type == SRV6_GTP6_DT4)
		{
		  vlib_buffer_advance (b0, (word) hdrlen);
		  ip4 = vlib_buffer_get_current (b0);
		  if ((ip4->ip_version_and_header_length & 0xf0) != 0x40)
		    {
		      next0 = SRV6_END_M_GTP6_DT_NEXT_DROP;
		      bad_n++;
		      goto DONE;
		    }

		  next0 = SRV6_END_M_GTP6_DT_NEXT_LOOKUP4;
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
		    ls_param->fib4_index;
		}
	      else if (ls_param->type == SRV6_GTP6_DT6)
		{
		  ip6 = (ip6_header_t *) ((u8 *) hdr0 + hdrlen);
		  if ((clib_net_to_host_u32
		       (ip6->ip_version_traffic_class_and_flow_label) >> 28)
		      != 6)
		    {
		      next0 = SRV6_END_M_GTP6_DT_NEXT_DROP;
		      bad_n++;
		      goto DONE;
		    }

		  next0 = SRV6_END_M_GTP6_DT_NEXT_LOOKUP6;
		  if ((ip6->dst_address.as_u8[0] == 0xff)
		      && ((ip6->dst_address.as_u8[1] & 0xc0) == 0x80))
		    {
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			ls_param->local_fib_index;
		    }
		  else
		    {
		      vlib_buffer_advance (b0, (word) hdrlen);
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			ls_param->fib6_index;
		    }
		}
	      else if (ls_param->type == SRV6_GTP6_DT46)
		{
		  ip6 = (ip6_header_t *) ((u8 *) hdr0 + hdrlen);
		  if ((clib_net_to_host_u32
		       (ip6->ip_version_traffic_class_and_flow_label) >> 28)
		      == 6)
		    {
		      next0 = SRV6_END_M_GTP6_DT_NEXT_LOOKUP6;
		      if ((ip6->dst_address.as_u8[0] == 0xff)
			  && ((ip6->dst_address.as_u8[1] & 0xc0) == 0x80))
			{
			  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			    ls_param->local_fib_index;
			}
		      else
			{
			  vlib_buffer_advance (b0, (word) hdrlen);
			  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			    ls_param->fib6_index;
			}
		    }
		  else
		    if ((clib_net_to_host_u32
			 (ip6->ip_version_traffic_class_and_flow_label) >> 28)
			== 4)
		    {
		      vlib_buffer_advance (b0, (word) hdrlen);
		      next0 = SRV6_END_M_GTP6_DT_NEXT_LOOKUP4;
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			ls_param->fib4_index;
		    }
		  else
		    {
		      next0 = SRV6_END_M_GTP6_DT_NEXT_DROP;
		      bad_n++;
		      goto DONE;
		    }
		}
	      else
		{
		  next0 = SRV6_END_M_GTP6_DT_NEXT_DROP;
		  bad_n++;
		  goto DONE;
		}

	      good_n++;

	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  srv6_end_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy (tr->src.as_u8, src.as_u8,
			       sizeof (ip6_address_t));
		  clib_memcpy (tr->dst.as_u8, dst.as_u8,
			       sizeof (ip6_address_t));
		  tr->teid = teid;
		}
	    }

	DONE:
	  vlib_increment_combined_counter
	    (((next0 ==
	       SRV6_END_M_GTP6_DT_NEXT_DROP) ? &(sm2->sr_ls_invalid_counters)
	      : &(sm2->sr_ls_valid_counters)), thread_index,
	     ls0 - sm2->localsids, 1, vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->end_m_gtp6_dt_node_index,
			       SRV6_END_ERROR_M_GTP6_DT_BAD_PACKETS, bad_n);

  vlib_node_increment_counter (vm, sm->end_m_gtp6_dt_node_index,
			       SRV6_END_ERROR_M_GTP6_DT_PACKETS, good_n);

  return frame->n_vectors;
}

// Function for SRv6 GTP4.DT function
VLIB_NODE_FN (srv6_t_m_gtp4_dt) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  srv6_t_main_v4_dt_t *sm = &srv6_t_main_v4_dt;
  ip6_sr_main_t *sm2 = &sr_main;
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
	  srv6_t_gtp4_dt_param_t *ls_param;
	  ip6_sr_sl_t *ls0;

	  ip4_gtpu_header_t *hdr0 = NULL;
	  ip4_header_t *ip4 = NULL;
	  ip6_header_t *ip6 = NULL;
	  ip6_address_t src, dst;
	  u32 teid;
	  u32 hdrlen;
	  u32 len0;

	  u32 next0 = SRV6_T_M_GTP4_DT_NEXT_DROP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ls0 =
	    pool_elt_at_index (sm2->sid_lists,
			       vnet_buffer (b0)->ip.adj_index);

	  ls_param = (srv6_t_gtp4_dt_param_t *) ls0->plugin_mem;

	  hdr0 = vlib_buffer_get_current (b0);

	  hdrlen = sizeof (ip4_gtpu_header_t);

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if ((hdr0->ip4.protocol != IP_PROTOCOL_UDP)
	      || (hdr0->udp.dst_port !=
		  clib_host_to_net_u16 (SRV6_GTP_UDP_DST_PORT))
	      || (len0 < sizeof (ip4_gtpu_header_t)))
	    {
	      next0 = SRV6_T_M_GTP4_DT_NEXT_DROP;

	      bad_n++;
	    }
	  else
	    {
	      clib_memcpy_fast (src.as_u8, hdr0->ip4.src_address.as_u8,
				sizeof (ip4_address_t));
	      clib_memcpy_fast (dst.as_u8, hdr0->ip4.dst_address.as_u8,
				sizeof (ip4_address_t));

	      teid = hdr0->gtpu.teid;

	      if (hdr0->gtpu.ver_flags & GTPU_EXTHDR_FLAG)
		{
		  hdrlen += sizeof (gtpu_exthdr_t);
		  if (hdr0->gtpu.ext->nextexthdr == GTPU_EXTHDR_PDU_SESSION)
		    {
		      gtpu_pdu_session_t *sess;

		      sess =
			(gtpu_pdu_session_t *) (((char *) hdr0) +
						sizeof (ip6_gtpu_header_t) +
						sizeof (gtpu_exthdr_t));

		      hdrlen += sizeof (gtpu_pdu_session_t);
		      if (sess->u.val & GTPU_PDU_SESSION_P_BIT_MASK)
			{
			  hdrlen += sizeof (gtpu_paging_policy_t);
			}
		    }
		}

	      if (ls_param->type == SRV6_GTP4_DT4)
		{
		  vlib_buffer_advance (b0, (word) hdrlen);
		  ip4 = vlib_buffer_get_current (b0);
		  if ((ip4->ip_version_and_header_length & 0xf0) != 0x40)
		    {
		      next0 = SRV6_T_M_GTP4_DT_NEXT_DROP;
		      bad_n++;
		      goto DONE;
		    }

		  next0 = SRV6_T_M_GTP4_DT_NEXT_LOOKUP4;
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
		    ls_param->fib4_index;
		}
	      else if (ls_param->type == SRV6_GTP4_DT6)
		{
		  ip6 = (ip6_header_t *) ((u8 *) hdr0 + hdrlen);
		  if ((clib_net_to_host_u32
		       (ip6->ip_version_traffic_class_and_flow_label) >> 28)
		      != 6)
		    {
		      next0 = SRV6_T_M_GTP4_DT_NEXT_DROP;
		      bad_n++;
		      goto DONE;
		    }

		  next0 = SRV6_T_M_GTP4_DT_NEXT_LOOKUP6;
		  if ((ip6->dst_address.as_u8[0] == 0xff)
		      && ((ip6->dst_address.as_u8[1] & 0xc0) == 0x80))
		    {
		      next0 = SRV6_T_M_GTP4_DT_NEXT_LOOKUP4;
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			ls_param->local_fib_index;
		    }
		  else
		    {
		      vlib_buffer_advance (b0, (word) hdrlen);
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			ls_param->fib6_index;
		    }
		}
	      else if (ls_param->type == SRV6_GTP4_DT46)
		{
		  ip6 = (ip6_header_t *) ((u8 *) hdr0 + hdrlen);
		  if ((clib_net_to_host_u32
		       (ip6->ip_version_traffic_class_and_flow_label) >> 28)
		      == 6)
		    {
		      next0 = SRV6_T_M_GTP4_DT_NEXT_LOOKUP6;
		      if ((ip6->dst_address.as_u8[0] == 0xff)
			  && ((ip6->dst_address.as_u8[1] & 0xc0) == 0x80))
			{
			  next0 = SRV6_T_M_GTP4_DT_NEXT_LOOKUP4;
			  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			    ls_param->local_fib_index;
			}
		      else
			{
			  vlib_buffer_advance (b0, (word) hdrlen);
			  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			    ls_param->fib6_index;
			}
		    }
		  else
		    if ((clib_net_to_host_u32
			 (ip6->ip_version_traffic_class_and_flow_label) >> 28)
			== 4)
		    {
		      vlib_buffer_advance (b0, (word) hdrlen);
		      next0 = SRV6_T_M_GTP4_DT_NEXT_LOOKUP4;
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			ls_param->fib4_index;
		    }
		  else
		    {
		      next0 = SRV6_T_M_GTP4_DT_NEXT_DROP;
		      bad_n++;
		      goto DONE;
		    }
		}
	      else
		{
		  next0 = SRV6_T_M_GTP4_DT_NEXT_DROP;
		  bad_n++;
		  goto DONE;
		}

	      good_n++;

	      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  srv6_end_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy (tr->src.as_u8, src.as_u8,
			       sizeof (ip6_address_t));
		  clib_memcpy (tr->dst.as_u8, dst.as_u8,
			       sizeof (ip6_address_t));
		  tr->teid = teid;
		}
	    }

	DONE:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sm->t_m_gtp4_dt_node_index,
			       SRV6_T_ERROR_M_GTP4_DT_BAD_PACKETS, bad_n);

  vlib_node_increment_counter (vm, sm->t_m_gtp4_dt_node_index,
			       SRV6_T_ERROR_M_GTP4_DT_PACKETS, good_n);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_end_m_gtp6_e) =
{
  .name = "srv6-end-m-gtp6-e",.vector_size = sizeof (u32),.format_trace =
    format_srv6_end_rewrite_trace6,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (srv6_end_error_v6_e_strings),.error_strings =
    srv6_end_error_v6_e_strings,.n_next_nodes =
    SRV6_END_M_GTP6_E_N_NEXT,.next_nodes =
  {
  [SRV6_END_M_GTP6_E_NEXT_DROP] =
      "error-drop",[SRV6_END_M_GTP6_E_NEXT_LOOKUP] = "ip6-lookup",}
,};

VLIB_REGISTER_NODE (srv6_end_m_gtp6_d) =
{
  .name = "srv6-end-m-gtp6-d",.vector_size = sizeof (u32),.format_trace =
    format_srv6_end_rewrite_trace6,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (srv6_end_error_v6_d_strings),.error_strings =
    srv6_end_error_v6_d_strings,.n_next_nodes =
    SRV6_END_M_GTP6_D_N_NEXT,.next_nodes =
  {
  [SRV6_END_M_GTP6_D_NEXT_DROP] =
      "error-drop",[SRV6_END_M_GTP6_D_NEXT_LOOKUP] = "ip6-lookup",}
,};

VLIB_REGISTER_NODE (srv6_end_m_gtp6_d_di) =
{
  .name = "srv6-end-m-gtp6-d-di",.vector_size = sizeof (u32),.format_trace =
    format_srv6_end_rewrite_trace6,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (srv6_end_error_v6_d_di_strings),.error_strings =
    srv6_end_error_v6_d_di_strings,.n_next_nodes =
    SRV6_END_M_GTP6_D_DI_N_NEXT,.next_nodes =
  {
  [SRV6_END_M_GTP6_D_DI_NEXT_DROP] = "error-drop",
      [SRV6_END_M_GTP6_D_DI_NEXT_LOOKUP] = "ip6-lookup",}
,};

VLIB_REGISTER_NODE (srv6_end_m_gtp6_dt) =
{
  .name = "srv6-end-m-gtp6-dt",.vector_size = sizeof (u32),.format_trace =
    format_srv6_end_rewrite_trace6,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (srv6_end_error_v6_dt_strings),.error_strings =
    srv6_end_error_v6_dt_strings,.n_next_nodes =
    SRV6_END_M_GTP6_DT_N_NEXT,.next_nodes =
  {
  [SRV6_END_M_GTP6_DT_NEXT_DROP] =
      "error-drop",
      [SRV6_END_M_GTP6_DT_NEXT_LOOKUP4]
      = "ip4-lookup",[SRV6_END_M_GTP6_DT_NEXT_LOOKUP6] = "ip6-lookup",}
,};

VLIB_REGISTER_NODE (srv6_t_m_gtp4_dt) =
{
  .name = "srv6-t-m-gtp4-dt",.vector_size = sizeof (u32),.format_trace =
    format_srv6_end_rewrite_trace6,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (srv6_t_error_v4_dt_strings),.error_strings =
    srv6_t_error_v4_dt_strings,.n_next_nodes =
    SRV6_T_M_GTP4_DT_N_NEXT,.next_nodes =
  {
  [SRV6_T_M_GTP4_DT_NEXT_DROP] =
      "error-drop",
      [SRV6_T_M_GTP4_DT_NEXT_LOOKUP4] =
      "ip4-lookup",[SRV6_T_M_GTP4_DT_NEXT_LOOKUP6] = "ip6-lookup",}
,};

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
