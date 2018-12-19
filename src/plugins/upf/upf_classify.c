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

#define _LGPL_SOURCE		/* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>		/* QSBR RCU flavor */

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_adf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if (CLIB_DEBUG > 0)
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_classify_error		\
  _(CLASSIFY, "good packets classify")

static char *upf_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_classify_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_CLASSIFY_ERROR_##sym,
  foreach_upf_classify_error
#undef _
    UPF_CLASSIFY_N_ERROR,
} upf_classify_error_t;

typedef enum
{
  UPF_CLASSIFY_NEXT_DROP,
  UPF_CLASSIFY_NEXT_PROCESS,
  UPF_CLASSIFY_N_NEXT,
} upf_classify_next_t;

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
upf_classify_trace_t;

static u8 *
format_upf_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_classify_trace_t *t = va_arg (*args, upf_classify_trace_t *);
  u32 indent = format_get_indent (s);

  s =
    format (s,
	    "upf_session%d cp-seid 0x%016" PRIx64
	    " pdr %d, next_index = %d\n%U%U", t->session_index, t->cp_seid,
	    t->pdr_idx, t->next_index, format_white_space, indent,
	    format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

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

always_inline int
ip4_address_is_equal (const ip4_address_t * a, const ip4_address_t * b)
{
  return a->as_u32 == b->as_u32;
}

always_inline int
ip4_address_is_equal_masked (const ip4_address_t * a,
			     const ip4_address_t * b,
			     const ip4_address_t * mask)
{
  gtp_debug ("IP: %U/%U, %U\n",
	     format_ip4_address, a,
	     format_ip4_address, b, format_ip4_address, mask);

  return (a->as_u32 & mask->as_u32) == (b->as_u32 & mask->as_u32);
}

always_inline u8 *
upf_adr_try_tls (u16 port, u8 *p, word length)
{
  struct tls_record_hdr *hdr = (struct tls_record_hdr *)p;
  struct tls_handshake_hdr *hsk = (struct tls_handshake_hdr *)(hdr + 1);
  struct tls_client_hello_hdr *hlo = (struct tls_client_hello_hdr *)(hsk + 1);
  u8 * data = (u8 *)(hlo + 1);
  word frgmt_len, hsk_len, len;
  u8 * url = NULL;

  clib_warning("Length: %d", length);
  if (length < sizeof(*hdr))
    return NULL;

  clib_warning("HDR: %u, v: %u.%u, Len: %d",
	       hdr->type, hdr->major, hdr->minor, clib_net_to_host_u16(hdr->length));
  if (hdr->type != TLS_HANDSHAKE)
    return NULL;

  if (hdr->major != 3 || hdr->minor < 1 || hdr->minor > 3)
    /* TLS 1.0, 1.1 and 1.2 only (for now)
     * SSLv2 backward-compatible hello is not supported
     */
    return NULL;

  length -= sizeof(*hdr);
  frgmt_len = clib_net_to_host_u16(hdr->length);

  if (length < frgmt_len)
    /* TLS fragment is longer that IP payload */
    return NULL;

  hsk_len = hsk->length[0] << 16 | hsk->length[1] << 8 | hsk->length[2];
  clib_warning("TLS Hello: %u, v: Len: %d", hsk->type, hsk_len);

  if (hsk_len + sizeof(*hsk) < frgmt_len)
    /* Hello is longer that the current fragment */
    return NULL;

  if (hsk->type != TLS_CLIENT_HELLO)
    return NULL;

  clib_warning("TLS Client Hello: %u.%u", hlo->major, hlo->minor);
  if (hlo->major != 3 || hlo->minor < 1 || hlo->minor > 3)
    /* TLS 1.0, 1.1 and 1.2 only (for now) */
    return NULL;

  len = hsk_len - sizeof(*hlo);

  /* Session Id */
  if (len < *data + 1) return NULL;
  len -= *data + 1;
  data += *data + 1;

  /* Cipher Suites */
  if (len < clib_net_to_host_unaligned_mem_u16((u16 *)data) + 2) return NULL;
  len -= clib_net_to_host_unaligned_mem_u16((u16 *)data) + 2;
  data += clib_net_to_host_unaligned_mem_u16((u16 *)data) + 2;

  /* Compression Methods */
  if (len < *data + 1) return NULL;
  len -= *data + 1;
  data += *data + 1;

  /* Extensions */
  if (len < clib_net_to_host_unaligned_mem_u16((u16 *)data) + 2) return NULL;
  len = clib_net_to_host_unaligned_mem_u16((u16 *)data);
  data += 2;

  while (len > 4)
    {
      u16 ext_type = clib_net_to_host_unaligned_mem_u16((u16 *)data);
      u16 ext_len = clib_net_to_host_unaligned_mem_u16((u16 *)(data + 2));

      clib_warning("TLS Hello Extension: %u, %u", ext_type, ext_len);

      if (ext_type == TLS_EXT_SNI && ext_len != 0)
	{
	  vec_add (url, "https://", sizeof ("https://"));
	  vec_add (url, data + 4, ext_len);
	  if (port != 443)
	    url = format (url, ":%u", port);
	  vec_add1 (url, '/');

	  return url;
	}

      len -= ext_len + 4;
      data += ext_len + 4;
    }

  return NULL;
}

always_inline u8 *
upf_adr_try_http (u16 port, u8 *p, word len)
{
  u8 *host;
  word uri_len;
  u8 *eol;
  u8 *s;
  u8 *url = NULL;

  if (!is_http_request (&p, &len))
    /* payload to short, abort ADR scanning for this flow */
    return NULL;

  eol = memchr (p, '\n', len);
  if (!eol)
    /* not EOL found */
    return NULL;

  s = memchr (p, ' ', eol - p);
  if (!s)
    /* HTTP/0.9 - can find the Host Header */
    return NULL;

  uri_len = s - p;

  {
    u64 d0 = *(u64 *) (s + 1);

    if (d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '0') &&
	d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '1'))
      /* not HTTP 1.0 or 1.1 compatible */
      return NULL;
  }

  host = eol + 1;
  len -= (eol - p) + 1;

  while (len > 0)
    {
      if (is_host_header (&host, &len))
	break;
    }

  if (len <= 0)
    return NULL;

  vec_add (url, "http://", sizeof ("http://"));
  vec_add (url, host, len);
  if (port != 80)
    url = format (url, ":%u", port);
  vec_add (url, p, uri_len);

  return url;
}

always_inline void
upf_application_detection (vlib_main_t * vm, vlib_buffer_t * b,
			   flow_entry_t * flow, struct rules *active,
			   u8 is_ip4)
{
  u32 offs = vnet_buffer (b)->gtpu.data_offset;
  ip4_header_t *ip4 = NULL;
  ip6_header_t *ip6 = NULL;
  upf_pdr_t *adr;
  upf_pdr_t *pdr;
  u8 *proto_hdr;
  u16 port = 0;
  u8 *p;
  word len;
  u8 *url;
  u8 src_intf;

  // known PDR.....
  // scan for Application Rules

  if (!(active->flags & SX_ADR))
    return;

  if (is_ip4)
    {
      ip4 = (ip4_header_t *) (vlib_buffer_get_current (b) + offs);
      proto_hdr = ip4_next_header (ip4);
      len = clib_net_to_host_u16 (ip4->length) - sizeof (ip4_header_t);
    }
  else
    {
      ip6 = (ip6_header_t *) (vlib_buffer_get_current (b) + offs);
      proto_hdr = ip6_next_header (ip6);
      len = clib_net_to_host_u16 (ip6->payload_length);
    }

  if (flow->key.proto == IP_PROTOCOL_TCP &&
      flow->tcp_state == TCP_STATE_ESTABLISHED)
    {
      len -= tcp_header_bytes ((tcp_header_t *) proto_hdr);
      offs = proto_hdr - (u8 *) vlib_buffer_get_current (b) +
	tcp_header_bytes ((tcp_header_t *) proto_hdr);
      port = clib_net_to_host_u16(((tcp_header_t *) proto_hdr)->dst_port);
    }
  else if (flow->key.proto == IP_PROTOCOL_UDP)
    {
      len -= sizeof (udp_header_t);
      offs =
	proto_hdr - (u8 *) vlib_buffer_get_current (b) +
	sizeof (udp_header_t);
      port = clib_net_to_host_u16(((udp_header_t *) proto_hdr)->dst_port);
    }
  else
    return;

  if (len < vlib_buffer_length_in_chain (vm, b) - offs || len <= 0)
    /* no or invalid payload */
    return;

  p = vlib_buffer_get_current (b) + offs;
  if (*p == TLS_HANDSHAKE)
    url = upf_adr_try_tls(port, p, len);
  else
    url = upf_adr_try_http(port, p, len);

  if (url == NULL)
    goto out_next_process;

  adf_debug ("URL: %v", url);

  adr = vec_elt_at_index (active->pdr, vnet_buffer (b)->gtpu.pdr_idx);
  adf_debug ("Old PDR: %p %u (idx %u)\n", adr, adr->id,
	     vnet_buffer (b)->gtpu.pdr_idx);
  src_intf = adr->pdi.src_intf;

  /*
   * see 3GPP TS 23.214 Table 5.2.2-1 for valid ADR combinations
   */
  vec_foreach (pdr, active->pdr)
  {
    if (!(pdr->pdi.fields & F_PDI_APPLICATION_ID))
      {
	adf_debug("skip PDR %u for no ADR\n", pdr->id);
	continue;
      }

    if (pdr->precedence >= adr->precedence)
      {
	adf_debug("skip PDR %u for lower precedence\n", pdr->id);
	continue;
      }

    if ((pdr->pdi.fields & F_PDI_UE_IP_ADDR))
      {
	if (is_ip4)
	  {
	    const ip4_address_t * addr;

	    if (!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4))
	      {
		adf_debug("skip PDR %u for no UE IPv4 address\n", pdr->id);
		continue;
	      }
	    addr = (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD) ?
	      &ip4->dst_address : &ip4->src_address;

	    if (!ip4_address_is_equal(&pdr->pdi.ue_addr.ip4, addr))
	      {
		adf_debug("skip PDR %u for UE IPv4 mismatch, S/D: %u, %U != %U\n",
			  pdr->id, !!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD),
			  format_ip4_address, &pdr->pdi.ue_addr.ip4,
			  format_ip4_address, addr);
		continue;
	      }
	  }
	else
	  {
	    const ip6_address_t * addr;

	    if (!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6))
	      {
		adf_debug("skip PDR %u for no UE IPv6 address\n", pdr->id);
		continue;
	      }
	    addr = (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD) ?
	      &ip6->dst_address : &ip6->src_address;

	    if (!ip6_address_is_equal_masked(&pdr->pdi.ue_addr.ip6, addr,
					     &ip6_main.fib_masks[64]))
	      {
		adf_debug("skip PDR %u for UE IPv6 mismatch, S/D: %u, %U != %U\n",
			  pdr->id, !!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD),
			  format_ip6_address, &pdr->pdi.ue_addr.ip6,
			  format_ip6_address, addr);
		continue;
	      }
	  }
      }

    if ((pdr->pdi.fields & F_PDI_LOCAL_F_TEID) &&
	vnet_buffer (b)->gtpu.teid != pdr->pdi.teid.teid)
      {
	adf_debug("skip PDR %u for TEID type mismatch\n", pdr->id);
	continue;
      }

    if (pdr->pdi.src_intf != src_intf)
      {
	/* must have the same direction as the original SDF that permited the flow */
	adf_debug("skip PDR %u for Src Intf mismatch, %u != %u\n",
		  pdr->id, pdr->pdi.src_intf, src_intf);
	continue;
      }

    adf_debug ("Scanning %p, db_id %u\n", pdr, pdr->pdi.adr.db_id);
    if (upf_adf_lookup (pdr->pdi.adr.db_id, url, vec_len (url)) == 0)
      adr = pdr;
  }
  vnet_buffer (b)->gtpu.pdr_idx = adr - active->pdr;
  if ((adr->pdi.fields & F_PDI_APPLICATION_ID))
    flow->application_id = adr->pdi.adr.application_id;

  adf_debug ("New PDR: %p %u (idx %u)\n", adr, adr->id,
	     vnet_buffer (b)->gtpu.pdr_idx);

  vec_free (url);

out_next_process:
  flow->next[vnet_buffer (b)->gtpu.is_reverse] = FT_NEXT_PROCESS;
  return;
}

always_inline void
upf_get_application_rule (vlib_main_t * vm, vlib_buffer_t * b,
			  flow_entry_t * flow, struct rules *active,
			  u8 is_ip4)
{
  upf_pdr_t *adr;
  upf_pdr_t *pdr;

  adr = vec_elt_at_index (active->pdr, vnet_buffer (b)->gtpu.pdr_idx);
  adf_debug ("Old PDR: %p %u (idx %u)\n", adr, adr->id,
	     vnet_buffer (b)->gtpu.pdr_idx);
  vec_foreach (pdr, active->pdr)
  {
    if ((pdr->pdi.fields & F_PDI_APPLICATION_ID)
	&& (pdr->precedence < adr->precedence)
	&& (pdr->pdi.adr.application_id == flow->application_id))
      adr = pdr;
  }
  vnet_buffer (b)->gtpu.pdr_idx = adr - active->pdr;
  if ((adr->pdi.fields & F_PDI_APPLICATION_ID))
    flow->application_id = adr->pdi.adr.application_id;

  adf_debug ("New PDR: %p %u (idx %u)\n", adr, adr->id,
	     vnet_buffer (b)->gtpu.pdr_idx);

  /* switch return traffic to processing node */
  flow->next[flow->is_reverse ^ FT_REVERSE] = FT_NEXT_PROCESS;
}

always_inline int
acl_ip4_is_equal_masked (const ip4_address_t * ip, upf_acl_t * acl, int field)
{
  return ip4_address_is_equal_masked (ip, &acl->match.address[field].ip4,
				      &acl->mask.address[field].ip4);
}

always_inline int
acl_ip6_is_equal_masked (const ip6_address_t * ip, upf_acl_t * acl, int field)
{
  return ip6_address_is_equal_masked (ip, &acl->match.address[field].ip6,
				      &acl->mask.address[field].ip6);
}

always_inline uword
ip46_address_is_equal_masked (const ip46_address_t * a,
			      const ip46_address_t * b,
			      const ip46_address_t * mask)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a->as_u64); i++)
    {
      u64 a_masked, b_masked;
      a_masked = a->as_u64[i] & mask->as_u64[i];
      b_masked = b->as_u64[i] & mask->as_u64[i];

      if (a_masked != b_masked)
	return 0;
    }
  return 1;
}

always_inline int
acl_ip46_is_equal_masked (const ip46_address_t * ip, upf_acl_t * acl, int field)
{
  return ip46_address_is_equal_masked (ip, &acl->match.address[field],
				       &acl->mask.address[field]);
}

always_inline int
acl_port_in_range (const u16 port, upf_acl_t * acl, int field)
{
  return (port >= acl->mask.port[field] && port <= acl->match.port[field]);
}

always_inline int
upf_acl_classify_one (vlib_main_t * vm, u32 teid,
		      flow_entry_t * flow, int is_reverse,
		      u8 is_ip4, upf_acl_t * acl)
{
  u32 pf_len = is_ip4 ? 32 : 64;

  if (! !is_ip4 != ! !acl->is_ip4)
    return 0;

  gtp_debug ("TEID %08x, Match %u, ACL %08x\n",
	     teid, acl->match_teid, acl->teid);
  if (acl->match_teid && teid != acl->teid)
    return 0;

  switch (acl->match_ue_ip)
    {
    case UPF_ACL_UL:
      gtp_debug ("UL: UE %U, Src: %U\n",
		 format_ip46_address, &acl->ue_ip, IP46_TYPE_ANY,
		 format_ip46_address, &flow->key.ip[FT_ORIGIN ^ is_reverse], IP46_TYPE_ANY);
      if (!ip46_address_is_equal_masked (&acl->ue_ip, &flow->key.ip[FT_ORIGIN ^ is_reverse],
					 (ip46_address_t *)&ip6_main.fib_masks[pf_len]))
	return 0;
      break;
    case UPF_ACL_DL:
      gtp_debug ("DL: UE %U, Dst: %U\n",
		 format_ip46_address, &acl->ue_ip, IP46_TYPE_ANY,
		 format_ip46_address, &flow->key.ip[FT_REVERSE ^ is_reverse], IP46_TYPE_ANY);
      if (!ip46_address_is_equal_masked (&acl->ue_ip, &flow->key.ip[FT_REVERSE ^ is_reverse],
					 (ip46_address_t *)&ip6_main.fib_masks[pf_len]))
	return 0;
      break;
    default:
      break;
    }

  gtp_debug ("Protocol: 0x%04x/0x%04x, 0x%04x\n",
	     acl->match.protocol, acl->mask.protocol, flow->key.proto);

  if ((flow->key.proto & acl->mask.protocol) !=
      (acl->match.protocol & acl->mask.protocol))
    return 0;

  if (!acl_ip46_is_equal_masked (&flow->key.ip[FT_ORIGIN ^ is_reverse],
				 acl, UPF_ACL_FIELD_SRC)
      || !acl_ip46_is_equal_masked (&flow->key.ip[FT_REVERSE ^ is_reverse],
				    acl, UPF_ACL_FIELD_DST))
    return 0;

  if (!acl_port_in_range(clib_net_to_host_u16 (flow->key.port[FT_ORIGIN ^ is_reverse]),
			 acl, UPF_ACL_FIELD_SRC)
      ||  !acl_port_in_range(clib_net_to_host_u16 (flow->key.port[FT_REVERSE ^ is_reverse]),
			     acl, UPF_ACL_FIELD_DST))
    return 0;

  return 1;
}

always_inline u32
upf_acl_classify (vlib_main_t * vm, vlib_buffer_t * b, flow_entry_t * flow,
		  struct rules * active, u8 is_ip4)
{
  u32 next = UPF_CLASSIFY_NEXT_DROP;
  u16 precedence;
  upf_acl_t *acl, *acl_vec;
  u32 teid;

  teid = vnet_buffer (b)->gtpu.teid;

  precedence = active->proxy_precedence;
  vnet_buffer (b)->gtpu.pdr_idx = active->proxy_pdr_idx;
  flow->is_l3_proxy = (~0 != active->proxy_pdr_idx);
  flow->is_decided = 0;
  next = flow->is_l3_proxy ? UPF_CLASSIFY_NEXT_PROCESS : UPF_CLASSIFY_NEXT_DROP;

  acl_vec = is_ip4 ? active->v4_acls : active->v6_acls;
  gtp_debug ("TEID %08x, ACLs %p (%u)\n", teid, acl_vec, vec_len (acl_vec));

  vec_foreach (acl, acl_vec)
  {
    if (acl->precedence < precedence &&
	upf_acl_classify_one (vm, teid, flow, vnet_buffer (b)->gtpu.is_reverse, is_ip4, acl))
      {
	precedence = acl->precedence;
	vnet_buffer (b)->gtpu.pdr_idx = acl->pdr_idx;
	next = UPF_CLASSIFY_NEXT_PROCESS;
	flow->is_l3_proxy = 0;
	flow->is_decided = 1;

	gtp_debug ("match PDR: %u\n", acl->pdr_idx);
      }
  }

  return next;
}

static uword
upf_classify (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  flowtable_main_t *fm = &flowtable_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  upf_session_t *sess = NULL;
  struct rules *active;
  u32 sidx = 0;
  u32 len;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      flow_entry_t *flow;
      u8 is_forward, is_reverse;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  /* Get next node index and adj index from tunnel next_dpo */
	  sidx = vnet_buffer (b)->gtpu.session_index;
	  sess = pool_elt_at_index (gtm->sessions, sidx);
	  active = sx_get_rules (sess, SX_ACTIVE);

	  next = UPF_CLASSIFY_NEXT_PROCESS;

	  flow = pool_elt_at_index (fm->flows, vnet_buffer (b)->gtpu.flow_id);
	  gtp_debug ("flow: %p\n", flow);
	  ASSERT (flow != NULL);

	  is_reverse = vnet_buffer (b)->gtpu.is_reverse;
	  is_forward = (is_reverse == flow->is_reverse) ? 1 : 0;
	  vnet_buffer (b)->gtpu.pdr_idx = flow->pdr_id[is_reverse];

	  gtp_debug ("is_rev %u, is_fwd %d, pdr_idx %x\n",
		     is_reverse, is_forward, flow->pdr_id[is_reverse]);

	  /* ADR + redirect + proxy

	     - process ACLs, remember proxy PDRs with the highest precedence
	     - if proxy PDR has precedence higher that ACL pdr or no ACL matches,
	       mark flow as proxy and goto processing
	     - in processing:
	       - send to proxy socket
	     - in proxy socket
	       - collect data till we have a decission
	       - if no match, continue with following PDRs
	       - if match, mark flow as decided and apply FAR
	   */
	  if (vnet_buffer (b)->gtpu.pdr_idx == ~0)
	    next = upf_acl_classify (vm, b, flow, active, is_ip4);
	  else if (is_forward)
	    upf_application_detection (vm, b, flow, active, is_ip4);
	  else if (!is_forward && flow->application_id != ~0)
	    {
	      gtp_debug ("Reverse Flow and AppId %u\n", flow->application_id);
	      upf_get_application_rule (vm, b, flow, active, is_ip4);
	    }
	  else if (flow->stats[0].bytes > 4096 && flow->stats[1].bytes > 4096)
	    {
	      /* stop flow classification after 4k in each direction */
	      gtp_debug ("Stopping Flow Classify after 4k");
	      flow->next[0] = flow->next[1] = FT_NEXT_PROCESS;
	    }

	  if (vnet_buffer (b)->gtpu.pdr_idx != ~0)
	    {
	      flow->pdr_id[is_reverse] = vnet_buffer (b)->gtpu.pdr_idx;

	      if (flow->is_l3_proxy)
		/* bypass flow classification if we decided to proxy */
		flow->next[0] = flow->next[1] = FT_NEXT_PROCESS;
	    }

	  len = vlib_buffer_length_in_chain (vm, b);
	  stats_n_packets += 1;
	  stats_n_bytes += len;

	  /* Batch stats increment on the same gtpu tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len;
	      stats_sw_if_index = sw_if_index;
	    }

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_classify_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      tr->pdr_idx = vnet_buffer (b)->gtpu.pdr_idx;
	      tr->next_index = next;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
			   sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi, next);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_classify_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return upf_classify (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_classify_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return upf_classify (vm, node, from_frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_classify_node) = {
  .name = "upf-ip4-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_classify_error_strings),
  .error_strings = upf_classify_error_strings,
  .n_next_nodes = UPF_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_CLASSIFY_NEXT_PROCESS] = "upf-ip4-process",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_classify_node) = {
  .name = "upf-ip6-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_classify_error_strings),
  .error_strings = upf_classify_error_strings,
  .n_next_nodes = UPF_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_CLASSIFY_NEXT_PROCESS] = "upf-ip6-process",
  },
};
/* *INDENT-ON* */

static uword
upf_tdf (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame, int is_ip4)
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
	  clib_warning("Data Offset: %u\n", b0->current_data);

	  /* en0 = vlib_buffer_get_current (b0); */

	  /* pkts_swapped += 1; */

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_tdf_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      /* tr->session_index = sidx; */
	      /* tr->cp_seid = sess->cp_seid; */
	      tr->pdr_idx = vnet_buffer (b0)->gtpu.pdr_idx;
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
  /* 			       UPF_TDF_ERROR_TDF, pkts_swapped); */
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
    [UPF_TDF_NEXT_PROCESS] = "upf-ip4-process",
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
    [UPF_TDF_NEXT_PROCESS] = "upf-ip6-process",
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
