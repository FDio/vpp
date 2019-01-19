/*
 * nat_ipfix_logging.c - NAT Events IPFIX logging
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/ipfix-export/flow_report.h>
#include <vlibmemory/api.h>
#include <nat/nat_inlines.h>
#include <nat/nat_ipfix_logging.h>

snat_ipfix_logging_main_t snat_ipfix_logging_main;

#define NAT44_SESSION_CREATE_LEN 26
#define NAT_ADDRESSES_EXHAUTED_LEN 13
#define MAX_ENTRIES_PER_USER_LEN 21
#define MAX_SESSIONS_LEN 17
#define MAX_BIBS_LEN 17
#define MAX_FRAGMENTS_IP4_LEN 21
#define MAX_FRAGMENTS_IP6_LEN 33
#define NAT64_BIB_LEN 38
#define NAT64_SES_LEN 62

#define NAT44_SESSION_CREATE_FIELD_COUNT 8
#define NAT_ADDRESSES_EXHAUTED_FIELD_COUNT 3
#define MAX_ENTRIES_PER_USER_FIELD_COUNT 5
#define MAX_SESSIONS_FIELD_COUNT 4
#define MAX_BIBS_FIELD_COUNT 4
#define MAX_FRAGMENTS_FIELD_COUNT 5
#define NAT64_BIB_FIELD_COUNT 8
#define NAT64_SES_FIELD_COUNT 12

typedef struct
{
  u8 nat_event;
  u32 src_ip;
  u32 nat_src_ip;
  snat_protocol_t snat_proto;
  u16 src_port;
  u16 nat_src_port;
  u32 vrf_id;
} snat_ipfix_logging_nat44_ses_args_t;

typedef struct
{
  u32 pool_id;
} snat_ipfix_logging_addr_exhausted_args_t;

typedef struct
{
  u32 limit;
  u32 src_ip;
} snat_ipfix_logging_max_entries_per_user_args_t;

typedef struct
{
  u32 limit;
} nat_ipfix_logging_max_sessions_args_t;

typedef struct
{
  u32 limit;
} nat_ipfix_logging_max_bibs_args_t;

typedef struct
{
  u32 limit;
  u32 src;
} nat_ipfix_logging_max_frags_ip4_args_t;

typedef struct
{
  u32 limit;
  u64 src[2];
} nat_ipfix_logging_max_frags_ip6_args_t;

typedef struct
{
  u8 nat_event;
  u64 src_ip[2];
  u32 nat_src_ip;
  u8 proto;
  u16 src_port;
  u16 nat_src_port;
  u64 dst_ip[2];
  u32 nat_dst_ip;
  u32 vrf_id;
  u16 dst_port;
  u16 nat_dst_port;
} nat_ipfix_logging_nat64_ses_args_t;

typedef struct
{
  u8 nat_event;
  u64 src_ip[2];
  u32 nat_src_ip;
  u8 proto;
  u16 src_port;
  u16 nat_src_port;
  u32 vrf_id;
} nat_ipfix_logging_nat64_bib_args_t;

#define skip_if_disabled()                                    \
do {                                                          \
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main; \
  if (PREDICT_TRUE (!silm->enabled))                          \
    return;                                                   \
} while (0)

/**
 * @brief Create an IPFIX template packet rewrite string
 *
 * @param frm               flow report main
 * @param fr                flow report
 * @param collector_address collector address
 * @param src_address       source address
 * @param collector_port    collector
 * @param event             NAT event ID
 * @param quota_event       NAT quota exceeded event ID
 *
 * @returns template packet
 */
static inline u8 *
snat_template_rewrite (flow_report_main_t * frm,
		       flow_report_t * fr,
		       ip4_address_t * collector_address,
		       ip4_address_t * src_address,
		       u16 collector_port,
		       nat_event_t event, quota_exceed_event_t quota_event)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  ip4_header_t *ip;
  udp_header_t *udp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  ipfix_template_header_t *t;
  ipfix_field_specifier_t *f;
  ipfix_field_specifier_t *first_field;
  u8 *rewrite = 0;
  ip4_ipfix_template_packet_t *tp;
  u32 field_count = 0;
  flow_report_stream_t *stream;

  stream = &frm->streams[fr->stream_index];
  silm->stream_index = fr->stream_index;

  if (event == NAT_ADDRESSES_EXHAUTED)
    {
      field_count = NAT_ADDRESSES_EXHAUTED_FIELD_COUNT;
      silm->addr_exhausted_template_id = fr->template_id;
    }
  else if (event == NAT44_SESSION_CREATE)
    {
      field_count = NAT44_SESSION_CREATE_FIELD_COUNT;
      silm->nat44_session_template_id = fr->template_id;
    }
  else if (event == NAT64_BIB_CREATE)
    {
      field_count = NAT64_BIB_FIELD_COUNT;
      silm->nat64_bib_template_id = fr->template_id;
    }
  else if (event == NAT64_SESSION_CREATE)
    {
      field_count = NAT64_SES_FIELD_COUNT;
      silm->nat64_ses_template_id = fr->template_id;
    }
  else if (event == QUOTA_EXCEEDED)
    {
      if (quota_event == MAX_ENTRIES_PER_USER)
	{
	  field_count = MAX_ENTRIES_PER_USER_FIELD_COUNT;
	  silm->max_entries_per_user_template_id = fr->template_id;
	}
      else if (quota_event == MAX_SESSION_ENTRIES)
	{
	  field_count = MAX_SESSIONS_FIELD_COUNT;
	  silm->max_sessions_template_id = fr->template_id;
	}
      else if (quota_event == MAX_BIB_ENTRIES)
	{
	  field_count = MAX_BIBS_FIELD_COUNT;
	  silm->max_bibs_template_id = fr->template_id;
	}
      else if (quota_event == MAX_FRAGMENTS_PENDING_REASSEMBLY)
	{
	  field_count = MAX_FRAGMENTS_FIELD_COUNT;
	  silm->max_frags_ip4_template_id = fr->template_id;
	}
      else if (quota_event == MAX_FRAGMENTS_PENDING_REASSEMBLY_IP6)
        {
          field_count = MAX_FRAGMENTS_FIELD_COUNT;
          silm->max_frags_ip6_template_id = fr->template_id;
        }
    }

  /* allocate rewrite space */
  vec_validate_aligned (rewrite,
			sizeof (ip4_ipfix_template_packet_t)
			+ field_count * sizeof (ipfix_field_specifier_t) - 1,
			CLIB_CACHE_LINE_BYTES);

  tp = (ip4_ipfix_template_packet_t *) rewrite;
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);
  t = (ipfix_template_header_t *) (s + 1);
  first_field = f = (ipfix_field_specifier_t *) (t + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = src_address->as_u32;
  ip->dst_address.as_u32 = collector_address->as_u32;
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (collector_port);
  udp->length = clib_host_to_net_u16 (vec_len (rewrite) - sizeof (*ip));

  /* FIXUP: message header export_time */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* Add TLVs to the template */
  if (event == NAT_ADDRESSES_EXHAUTED)
    {
      f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds, 8);
      f++;
      f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
      f++;
      f->e_id_length = ipfix_e_id_length (0, natPoolId, 4);
      f++;
    }
  else if (event == NAT44_SESSION_CREATE)
    {
      f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds, 8);
      f++;
      f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
      f++;
      f->e_id_length = ipfix_e_id_length (0, sourceIPv4Address, 4);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNATSourceIPv4Address, 4);
      f++;
      f->e_id_length = ipfix_e_id_length (0, protocolIdentifier, 1);
      f++;
      f->e_id_length = ipfix_e_id_length (0, sourceTransportPort, 2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNAPTSourceTransportPort, 2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, ingressVRFID, 4);
      f++;
    }
  else if (event == NAT64_BIB_CREATE)
    {
      f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds, 8);
      f++;
      f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
      f++;
      f->e_id_length = ipfix_e_id_length (0, sourceIPv6Address, 16);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNATSourceIPv4Address, 4);
      f++;
      f->e_id_length = ipfix_e_id_length (0, protocolIdentifier, 1);
      f++;
      f->e_id_length = ipfix_e_id_length (0, sourceTransportPort, 2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNAPTSourceTransportPort, 2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, ingressVRFID, 4);
      f++;
    }
  else if (event == NAT64_SESSION_CREATE)
    {
      f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds, 8);
      f++;
      f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
      f++;
      f->e_id_length = ipfix_e_id_length (0, sourceIPv6Address, 16);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNATSourceIPv4Address, 4);
      f++;
      f->e_id_length = ipfix_e_id_length (0, protocolIdentifier, 1);
      f++;
      f->e_id_length = ipfix_e_id_length (0, sourceTransportPort, 2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNAPTSourceTransportPort, 2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, destinationIPv6Address, 16);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNATDestinationIPv4Address, 4);
      f++;
      f->e_id_length = ipfix_e_id_length (0, destinationTransportPort, 2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, postNAPTDestinationTransportPort,
                                          2);
      f++;
      f->e_id_length = ipfix_e_id_length (0, ingressVRFID, 4);
      f++;
    }
  else if (event == QUOTA_EXCEEDED)
    {
      if (quota_event == MAX_ENTRIES_PER_USER)
	{
	  f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds,
					      8);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natQuotaExceededEvent, 4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, maxEntriesPerUser, 4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, sourceIPv4Address, 4);
	  f++;
	}
      else if (quota_event == MAX_SESSION_ENTRIES)
        {
	  f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds,
					      8);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natQuotaExceededEvent, 4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, maxSessionEntries, 4);
	  f++;
        }
      else if (quota_event == MAX_BIB_ENTRIES)
        {
	  f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds,
					      8);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natQuotaExceededEvent, 4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, maxBIBEntries, 4);
	  f++;
        }
      else if (quota_event == MAX_FRAGMENTS_PENDING_REASSEMBLY)
        {
	  f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds,
					      8);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natQuotaExceededEvent, 4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, maxFragmentsPendingReassembly,
                                              4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, sourceIPv4Address, 4);
	  f++;
        }
      else if (quota_event == MAX_FRAGMENTS_PENDING_REASSEMBLY_IP6)
        {
	  f->e_id_length = ipfix_e_id_length (0, observationTimeMilliseconds,
					      8);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natEvent, 1);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, natQuotaExceededEvent, 4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, maxFragmentsPendingReassembly,
                                              4);
	  f++;
	  f->e_id_length = ipfix_e_id_length (0, sourceIPv6Address, 16);
	  f++;
        }
    }

  /* Back to the template packet... */
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  /* set length in octets */
  s->set_id_length =
    ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
  ip->checksum = ip4_header_checksum (ip);

  return rewrite;
}

u8 *
snat_template_rewrite_addr_exhausted (flow_report_main_t * frm,
				      flow_report_t * fr,
				      ip4_address_t * collector_address,
				      ip4_address_t * src_address,
				      u16 collector_port,
                                      ipfix_report_element_t *elts,
                                      u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, NAT_ADDRESSES_EXHAUTED, 0);
}

u8 *
snat_template_rewrite_nat44_session (flow_report_main_t * frm,
				     flow_report_t * fr,
				     ip4_address_t * collector_address,
				     ip4_address_t * src_address,
				     u16 collector_port,
                                     ipfix_report_element_t *elts,
                                     u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, NAT44_SESSION_CREATE, 0);
}

u8 *
snat_template_rewrite_max_entries_per_usr (flow_report_main_t * frm,
					   flow_report_t * fr,
					   ip4_address_t * collector_address,
					   ip4_address_t * src_address,
					   u16 collector_port,
                                           ipfix_report_element_t *elts,
                                           u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, QUOTA_EXCEEDED,
				MAX_ENTRIES_PER_USER);
}

u8 *
nat_template_rewrite_max_sessions (flow_report_main_t * frm,
				   flow_report_t * fr,
				   ip4_address_t * collector_address,
				   ip4_address_t * src_address,
				   u16 collector_port,
                                   ipfix_report_element_t *elts,
                                   u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, QUOTA_EXCEEDED,
				MAX_SESSION_ENTRIES);
}

u8 *
nat_template_rewrite_max_bibs (flow_report_main_t * frm,
			       flow_report_t * fr,
			       ip4_address_t * collector_address,
			       ip4_address_t * src_address,
			       u16 collector_port,
                               ipfix_report_element_t *elts,
                               u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, QUOTA_EXCEEDED,
				MAX_BIB_ENTRIES);
}

u8 *
nat_template_rewrite_max_frags_ip4 (flow_report_main_t * frm,
			            flow_report_t * fr,
			            ip4_address_t * collector_address,
			            ip4_address_t * src_address,
			            u16 collector_port,
                                    ipfix_report_element_t *elts,
                                    u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, QUOTA_EXCEEDED,
				MAX_FRAGMENTS_PENDING_REASSEMBLY);
}

u8 *
nat_template_rewrite_max_frags_ip6 (flow_report_main_t * frm,
			            flow_report_t * fr,
			            ip4_address_t * collector_address,
			            ip4_address_t * src_address,
			            u16 collector_port,
                                    ipfix_report_element_t *elts,
                                    u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, QUOTA_EXCEEDED,
				MAX_FRAGMENTS_PENDING_REASSEMBLY_IP6);
}

u8 *
nat_template_rewrite_nat64_bib (flow_report_main_t * frm,
			        flow_report_t * fr,
			        ip4_address_t * collector_address,
			        ip4_address_t * src_address,
			        u16 collector_port,
                                ipfix_report_element_t *elts,
                                u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, NAT64_BIB_CREATE, 0);
}

u8 *
nat_template_rewrite_nat64_session (flow_report_main_t * frm,
			            flow_report_t * fr,
			            ip4_address_t * collector_address,
			            ip4_address_t * src_address,
			            u16 collector_port,
                                    ipfix_report_element_t *elts,
                                    u32 n_elts, u32 *stream_index)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
				collector_port, NAT64_SESSION_CREATE, 0);
}

static inline void
snat_ipfix_header_create (flow_report_main_t * frm,
			  vlib_buffer_t * b0, u32 * offset)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_stream_t *stream;
  ip4_ipfix_template_packet_t *tp;
  ipfix_message_header_t *h = 0;
  ipfix_set_header_t *s = 0;
  ip4_header_t *ip;
  udp_header_t *udp;

  stream = &frm->streams[silm->stream_index];

  b0->current_data = 0;
  b0->current_length = sizeof (*ip) + sizeof (*udp) + sizeof (*h) +
    sizeof (*s);
  b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = frm->fib_index;
  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->flags_and_fragment_offset = 0;
  ip->src_address.as_u32 = frm->src_address.as_u32;
  ip->dst_address.as_u32 = frm->ipfix_collector.as_u32;
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (frm->collector_port);
  udp->checksum = 0;

  h->export_time = clib_host_to_net_u32 ((u32)
					 (((f64) frm->unix_time_0) +
					  (vlib_time_now (frm->vlib_main) -
					   frm->vlib_time_0)));
  h->sequence_number = clib_host_to_net_u32 (stream->sequence_number++);
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  *offset = (u32) (((u8 *) (s + 1)) - (u8 *) tp);
}

static inline void
snat_ipfix_send (flow_report_main_t * frm,
		 vlib_frame_t * f, vlib_buffer_t * b0, u16 template_id)
{
  ip4_ipfix_template_packet_t *tp;
  ipfix_message_header_t *h = 0;
  ipfix_set_header_t *s = 0;
  ip4_header_t *ip;
  udp_header_t *udp;
  vlib_main_t *vm = frm->vlib_main;

  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  s->set_id_length = ipfix_set_id_length (template_id,
					  b0->current_length -
					  (sizeof (*ip) + sizeof (*udp) +
					   sizeof (*h)));
  h->version_length = version_length (b0->current_length -
				      (sizeof (*ip) + sizeof (*udp)));

  ip->length = clib_host_to_net_u16 (b0->current_length);
  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

  if (frm->udp_checksum)
    {
      udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
      if (udp->checksum == 0)
	udp->checksum = 0xffff;
    }

  ASSERT (ip->checksum == ip4_header_checksum (ip));

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
}

static void
snat_ipfix_logging_nat44_ses (u8 nat_event, u32 src_ip, u32 nat_src_ip,
			      snat_protocol_t snat_proto, u16 src_port,
			      u16 nat_src_port, u32 vrf_id, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;
  u8 proto = ~0;

  if (!silm->enabled)
    return;

  proto = snat_proto_to_ip_proto (snat_proto);

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->nat44_session_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->nat44_session_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->nat44_session_next_record_offset;
    }

  f = silm->nat44_session_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->nat44_session_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, &src_ip, sizeof (src_ip));
      offset += sizeof (src_ip);

      clib_memcpy_fast (b0->data + offset, &nat_src_ip, sizeof (nat_src_ip));
      offset += sizeof (nat_src_ip);

      clib_memcpy_fast (b0->data + offset, &proto, sizeof (proto));
      offset += sizeof (proto);

      clib_memcpy_fast (b0->data + offset, &src_port, sizeof (src_port));
      offset += sizeof (src_port);

      clib_memcpy_fast (b0->data + offset, &nat_src_port, sizeof (nat_src_port));
      offset += sizeof (nat_src_port);

      clib_memcpy_fast (b0->data + offset, &vrf_id, sizeof (vrf_id));
      offset += sizeof (vrf_id);

      b0->current_length += NAT44_SESSION_CREATE_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + NAT44_SESSION_CREATE_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->nat44_session_template_id);
      silm->nat44_session_frame = 0;
      silm->nat44_session_buffer = 0;
      offset = 0;
    }
  silm->nat44_session_next_record_offset = offset;
}

static void
snat_ipfix_logging_addr_exhausted (u32 pool_id, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;
  u8 nat_event = NAT_ADDRESSES_EXHAUTED;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->addr_exhausted_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->addr_exhausted_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->addr_exhausted_next_record_offset;
    }

  f = silm->addr_exhausted_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->addr_exhausted_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, &pool_id, sizeof (pool_id));
      offset += sizeof (pool_id);

      b0->current_length += NAT_ADDRESSES_EXHAUTED_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + NAT_ADDRESSES_EXHAUTED_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->addr_exhausted_template_id);
      silm->addr_exhausted_frame = 0;
      silm->addr_exhausted_buffer = 0;
      offset = 0;
    }
  silm->addr_exhausted_next_record_offset = offset;
}

static void
snat_ipfix_logging_max_entries_per_usr (u32 limit, u32 src_ip, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;
  u8 nat_event = QUOTA_EXCEEDED;
  u32 quota_event = MAX_ENTRIES_PER_USER;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->max_entries_per_user_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->max_entries_per_user_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->max_entries_per_user_next_record_offset;
    }

  f = silm->max_entries_per_user_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->max_entries_per_user_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, &quota_event, sizeof (quota_event));
      offset += sizeof (quota_event);

      clib_memcpy_fast (b0->data + offset, &limit, sizeof (limit));
      offset += sizeof (limit);

      clib_memcpy_fast (b0->data + offset, &src_ip, sizeof (src_ip));
      offset += sizeof (src_ip);

      b0->current_length += MAX_ENTRIES_PER_USER_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + MAX_ENTRIES_PER_USER_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->max_entries_per_user_template_id);
      silm->max_entries_per_user_frame = 0;
      silm->max_entries_per_user_buffer = 0;
      offset = 0;
    }
  silm->max_entries_per_user_next_record_offset = offset;
}

static void
nat_ipfix_logging_max_ses (u32 limit, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;
  u8 nat_event = QUOTA_EXCEEDED;
  u32 quota_event = MAX_SESSION_ENTRIES;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->max_sessions_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->max_sessions_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->max_sessions_next_record_offset;
    }

  f = silm->max_sessions_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->max_sessions_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, &quota_event, sizeof (quota_event));
      offset += sizeof (quota_event);

      clib_memcpy_fast (b0->data + offset, &limit, sizeof (limit));
      offset += sizeof (limit);

      b0->current_length += MAX_SESSIONS_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + MAX_SESSIONS_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->max_sessions_template_id);
      silm->max_sessions_frame = 0;
      silm->max_sessions_buffer = 0;
      offset = 0;
    }
  silm->max_sessions_next_record_offset = offset;
}

static void
nat_ipfix_logging_max_bib (u32 limit, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;
  u8 nat_event = QUOTA_EXCEEDED;
  u32 quota_event = MAX_BIB_ENTRIES;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->max_bibs_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->max_bibs_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->max_bibs_next_record_offset;
    }

  f = silm->max_bibs_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->max_bibs_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, &quota_event, sizeof (quota_event));
      offset += sizeof (quota_event);

      clib_memcpy_fast (b0->data + offset, &limit, sizeof (limit));
      offset += sizeof (limit);

      b0->current_length += MAX_BIBS_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + MAX_BIBS_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->max_bibs_template_id);
      silm->max_bibs_frame = 0;
      silm->max_bibs_buffer = 0;
      offset = 0;
    }
  silm->max_bibs_next_record_offset = offset;
}

static void
nat_ipfix_logging_max_frag_ip4 (u32 limit, u32 src, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;
  u8 nat_event = QUOTA_EXCEEDED;
  u32 quota_event = MAX_FRAGMENTS_PENDING_REASSEMBLY;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->max_frags_ip4_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->max_frags_ip4_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->max_frags_ip4_next_record_offset;
    }

  f = silm->max_frags_ip4_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->max_frags_ip4_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, &quota_event, sizeof (quota_event));
      offset += sizeof (quota_event);

      clib_memcpy_fast (b0->data + offset, &limit, sizeof (limit));
      offset += sizeof (limit);

      clib_memcpy_fast (b0->data + offset, &src, sizeof (src));
      offset += sizeof (src);

      b0->current_length += MAX_FRAGMENTS_IP4_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + MAX_BIBS_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->max_frags_ip4_template_id);
      silm->max_frags_ip4_frame = 0;
      silm->max_frags_ip4_buffer = 0;
      offset = 0;
    }
  silm->max_frags_ip4_next_record_offset = offset;
}

static void
nat_ipfix_logging_max_frag_ip6 (u32 limit, ip6_address_t * src, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;
  u8 nat_event = QUOTA_EXCEEDED;
  u32 quota_event = MAX_FRAGMENTS_PENDING_REASSEMBLY;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->max_frags_ip6_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->max_frags_ip6_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->max_frags_ip6_next_record_offset;
    }

  f = silm->max_frags_ip6_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->max_frags_ip6_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, &quota_event, sizeof (quota_event));
      offset += sizeof (quota_event);

      clib_memcpy_fast (b0->data + offset, &limit, sizeof (limit));
      offset += sizeof (limit);

      clib_memcpy_fast (b0->data + offset, src, sizeof (ip6_address_t));
      offset += sizeof (ip6_address_t);

      b0->current_length += MAX_FRAGMENTS_IP6_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + MAX_BIBS_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->max_frags_ip6_template_id);
      silm->max_frags_ip6_frame = 0;
      silm->max_frags_ip6_buffer = 0;
      offset = 0;
    }
  silm->max_frags_ip6_next_record_offset = offset;
}

static void
nat_ipfix_logging_nat64_bibe (u8 nat_event, ip6_address_t * src_ip,
                              u32 nat_src_ip, u8 proto, u16 src_port,
                              u16 nat_src_port, u32 vrf_id, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->nat64_bib_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->nat64_bib_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->nat64_bib_next_record_offset;
    }

  f = silm->nat64_bib_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->nat64_bib_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, src_ip, sizeof (ip6_address_t));
      offset += sizeof (ip6_address_t);

      clib_memcpy_fast (b0->data + offset, &nat_src_ip, sizeof (nat_src_ip));
      offset += sizeof (nat_src_ip);

      clib_memcpy_fast (b0->data + offset, &proto, sizeof (proto));
      offset += sizeof (proto);

      clib_memcpy_fast (b0->data + offset, &src_port, sizeof (src_port));
      offset += sizeof (src_port);

      clib_memcpy_fast (b0->data + offset, &nat_src_port, sizeof (nat_src_port));
      offset += sizeof (nat_src_port);

      clib_memcpy_fast (b0->data + offset, &vrf_id, sizeof (vrf_id));
      offset += sizeof (vrf_id);

      b0->current_length += NAT64_BIB_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + NAT64_BIB_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->nat64_bib_template_id);
      silm->nat64_bib_frame = 0;
      silm->nat64_bib_buffer = 0;
      offset = 0;
    }
  silm->nat64_bib_next_record_offset = offset;
}

static void
nat_ipfix_logging_nat64_ses (u8 nat_event, ip6_address_t * src_ip,
                             u32 nat_src_ip, u8 proto, u16 src_port,
                             u16 nat_src_port, ip6_address_t * dst_ip,
                             u32 nat_dst_ip, u16 dst_port, u16 nat_dst_port,
                             u32 vrf_id, int do_flush)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  vlib_buffer_t *b0 = 0;
  u32 bi0 = ~0;
  u32 offset;
  vlib_main_t *vm = frm->vlib_main;
  u64 now;

  if (!silm->enabled)
    return;

  now = (u64) ((vlib_time_now (vm) - silm->vlib_time_0) * 1e3);
  now += silm->milisecond_time_0;

  b0 = silm->nat64_ses_buffer;

  if (PREDICT_FALSE (b0 == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  nat_log_err ("can't allocate buffer for NAT IPFIX event");
	  return;
	}

      b0 = silm->nat64_ses_buffer = vlib_get_buffer (vm, bi0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      offset = 0;
    }
  else
    {
      bi0 = vlib_get_buffer_index (vm, b0);
      offset = silm->nat64_ses_next_record_offset;
    }

  f = silm->nat64_ses_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      silm->nat64_ses_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (offset == 0))
    snat_ipfix_header_create (frm, b0, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      u64 time_stamp = clib_host_to_net_u64 (now);
      clib_memcpy_fast (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy_fast (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy_fast (b0->data + offset, src_ip, sizeof (ip6_address_t));
      offset += sizeof (ip6_address_t);

      clib_memcpy_fast (b0->data + offset, &nat_src_ip, sizeof (nat_src_ip));
      offset += sizeof (nat_src_ip);

      clib_memcpy_fast (b0->data + offset, &proto, sizeof (proto));
      offset += sizeof (proto);

      clib_memcpy_fast (b0->data + offset, &src_port, sizeof (src_port));
      offset += sizeof (src_port);

      clib_memcpy_fast (b0->data + offset, &nat_src_port, sizeof (nat_src_port));
      offset += sizeof (nat_src_port);

      clib_memcpy_fast (b0->data + offset, dst_ip, sizeof (ip6_address_t));
      offset += sizeof (ip6_address_t);

      clib_memcpy_fast (b0->data + offset, &nat_dst_ip, sizeof (nat_dst_ip));
      offset += sizeof (nat_dst_ip);

      clib_memcpy_fast (b0->data + offset, &dst_port, sizeof (dst_port));
      offset += sizeof (dst_port);

      clib_memcpy_fast (b0->data + offset, &nat_dst_port, sizeof (nat_dst_port));
      offset += sizeof (nat_dst_port);

      clib_memcpy_fast (b0->data + offset, &vrf_id, sizeof (vrf_id));
      offset += sizeof (vrf_id);

      b0->current_length += NAT64_SES_LEN;
    }

  if (PREDICT_FALSE
      (do_flush || (offset + NAT64_SES_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->nat64_ses_template_id);
      silm->nat64_ses_frame = 0;
      silm->nat64_ses_buffer = 0;
      offset = 0;
    }
  silm->nat64_ses_next_record_offset = offset;
}

static void
snat_ipfix_logging_nat44_ses_rpc_cb (snat_ipfix_logging_nat44_ses_args_t * a)
{
  snat_ipfix_logging_nat44_ses (a->nat_event, a->src_ip, a->nat_src_ip,
				a->snat_proto, a->src_port, a->nat_src_port,
				a->vrf_id, 0);
}

/**
 * @brief Generate NAT44 session create event
 *
 * @param src_ip       source IPv4 address
 * @param nat_src_ip   transaltes source IPv4 address
 * @param snat_proto   NAT transport protocol
 * @param src_port     source port
 * @param nat_src_port translated source port
 * @param vrf_id       VRF ID
 */
void
snat_ipfix_logging_nat44_ses_create (u32 src_ip,
				     u32 nat_src_ip,
				     snat_protocol_t snat_proto,
				     u16 src_port,
				     u16 nat_src_port, u32 vrf_id)
{
  snat_ipfix_logging_nat44_ses_args_t a;

  skip_if_disabled ();

  a.nat_event = NAT44_SESSION_CREATE;
  a.src_ip = src_ip;
  a.nat_src_ip = nat_src_ip;
  a.snat_proto = snat_proto;
  a.src_port = src_port;
  a.nat_src_port = nat_src_port;
  a.vrf_id = vrf_id;

  vl_api_rpc_call_main_thread (snat_ipfix_logging_nat44_ses_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

/**
 * @brief Generate NAT44 session delete event
 *
 * @param src_ip       source IPv4 address
 * @param nat_src_ip   transaltes source IPv4 address
 * @param snat_proto   NAT transport protocol
 * @param src_port     source port
 * @param nat_src_port translated source port
 * @param vrf_id       VRF ID
 */
void
snat_ipfix_logging_nat44_ses_delete (u32 src_ip,
				     u32 nat_src_ip,
				     snat_protocol_t snat_proto,
				     u16 src_port,
				     u16 nat_src_port, u32 vrf_id)
{
  snat_ipfix_logging_nat44_ses_args_t a;

  skip_if_disabled ();

  a.nat_event = NAT44_SESSION_DELETE;
  a.src_ip = src_ip;
  a.nat_src_ip = nat_src_ip;
  a.snat_proto = snat_proto;
  a.src_port = src_port;
  a.nat_src_port = nat_src_port;
  a.vrf_id = vrf_id;

  vl_api_rpc_call_main_thread (snat_ipfix_logging_nat44_ses_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
snat_data_callback_nat44_session (flow_report_main_t * frm,
				  flow_report_t * fr,
				  vlib_frame_t * f,
				  u32 * to_next, u32 node_index)
{
  snat_ipfix_logging_nat44_ses (0, 0, 0, 0, 0, 0, 0, 1);
  return f;
}

static void
  snat_ipfix_logging_addr_exhausted_rpc_cb
  (snat_ipfix_logging_addr_exhausted_args_t * a)
{
  snat_ipfix_logging_addr_exhausted (a->pool_id, 0);
}

/**
 * @brief Generate NAT addresses exhausted event
 *
 * @param pool_id NAT pool ID
 */
void
snat_ipfix_logging_addresses_exhausted (u32 pool_id)
{
  //TODO: This event SHOULD be rate limited
  snat_ipfix_logging_addr_exhausted_args_t a;

  skip_if_disabled ();

  a.pool_id = pool_id;

  vl_api_rpc_call_main_thread (snat_ipfix_logging_addr_exhausted_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
snat_data_callback_addr_exhausted (flow_report_main_t * frm,
				   flow_report_t * fr,
				   vlib_frame_t * f,
				   u32 * to_next, u32 node_index)
{
  snat_ipfix_logging_addr_exhausted (0, 1);
  return f;
}

static void
  snat_ipfix_logging_max_entries_per_usr_rpc_cb
  (snat_ipfix_logging_max_entries_per_user_args_t * a)
{
  snat_ipfix_logging_max_entries_per_usr (a->limit, a->src_ip, 0);
}

/**
 * @brief Generate maximum entries per user exceeded event
 *
 * @param limit maximum NAT entries that can be created per user
 * @param src_ip source IPv4 address
 */
void
snat_ipfix_logging_max_entries_per_user (u32 limit, u32 src_ip)
{
  //TODO: This event SHOULD be rate limited
  snat_ipfix_logging_max_entries_per_user_args_t a;

  skip_if_disabled ();

  a.limit = limit;
  a.src_ip = src_ip;

  vl_api_rpc_call_main_thread (snat_ipfix_logging_max_entries_per_usr_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
snat_data_callback_max_entries_per_usr (flow_report_main_t * frm,
					flow_report_t * fr,
					vlib_frame_t * f,
					u32 * to_next, u32 node_index)
{
  snat_ipfix_logging_max_entries_per_usr (0, 0, 1);
  return f;
}

static void
nat_ipfix_logging_max_ses_rpc_cb (nat_ipfix_logging_max_sessions_args_t * a)
{
  nat_ipfix_logging_max_ses (a->limit, 0);
}

/**
 * @brief Generate maximum session entries exceeded event
 *
 * @param limit configured limit
 */
void
nat_ipfix_logging_max_sessions (u32 limit)
{
  //TODO: This event SHOULD be rate limited
  nat_ipfix_logging_max_sessions_args_t a;

  skip_if_disabled ();

  a.limit = limit;

  vl_api_rpc_call_main_thread (nat_ipfix_logging_max_ses_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
nat_data_callback_max_sessions (flow_report_main_t * frm,
				flow_report_t * fr,
				vlib_frame_t * f,
				u32 * to_next, u32 node_index)
{
  nat_ipfix_logging_max_ses (0, 1);
  return f;
}

static void
nat_ipfix_logging_max_bib_rpc_cb (nat_ipfix_logging_max_bibs_args_t * a)
{
  nat_ipfix_logging_max_bib (a->limit, 0);
}

/**
 * @brief Generate maximum BIB entries exceeded event
 *
 * @param limit configured limit
 */
void
nat_ipfix_logging_max_bibs (u32 limit)
{
  //TODO: This event SHOULD be rate limited
  nat_ipfix_logging_max_bibs_args_t a;

  skip_if_disabled ();

  a.limit = limit;

  vl_api_rpc_call_main_thread (nat_ipfix_logging_max_bib_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
nat_data_callback_max_bibs (flow_report_main_t * frm,
			    flow_report_t * fr,
			    vlib_frame_t * f,
			    u32 * to_next, u32 node_index)
{
  nat_ipfix_logging_max_bib (0, 1);
  return f;
}

static void
nat_ipfix_logging_max_frag_ip4_rpc_cb (nat_ipfix_logging_max_frags_ip4_args_t * a)
{
  nat_ipfix_logging_max_frag_ip4 (a->limit, a->src, 0);
}

/**
 * @brief Generate maximum IPv4 fragments pending reassembly exceeded event
 *
 * @param limit configured limit
 * @param src source IPv4 address
 */
void
nat_ipfix_logging_max_fragments_ip4 (u32 limit, ip4_address_t * src)
{
  //TODO: This event SHOULD be rate limited
  nat_ipfix_logging_max_frags_ip4_args_t a;

  skip_if_disabled ();

  a.limit = limit;
  a.src = src->as_u32;

  vl_api_rpc_call_main_thread (nat_ipfix_logging_max_frag_ip4_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
nat_data_callback_max_frags_ip4 (flow_report_main_t * frm,
			         flow_report_t * fr,
			         vlib_frame_t * f,
			         u32 * to_next, u32 node_index)
{
  nat_ipfix_logging_max_frag_ip4 (0, 0, 1);
  return f;
}

static void
nat_ipfix_logging_max_frag_ip6_rpc_cb (nat_ipfix_logging_max_frags_ip6_args_t * a)
{
  ip6_address_t src;
  src.as_u64[0] = a->src[0];
  src.as_u64[1] = a->src[1];
  nat_ipfix_logging_max_frag_ip6 (a->limit, &src, 0);
}

/**
 * @brief Generate maximum IPv6 fragments pending reassembly exceeded event
 *
 * @param limit configured limit
 * @param src source IPv6 address
 */
void
nat_ipfix_logging_max_fragments_ip6 (u32 limit, ip6_address_t * src)
{
  //TODO: This event SHOULD be rate limited
  nat_ipfix_logging_max_frags_ip6_args_t a;

  skip_if_disabled ();

  a.limit = limit;
  a.src[0] = src->as_u64[0];
  a.src[1] = src->as_u64[1];

  vl_api_rpc_call_main_thread (nat_ipfix_logging_max_frag_ip6_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
nat_data_callback_max_frags_ip6 (flow_report_main_t * frm,
			         flow_report_t * fr,
			         vlib_frame_t * f,
			         u32 * to_next, u32 node_index)
{
  nat_ipfix_logging_max_frag_ip6 (0, 0, 1);
  return f;
}

static void
nat_ipfix_logging_nat64_bib_rpc_cb (nat_ipfix_logging_nat64_bib_args_t * a)
{
  ip6_address_t src_ip;
  src_ip.as_u64[0] = a->src_ip[0];
  src_ip.as_u64[1] = a->src_ip[1];
  nat_ipfix_logging_nat64_bibe (a->nat_event, &src_ip, a->nat_src_ip,
                                a->proto, a->src_port, a->nat_src_port,
                                a->vrf_id, 0);
}

/**
 * @brief Generate NAT64 BIB create and delete events
 *
 * @param src_ip       source IPv6 address
 * @param nat_src_ip   transaltes source IPv4 address
 * @param proto        L4 protocol
 * @param src_port     source port
 * @param nat_src_port translated source port
 * @param vrf_id       VRF ID
 * @param is_create    non-zero value if create event otherwise delete event
 */
void
nat_ipfix_logging_nat64_bib (ip6_address_t * src_ip,
                             ip4_address_t * nat_src_ip, u8 proto,
                             u16 src_port, u16 nat_src_port, u32 vrf_id,
                             u8 is_create)
{
  nat_ipfix_logging_nat64_bib_args_t a;

  skip_if_disabled ();

  a.src_ip[0] = src_ip->as_u64[0];
  a.src_ip[1] = src_ip->as_u64[1];
  a.nat_src_ip = nat_src_ip->as_u32;
  a.proto = proto;
  a.src_port = src_port;
  a.nat_src_port = nat_src_port;
  a.vrf_id = vrf_id;
  a.nat_event = is_create ? NAT64_BIB_CREATE : NAT64_BIB_DELETE;

  vl_api_rpc_call_main_thread (nat_ipfix_logging_nat64_bib_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
nat_data_callback_nat64_bib (flow_report_main_t * frm,
			     flow_report_t * fr,
			     vlib_frame_t * f,
			     u32 * to_next, u32 node_index)
{
  nat_ipfix_logging_nat64_bibe (0, 0, 0, 0, 0, 0, 0, 1);
  return f;
}

static void
nat_ipfix_logging_nat64_ses_rpc_cb (nat_ipfix_logging_nat64_ses_args_t * a)
{
  ip6_address_t src_ip, dst_ip;
  src_ip.as_u64[0] = a->src_ip[0];
  src_ip.as_u64[1] = a->src_ip[1];
  dst_ip.as_u64[0] = a->dst_ip[0];
  dst_ip.as_u64[1] = a->dst_ip[1];
  nat_ipfix_logging_nat64_ses (a->nat_event, &src_ip, a->nat_src_ip,
                               a->proto, a->src_port, a->nat_src_port,
                               &dst_ip, a->nat_dst_ip, a->dst_port,
                               a->nat_dst_port, a->vrf_id, 0);
}

/**
 * @brief Generate NAT64 session create and delete events
 *
 * @param src_ip       source IPv6 address
 * @param nat_src_ip   transaltes source IPv4 address
 * @param proto        L4 protocol
 * @param src_port     source port
 * @param nat_src_port translated source port
 * @param dst_ip       destination IPv6 address
 * @param nat_dst_ip   destination IPv4 address
 * @param dst_port     destination port
 * @param nat_dst_port translated destination port
 * @param vrf_id       VRF ID
 * @param is_create    non-zero value if create event otherwise delete event
 */
void
nat_ipfix_logging_nat64_session (ip6_address_t * src_ip,
                                 ip4_address_t * nat_src_ip, u8 proto,
                                 u16 src_port, u16 nat_src_port,
                                 ip6_address_t * dst_ip,
                                 ip4_address_t * nat_dst_ip, u16 dst_port,
                                 u16 nat_dst_port, u32 vrf_id, u8 is_create)
{
  nat_ipfix_logging_nat64_ses_args_t a;

  skip_if_disabled ();

  a.src_ip[0] = src_ip->as_u64[0];
  a.src_ip[1] = src_ip->as_u64[1];
  a.nat_src_ip = nat_src_ip->as_u32;
  a.proto = proto;
  a.src_port = src_port;
  a.nat_src_port = nat_src_port;
  a.dst_ip[0] = dst_ip->as_u64[0];
  a.dst_ip[1] = dst_ip->as_u64[1];
  a.nat_dst_ip = nat_dst_ip->as_u32;
  a.dst_port = dst_port;
  a.nat_dst_port = nat_dst_port;
  a.vrf_id = vrf_id;
  a.nat_event = is_create ? NAT64_SESSION_CREATE : NAT64_SESSION_DELETE;

  vl_api_rpc_call_main_thread (nat_ipfix_logging_nat64_ses_rpc_cb,
			       (u8 *) & a, sizeof (a));
}

vlib_frame_t *
nat_data_callback_nat64_session (flow_report_main_t * frm,
			         flow_report_t * fr,
			         vlib_frame_t * f,
			         u32 * to_next, u32 node_index)
{
  nat_ipfix_logging_nat64_ses (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);
  return f;
}

/**
 * @brief Enable/disable NAT plugin IPFIX logging
 *
 * @param enable    1 if enable, 0 if disable
 * @param domain_id observation domain ID
 * @param src_port  source port number
 *
 * @returns 0 if success
 */
int
snat_ipfix_logging_enable_disable (int enable, u32 domain_id, u16 src_port)
{
  snat_main_t *sm = &snat_main;
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vnet_flow_report_add_del_args_t a;
  int rv;
  u8 e = enable ? 1 : 0;

  if (silm->enabled == e)
    return 0;

  silm->enabled = e;

  clib_memset (&a, 0, sizeof (a));
  a.is_add = enable;
  a.domain_id = domain_id ? domain_id : 1;
  a.src_port = src_port ? src_port : UDP_DST_PORT_ipfix;

  if (sm->deterministic)
    {
      a.rewrite_callback = snat_template_rewrite_max_entries_per_usr;
      a.flow_data_callback = snat_data_callback_max_entries_per_usr;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}
    }
  else
    {
      a.rewrite_callback = snat_template_rewrite_nat44_session;
      a.flow_data_callback = snat_data_callback_nat44_session;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      a.rewrite_callback = snat_template_rewrite_addr_exhausted;
      a.flow_data_callback = snat_data_callback_addr_exhausted;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      a.rewrite_callback = nat_template_rewrite_max_sessions;
      a.flow_data_callback = nat_data_callback_max_sessions;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      a.rewrite_callback = nat_template_rewrite_max_bibs;
      a.flow_data_callback = nat_data_callback_max_bibs;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      a.rewrite_callback = nat_template_rewrite_max_frags_ip4;
      a.flow_data_callback = nat_data_callback_max_frags_ip4;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      a.rewrite_callback = nat_template_rewrite_max_frags_ip6;
      a.flow_data_callback = nat_data_callback_max_frags_ip6;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      a.rewrite_callback = nat_template_rewrite_nat64_bib;
      a.flow_data_callback = nat_data_callback_nat64_bib;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      a.rewrite_callback = nat_template_rewrite_nat64_session;
      a.flow_data_callback = nat_data_callback_nat64_session;

      rv = vnet_flow_report_add_del (frm, &a, NULL);
      if (rv)
	{
	  nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}

      if (sm->endpoint_dependent)
        {
          a.rewrite_callback = snat_template_rewrite_max_entries_per_usr;
          a.flow_data_callback = snat_data_callback_max_entries_per_usr;

          rv = vnet_flow_report_add_del (frm, &a, NULL);
          if (rv)
            {
              nat_log_warn ("vnet_flow_report_add_del returned %d", rv);
              return -1;
            }
        }
    }

  return 0;
}

/**
 * @brief Initialize NAT plugin IPFIX logging
 *
 * @param vm vlib main
 */
void
snat_ipfix_logging_init (vlib_main_t * vm)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;

  silm->enabled = 0;

  /* Set up time reference pair */
  silm->vlib_time_0 = vlib_time_now (vm);
  silm->milisecond_time_0 = unix_time_now_nsec () * 1e-6;
}
