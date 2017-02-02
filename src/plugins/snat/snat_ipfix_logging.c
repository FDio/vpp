/*
 * snat_ipfix_logging.c - NAT Events IPFIX logging
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

#include <vnet/flow/flow_report.h>
#include <vlibmemory/api.h>
#include <snat/snat.h>
#include <snat/snat_ipfix_logging.h>

snat_ipfix_logging_main_t snat_ipfix_logging_main;

#define NAT44_SESSION_CREATE_LEN 26
#define NAT_ADDRESSES_EXHAUTED_LEN 13

#define NAT44_SESSION_CREATE_FIELD_COUNT 8
#define NAT_ADDRESSES_EXHAUTED_FIELD_COUNT 3

typedef struct {
  u8 nat_event;
  u32 src_ip;
  u32 nat_src_ip;
  snat_protocol_t snat_proto;
  u16 src_port;
  u16 nat_src_port;
  u32 vrf_id;
} snat_ipfix_logging_nat44_ses_args_t;

typedef struct {
  u32 pool_id;
} snat_ipfix_logging_addr_exhausted_args_t;

/**
 * @brief Create an IPFIX template packet rewrite string
 *
 * @param frm               flow report main
 * @param fr                flow report
 * @param collector_address collector address
 * @param src_address       source address
 * @param collector_port    collector
 * @param event             NAT event ID
 *
 * @returns template packet
 */
static inline u8 *
snat_template_rewrite (flow_report_main_t * frm,
                       flow_report_t * fr,
                       ip4_address_t * collector_address,
                       ip4_address_t * src_address,
                       u16 collector_port,
                       nat_event_t event)
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
                                      u16 collector_port)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
                                collector_port, NAT_ADDRESSES_EXHAUTED);
}

u8 *
snat_template_rewrite_nat44_session (flow_report_main_t * frm,
                                     flow_report_t * fr,
                                     ip4_address_t * collector_address,
                                     ip4_address_t * src_address,
                                     u16 collector_port)
{
  return snat_template_rewrite (frm, fr, collector_address, src_address,
                                collector_port, NAT44_SESSION_CREATE);
}

static inline void
snat_ipfix_header_create (flow_report_main_t * frm,
                          vlib_buffer_t * b0,
                          u32 * offset)
{
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_stream_t *stream;
  ip4_ipfix_template_packet_t * tp;
  ipfix_message_header_t * h = 0;
  ipfix_set_header_t * s = 0;
  ip4_header_t * ip;
  udp_header_t * udp;
 
  stream = &frm->streams[silm->stream_index];

  b0->current_data = 0;
  b0->current_length = sizeof (*ip) + sizeof (*udp) + sizeof (*h) +
                       sizeof (*s);
  b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VLIB_BUFFER_FLOW_REPORT);
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = frm->fib_index;
  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) &tp->ip4;
  udp = (udp_header_t *) (ip+1);
  h = (ipfix_message_header_t *)(udp+1);
  s = (ipfix_set_header_t *)(h+1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->flags_and_fragment_offset = 0;
  ip->src_address.as_u32 = frm->src_address.as_u32;
  ip->dst_address.as_u32 = frm->ipfix_collector.as_u32;
  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  udp->checksum = 0;

  h->export_time = clib_host_to_net_u32 (
    (u32) (((f64)frm->unix_time_0) + (vlib_time_now(frm->vlib_main) -
    frm->vlib_time_0)));
  h->sequence_number = clib_host_to_net_u32 (stream->sequence_number++);
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  *offset = (u32) (((u8 *)(s+1)) - (u8 *)tp);
}

static inline void
snat_ipfix_send (flow_report_main_t * frm,
                 vlib_frame_t * f,
                 vlib_buffer_t * b0,
                 u16 template_id)
{
  ip4_ipfix_template_packet_t * tp;
  ipfix_message_header_t * h = 0;
  ipfix_set_header_t * s = 0;
  ip4_header_t * ip;
  udp_header_t * udp;
  vlib_main_t * vm = frm->vlib_main;

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
  vlib_main_t * vm = frm->vlib_main;
  u64 now;
  vlib_buffer_free_list_t *fl;
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
          clib_warning ("can't allocate buffer for NAT IPFIX event");
          return;
        }

      b0 = silm->nat44_session_buffer =
        vlib_get_buffer (vm, bi0);
      fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      vlib_buffer_init_for_free_list (b0, fl);
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
      u32 * to_next;
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
      clib_memcpy (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy (b0->data + offset, &src_ip, sizeof (src_ip));
      offset += sizeof (src_ip);

      clib_memcpy (b0->data + offset, &nat_src_ip, sizeof (nat_src_ip));
      offset += sizeof (nat_src_ip);

      clib_memcpy (b0->data + offset, &proto, sizeof (proto));
      offset += sizeof (proto);

      clib_memcpy (b0->data + offset, &src_port, sizeof (src_port));
      offset += sizeof (src_port);

      clib_memcpy (b0->data + offset, &nat_src_port, sizeof (nat_src_port));
      offset += sizeof (nat_src_port);

      clib_memcpy (b0->data + offset, &vrf_id, sizeof(vrf_id));
      offset += sizeof (vrf_id);

      b0->current_length += NAT44_SESSION_CREATE_LEN;
    }

  if (PREDICT_FALSE (do_flush || (offset + NAT44_SESSION_CREATE_LEN) > frm->path_mtu))
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
  vlib_main_t * vm = frm->vlib_main;
  u64 now;
  vlib_buffer_free_list_t *fl;
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
          clib_warning ("can't allocate buffer for NAT IPFIX event");
          return;
        }

      b0 = silm->addr_exhausted_buffer =
        vlib_get_buffer (vm, bi0);
      fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      vlib_buffer_init_for_free_list (b0, fl);
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
      u32 * to_next;
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
      clib_memcpy (b0->data + offset, &time_stamp, sizeof (time_stamp));
      offset += sizeof (time_stamp);

      clib_memcpy (b0->data + offset, &nat_event, sizeof (nat_event));
      offset += sizeof (nat_event);

      clib_memcpy (b0->data + offset, &pool_id, sizeof(pool_id));
      offset += sizeof (pool_id);

      b0->current_length += NAT_ADDRESSES_EXHAUTED_LEN;
    }

  if (PREDICT_FALSE (do_flush || (offset + NAT_ADDRESSES_EXHAUTED_LEN) > frm->path_mtu))
    {
      snat_ipfix_send (frm, f, b0, silm->addr_exhausted_template_id);
      silm->addr_exhausted_frame = 0;
      silm->addr_exhausted_buffer = 0;
      offset = 0;
    }
  silm->addr_exhausted_next_record_offset = offset;
 }

static void
snat_ipfix_logging_nat44_ses_rpc_cb (snat_ipfix_logging_nat44_ses_args_t *a)
{
  snat_ipfix_logging_nat44_ses(a->nat_event, a->src_ip, a->nat_src_ip,
                               a->snat_proto, a->src_port, a->nat_src_port,
                               a->vrf_id, 0);
}

/**
 * @brief Generate NAT44 session create event
 *
 * @param src_ip       source IPv4 address
 * @param nat_src_ip   transaltes source IPv4 address
 * @param snat_proto   SNAT transport protocol
 * @param src_port     source port
 * @param nat_src_port translated source port
 * @param vrf_id       VRF ID
 */
void
snat_ipfix_logging_nat44_ses_create (u32 src_ip,
                                     u32 nat_src_ip,
                                     snat_protocol_t snat_proto,
                                     u16 src_port,
                                     u16 nat_src_port,
                                     u32 vrf_id)
{
  snat_ipfix_logging_nat44_ses_args_t a;

  a.nat_event = NAT44_SESSION_CREATE;
  a.src_ip = src_ip;
  a.nat_src_ip = nat_src_ip;
  a.snat_proto = snat_proto;
  a.src_port = src_port;
  a.nat_src_port = nat_src_port;
  a.vrf_id = vrf_id;

  vl_api_rpc_call_main_thread (snat_ipfix_logging_nat44_ses_rpc_cb, (u8 *) &a,
                               sizeof (a));
}

/**
 * @brief Generate NAT44 session delete event
 *
 * @param src_ip       source IPv4 address
 * @param nat_src_ip   transaltes source IPv4 address
 * @param snat_proto   SNAT transport protocol
 * @param src_port     source port
 * @param nat_src_port translated source port
 * @param vrf_id       VRF ID
 */
void
snat_ipfix_logging_nat44_ses_delete (u32 src_ip,
                                     u32 nat_src_ip,
                                     snat_protocol_t snat_proto,
                                     u16 src_port,
                                     u16 nat_src_port,
                                     u32 vrf_id)
{
  snat_ipfix_logging_nat44_ses_args_t a;

  a.nat_event = NAT44_SESSION_DELETE;
  a.src_ip = src_ip;
  a.nat_src_ip = nat_src_ip;
  a.snat_proto = snat_proto;
  a.src_port = src_port;
  a.nat_src_port = nat_src_port;
  a.vrf_id = vrf_id;

  vl_api_rpc_call_main_thread (snat_ipfix_logging_nat44_ses_rpc_cb, (u8 *) &a,
                               sizeof (a));
}

vlib_frame_t *
snat_data_callback_nat44_session (flow_report_main_t * frm,
                                  flow_report_t * fr,
                                  vlib_frame_t * f,
                                  u32 * to_next,
                                  u32 node_index)
{
  snat_ipfix_logging_nat44_ses(0, 0, 0, 0, 0, 0, 0, 1);
  return f;
}

static void
snat_ipfix_logging_addr_exhausted_rpc_cb
 (snat_ipfix_logging_addr_exhausted_args_t * a)
{
  snat_ipfix_logging_addr_exhausted(a->pool_id, 0);
}

/**
 * @brief Generate NAT addresses exhausted event
 *
 * @param pool_id NAT pool ID
 */
void
snat_ipfix_logging_addresses_exhausted(u32 pool_id)
{
  //TODO: This event SHOULD be rate limited
  snat_ipfix_logging_addr_exhausted_args_t a;

  a.pool_id = pool_id;

  vl_api_rpc_call_main_thread (snat_ipfix_logging_addr_exhausted_rpc_cb,
                               (u8 *) &a, sizeof (a));
}

vlib_frame_t *
snat_data_callback_addr_exhausted (flow_report_main_t * frm,
                                   flow_report_t * fr,
                                   vlib_frame_t * f,
                                   u32 * to_next,
                                   u32 node_index)
{
  snat_ipfix_logging_addr_exhausted(0, 1);
  return f;
}

/**
 * @brief Enable/disable SNAT IPFIX logging
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
  snat_ipfix_logging_main_t *silm = &snat_ipfix_logging_main;
  flow_report_main_t *frm = &flow_report_main;
  vnet_flow_report_add_del_args_t a;
  int rv;
  u8 e = enable ? 1 : 0;

  if (silm->enabled == e)
    return 0;

  silm->enabled = e;

  memset (&a, 0, sizeof (a));
  a.rewrite_callback = snat_template_rewrite_nat44_session;
  a.flow_data_callback = snat_data_callback_nat44_session;
  a.is_add = enable;
  a.domain_id = domain_id ? domain_id : 1;
  a.src_port = src_port ? src_port : UDP_DST_PORT_ipfix;

  rv = vnet_flow_report_add_del (frm, &a);
  if (rv)
    {
      clib_warning ("vnet_flow_report_add_del returned %d", rv);
      return -1;
    }

  a.rewrite_callback = snat_template_rewrite_addr_exhausted;
  a.flow_data_callback = snat_data_callback_addr_exhausted;

  rv = vnet_flow_report_add_del (frm, &a);
  if (rv)
    {
      clib_warning ("vnet_flow_report_add_del returned %d", rv);
      return -1;
    }

  return 0;
}

/**
 * @brief Initialize SNAT IPFIX logging
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
