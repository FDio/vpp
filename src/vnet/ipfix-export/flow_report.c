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
/*
 * flow_report.c
 */
#include <vppinfra/atomics.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/api_errno.h>
#include <vnet/udp/udp.h>

flow_report_main_t flow_report_main;

static_always_inline u8
stream_index_valid (ipfix_exporter_t *exp, u32 index)
{
  return index < vec_len (exp->streams) && exp->streams[index].domain_id != ~0;
}

static_always_inline flow_report_stream_t *
add_stream (ipfix_exporter_t *exp)
{
  u32 i;
  for (i = 0; i < vec_len (exp->streams); i++)
    if (!stream_index_valid (exp, i))
      return &exp->streams[i];
  u32 index = vec_len (exp->streams);
  vec_validate (exp->streams, index);
  return &exp->streams[index];
}

static_always_inline void
delete_stream (ipfix_exporter_t *exp, u32 index)
{
  ASSERT (index < vec_len (exp->streams));
  ASSERT (exp->streams[index].domain_id != ~0);
  exp->streams[index].domain_id = ~0;
}

static i32
find_stream (ipfix_exporter_t *exp, u32 domain_id, u16 src_port)
{
  flow_report_stream_t *stream;
  u32 i;
  for (i = 0; i < vec_len (exp->streams); i++)
    if (stream_index_valid (exp, i))
      {
	stream = &exp->streams[i];
	if (domain_id == stream->domain_id)
	  {
	    if (src_port != stream->src_port)
	      return -2;
	    return i;
	  }
	else if (src_port == stream->src_port)
	  {
	    return -2;
	  }
      }
  return -1;
}

int
send_template_packet (flow_report_main_t *frm, ipfix_exporter_t *exp,
		      flow_report_t *fr, u32 *buffer_indexp)
{
  u32 bi0;
  vlib_buffer_t *b0;
  ip4_ipfix_template_packet_t *tp4;
  ip6_ipfix_template_packet_t *tp6;
  ipfix_message_header_t *h;
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  void *ip;
  udp_header_t *udp;
  vlib_main_t *vm = frm->vlib_main;
  flow_report_stream_t *stream;

  ASSERT (buffer_indexp);

  if (fr->update_rewrite || fr->rewrite == 0)
    {
      if (ip_address_is_zero (&exp->ipfix_collector) ||
	  ip_address_is_zero (&exp->src_address))
	{
	  vlib_node_set_state (frm->vlib_main, flow_report_process_node.index,
			       VLIB_NODE_STATE_DISABLED);
	  return -1;
	}
      vec_free (fr->rewrite);
      fr->update_rewrite = 1;
    }

  if (fr->update_rewrite)
    {
      fr->rewrite = fr->rewrite_callback (
	exp, fr, exp->collector_port, fr->report_elements,
	fr->n_report_elements, fr->stream_indexp);
      fr->update_rewrite = 0;
    }

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return -1;

  b0 = vlib_get_buffer (vm, bi0);

  ASSERT (vec_len (fr->rewrite) < vlib_buffer_get_default_data_size (vm));

  clib_memcpy_fast (b0->data, fr->rewrite, vec_len (fr->rewrite));
  b0->current_data = 0;
  b0->current_length = vec_len (fr->rewrite);
  b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = exp->fib_index;

  if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
    {
      tp4 = vlib_buffer_get_current (b0);
      ip4 = (ip4_header_t *) &tp4->ip4;
      ip = ip4;
      udp = (udp_header_t *) (ip4 + 1);
    }
  else
    {
      tp6 = vlib_buffer_get_current (b0);
      ip6 = (ip6_header_t *) &tp6->ip6;
      ip = ip6;
      udp = (udp_header_t *) (ip6 + 1);
    }
  h = (ipfix_message_header_t *) (udp + 1);

  /* FIXUP: message header export_time */
  h->export_time = (u32)
    (((f64) frm->unix_time_0) +
     (vlib_time_now (frm->vlib_main) - frm->vlib_time_0));
  h->export_time = clib_host_to_net_u32 (h->export_time);

  stream = &exp->streams[fr->stream_index];

  /* FIXUP: message header sequence_number. Templates do not increase it */
  h->sequence_number = clib_host_to_net_u32 (stream->sequence_number);

  /* FIXUP: udp length */
  if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
    udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip4));
  else
    udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip6));

  if (exp->udp_checksum || ip_addr_version (&exp->ipfix_collector) == AF_IP6)
    {
      /* RFC 7011 section 10.3.2. */

      if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
	udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
      else
	{
	  int bogus = 0;
	  udp->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip, &bogus);
	}

      if (udp->checksum == 0)
	udp->checksum = 0xffff;
    }

  *buffer_indexp = bi0;

  fr->last_template_sent = vlib_time_now (vm);

  return 0;
}

u32 always_inline
ipfix_write_headers (ipfix_exporter_t *exp, void *data, void **ip,
		     udp_header_t **udp, u32 len)
{
  if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
    {
      ip4_ipfix_template_packet_t *tp4;
      ip4_header_t *ip4;

      tp4 = (ip4_ipfix_template_packet_t *) data;
      ip4 = (ip4_header_t *) &tp4->ip4;
      ip4->ip_version_and_header_length = 0x45;
      ip4->ttl = 254;
      ip4->protocol = IP_PROTOCOL_UDP;
      ip4->flags_and_fragment_offset = 0;
      ip4->src_address.as_u32 = exp->src_address.ip.ip4.as_u32;
      ip4->dst_address.as_u32 = exp->ipfix_collector.ip.ip4.as_u32;
      *ip = ip4;
      *udp = (udp_header_t *) (ip4 + 1);

      (*udp)->length = clib_host_to_net_u16 (len - sizeof (*ip4));
      return sizeof (*ip4);
    }
  else
    {
      ip6_ipfix_template_packet_t *tp6;
      ip6_header_t *ip6;

      tp6 = (ip6_ipfix_template_packet_t *) data;
      ip6 = (ip6_header_t *) &tp6->ip6;
      ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ip6->hop_limit = 254;
      ip6->protocol = IP_PROTOCOL_UDP;
      ip6->src_address = exp->src_address.ip.ip6;
      ip6->dst_address = exp->ipfix_collector.ip.ip6;
      *ip = ip6;
      *udp = (udp_header_t *) (ip6 + 1);
      (*udp)->length = clib_host_to_net_u16 (len - sizeof (*ip6));
      return sizeof (*ip6);
    }
}

u8 *
vnet_flow_rewrite_generic_callback (ipfix_exporter_t *exp, flow_report_t *fr,
				    u16 collector_port,
				    ipfix_report_element_t *report_elts,
				    u32 n_elts, u32 *stream_indexp)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  void *ip;
  udp_header_t *udp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  ipfix_template_header_t *t;
  ipfix_field_specifier_t *f;
  ipfix_field_specifier_t *first_field;
  u8 *rewrite = 0;
  flow_report_stream_t *stream;
  int i;
  ipfix_report_element_t *ep;
  u32 size;

  ASSERT (stream_indexp);
  ASSERT (n_elts);
  ASSERT (report_elts);

  stream = &exp->streams[fr->stream_index];
  *stream_indexp = fr->stream_index;

  if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
    size = sizeof (ip4_ipfix_template_packet_t);
  else
    size = sizeof (ip6_ipfix_template_packet_t);
  /* allocate rewrite space */
  vec_validate_aligned (rewrite,
			size + n_elts * sizeof (ipfix_field_specifier_t) - 1,
			CLIB_CACHE_LINE_BYTES);

  /* create the packet rewrite string */
  ipfix_write_headers (exp, rewrite, &ip, &udp, vec_len (rewrite));

  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);
  t = (ipfix_template_header_t *) (s + 1);
  first_field = f = (ipfix_field_specifier_t *) (t + 1);
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (collector_port);

  /* FIXUP LATER: message header export_time */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  ep = report_elts;

  for (i = 0; i < n_elts; i++)
    {
      f->e_id_length = ipfix_e_id_length (0, ep->info_element, ep->size);
      f++;
      ep++;
    }

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  /* set length in octets */
  s->set_id_length =
    ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
    {
      ip4 = (ip4_header_t *) ip;
      ip4->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip4);
      ip4->checksum = ip4_header_checksum (ip4);
    }
  else
    {
      ip6 = (ip6_header_t *) ip;
      /* IPv6 payload length does not include the IPv6 header */
      ip6->payload_length = clib_host_to_net_u16 ((u8 *) f - (u8 *) udp);
    }

  return rewrite;
}

vlib_buffer_t *
vnet_ipfix_exp_get_buffer (vlib_main_t *vm, ipfix_exporter_t *exp,
			   flow_report_t *fr, clib_thread_index_t thread_index)
{
  u32 bi0;
  vlib_buffer_t *b0;

  if (fr->per_thread_data[thread_index].buffer)
    return fr->per_thread_data[thread_index].buffer;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return NULL;

  /* Initialize the buffer */
  b0 = fr->per_thread_data[thread_index].buffer = vlib_get_buffer (vm, bi0);

  b0->current_data = 0;
  b0->current_length = exp->all_headers_size;
  b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = exp->fib_index;
  fr->per_thread_data[thread_index].next_data_offset = b0->current_length;

  return b0;
}

/*
 * Send a buffer that is mostly populated. Has flow records but needs some
 * header fields updated.
 */
void
vnet_ipfix_exp_send_buffer (vlib_main_t *vm, ipfix_exporter_t *exp,
			    flow_report_t *fr, flow_report_stream_t *stream,
			    clib_thread_index_t thread_index,
			    vlib_buffer_t *b0)
{
  flow_report_main_t *frm = &flow_report_main;
  vlib_frame_t *f;
  ipfix_set_header_t *s;
  ipfix_message_header_t *h;
  ip4_header_t *ip4 = 0;
  ip6_header_t *ip6 = 0;
  void *ip;
  udp_header_t *udp;
  int ip_len;

  /* nothing to send */
  if (fr->per_thread_data[thread_index].next_data_offset <=
      exp->all_headers_size)
    return;

  ip_len = ipfix_write_headers (exp, (void *) vlib_buffer_get_current (b0),
				&ip, &udp, b0->current_length);

  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);

  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (exp->collector_port);
  udp->checksum = 0;

  /* FIXUP: message header export_time */
  h->export_time =
    (u32) (((f64) frm->unix_time_0) + (vlib_time_now (vm) - frm->vlib_time_0));
  h->export_time = clib_host_to_net_u32 (h->export_time);
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /*
   * RFC 7011: Section 3.2
   *
   * Incremental sequence counter modulo 2^32 of all IPFIX Data Records
   * sent in the current stream from the current Observation Domain by
   * the Exporting Process
   */
  h->sequence_number =
    clib_atomic_fetch_add (&stream->sequence_number,
			   fr->per_thread_data[thread_index].n_data_records);
  h->sequence_number = clib_host_to_net_u32 (h->sequence_number);

  /*
   * For data records we use the template ID as the set ID.
   * RFC 7011: 3.4.3
   */
  s->set_id_length = ipfix_set_id_length (
    fr->template_id,
    b0->current_length - (ip_len + sizeof (*udp) + sizeof (*h)));
  h->version_length =
    version_length (b0->current_length - (ip_len + sizeof (*udp)));

  if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
    {
      ip4 = (ip4_header_t *) ip;
      ip4->length = clib_host_to_net_u16 (b0->current_length);
      ip4->checksum = ip4_header_checksum (ip4);
      udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip4));
      ASSERT (ip4_header_checksum_is_valid (ip4));
    }
  else
    {
      ip6 = (ip6_header_t *) ip;
      /* Ipv6 payload length does not include the IPv6 header */
      ip6->payload_length =
	clib_host_to_net_u16 (b0->current_length - sizeof (*ip6));
      udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip6));
    }

  if (exp->udp_checksum || ip_addr_version (&exp->ipfix_collector) == AF_IP6)
    {
      /* RFC 7011 section 10.3.2. */
      if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
	udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip4);
      else
	{
	  int bogus = 0;
	  udp->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6, &bogus);
	}
      if (udp->checksum == 0)
	udp->checksum = 0xffff;
    }

  /* Find or allocate a frame */
  f = fr->per_thread_data[thread_index].frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
	f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      else
	f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
      fr->per_thread_data[thread_index].frame = f;
      u32 bi0 = vlib_get_buffer_index (vm, b0);

      /* Enqueue the buffer */
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;
    }

  if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
    vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
  else
    vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);

  fr->per_thread_data[thread_index].frame = NULL;
  fr->per_thread_data[thread_index].buffer = NULL;
  fr->per_thread_data[thread_index].next_data_offset = 0;
}

static void
flow_report_process_send (vlib_main_t *vm, flow_report_main_t *frm,
			  ipfix_exporter_t *exp, flow_report_t *fr,
			  u32 next_node, u32 template_bi)
{
  vlib_frame_t *nf = 0;
  u32 *to_next;

  nf = vlib_get_frame_to_node (vm, next_node);
  nf->n_vectors = 0;
  to_next = vlib_frame_vector_args (nf);

  if (template_bi != ~0)
    {
      to_next[0] = template_bi;
      to_next++;
      nf->n_vectors++;
    }

  nf = fr->flow_data_callback (frm, exp, fr, nf, to_next, next_node);
  if (nf)
    {
      if (nf->n_vectors)
	vlib_put_frame_to_node (vm, next_node, nf);
      else
	{
	  vlib_frame_free (vm, nf);
	}
    }
}

static uword
flow_report_process (vlib_main_t * vm,
		     vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  flow_report_main_t *frm = &flow_report_main;
  flow_report_t *fr;
  u32 ip4_lookup_node_index;
  vlib_node_t *ip4_lookup_node;
  u32 ip6_lookup_node_index;
  vlib_node_t *ip6_lookup_node;
  u32 template_bi;
  int send_template;
  f64 now, wait_time;
  f64 def_wait_time = 5.0;
  int rv;
  uword event_type;
  uword *event_data = 0;

  /* Wait for Godot... */
  vlib_process_wait_for_event_or_clock (vm, 1e9);
  event_type = vlib_process_get_events (vm, &event_data);
  if (event_type != 1)
    clib_warning ("bogus kickoff event received, %d", event_type);
  vec_reset_length (event_data);

  /* Enqueue pkts to ip4-lookup */
  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  ip4_lookup_node_index = ip4_lookup_node->index;

  /* Enqueue pkts to ip6-lookup */
  ip6_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip6-lookup");
  ip6_lookup_node_index = ip6_lookup_node->index;

  wait_time = def_wait_time;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, wait_time);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);
      ipfix_exporter_t *exp;
      pool_foreach (exp, frm->exporters)
	{

	  /* 5s delay by default, possibly reduced by template intervals */
	  wait_time = def_wait_time;

	  vec_foreach (fr, exp->reports)
	    {
	      f64 next_template;
	      now = vlib_time_now (vm);

	      /* Need to send a template packet? */
	      send_template =
		now > (fr->last_template_sent + exp->template_interval);
	      send_template += fr->last_template_sent == 0;
	      template_bi = ~0;
	      rv = 0;

	      if (send_template)
		rv = send_template_packet (frm, exp, fr, &template_bi);

	      if (rv < 0)
		continue;

	      /*
	       * decide if template should be sent sooner than current wait
	       * time
	       */
	      next_template =
		(fr->last_template_sent + exp->template_interval) - now;
	      wait_time = clib_min (wait_time, next_template);

	      if (ip_addr_version (&exp->ipfix_collector) == AF_IP4)
		{
		  flow_report_process_send (
		    vm, frm, exp, fr, ip4_lookup_node_index, template_bi);
		}
	      else
		{
		  flow_report_process_send (
		    vm, frm, exp, fr, ip6_lookup_node_index, template_bi);
		}
	    }
	}
    }

  return 0;			/* not so much */
}

VLIB_REGISTER_NODE (flow_report_process_node) = {
    .function = flow_report_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "flow-report-process",
};

int
vnet_flow_report_add_del (ipfix_exporter_t *exp,
			  vnet_flow_report_add_del_args_t *a, u16 *template_id)
{
  int i;
  int found_index = ~0;
  flow_report_t *fr;
  flow_report_stream_t *stream;
  u32 si;
  vlib_thread_main_t *tm = &vlib_thread_main;
  flow_report_main_t *frm = &flow_report_main;
  vlib_main_t *vm = frm->vlib_main;
  int size;

  si = find_stream (exp, a->domain_id, a->src_port);
  if (si == -2)
    return VNET_API_ERROR_INVALID_VALUE;
  if (si == -1 && a->is_add == 0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  for (i = 0; i < vec_len (exp->reports); i++)
    {
      fr = vec_elt_at_index (exp->reports, i);
      if (fr->opaque.as_uword == a->opaque.as_uword
	  && fr->rewrite_callback == a->rewrite_callback
	  && fr->flow_data_callback == a->flow_data_callback)
	{
	  found_index = i;
	  if (template_id)
	    *template_id = fr->template_id;
	  break;
	}
    }

  if (a->is_add == 0)
    {
      if (found_index != ~0)
	{
	  for (int i = 0;
	       i < vec_len (exp->reports[found_index].per_thread_data); i++)
	    {
	      u32 bi;
	      if (exp->reports[found_index].per_thread_data[i].buffer)
		{
		  bi = vlib_get_buffer_index (
		    vm, exp->reports[found_index].per_thread_data[i].buffer);
		  vlib_buffer_free (vm, &bi, 1);
		}
	    }
	  vec_free (exp->reports[found_index].per_thread_data);

	  vec_delete (exp->reports, 1, found_index);
	  stream = &exp->streams[si];
	  stream->n_reports--;
	  if (stream->n_reports == 0)
	    delete_stream (exp, si);
	  return 0;
	}
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (found_index != ~0)
    return VNET_API_ERROR_VALUE_EXIST;

  if (si == -1)
    {
      stream = add_stream (exp);
      stream->domain_id = a->domain_id;
      stream->src_port = a->src_port;
      stream->sequence_number = 0;
      stream->n_reports = 0;
      si = stream - exp->streams;
    }
  else
    stream = &exp->streams[si];

  stream->n_reports++;

  vec_add2 (exp->reports, fr, 1);

  fr->stream_index = si;
  fr->template_id = 256 + stream->next_template_no;
  stream->next_template_no = (stream->next_template_no + 1) % (65536 - 256);
  fr->update_rewrite = 1;
  fr->opaque = a->opaque;
  fr->rewrite_callback = a->rewrite_callback;
  fr->flow_data_callback = a->flow_data_callback;
  fr->report_elements = a->report_elements;
  fr->n_report_elements = a->n_report_elements;
  fr->stream_indexp = a->stream_indexp;
  vec_validate (fr->per_thread_data, tm->n_threads);
  /* Store the flow_report index back in the args struct */
  a->flow_report_index = fr - exp->reports;

  size = 0;
  for (int i = 0; i < fr->n_report_elements; i++)
    size += fr->report_elements[i].size;
  fr->data_record_size = size;
  if (template_id)
    *template_id = fr->template_id;

  return 0;
}

clib_error_t *
flow_report_add_del_error_to_clib_error (int error)
{
  switch (error)
    {
    case 0:
      return 0;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "Flow report not found");
    case VNET_API_ERROR_VALUE_EXIST:
      return clib_error_return (0, "Flow report already exists");
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "Expecting either still unused values "
				"for both domain_id and src_port "
				"or already used values for both fields");
    default:
      return clib_error_return (0, "vnet_flow_report_add_del returned %d",
				error);
    }
}

void
vnet_flow_reports_reset (ipfix_exporter_t *exp)
{
  flow_report_t *fr;
  u32 i;

  for (i = 0; i < vec_len (exp->streams); i++)
    if (stream_index_valid (exp, i))
      exp->streams[i].sequence_number = 0;

  vec_foreach (fr, exp->reports)
    {
      fr->update_rewrite = 1;
      fr->last_template_sent = 0;
    }
}

void
vnet_stream_reset (ipfix_exporter_t *exp, u32 stream_index)
{
  flow_report_t *fr;

  exp->streams[stream_index].sequence_number = 0;

  vec_foreach (fr, exp->reports)
    if (exp->reports->stream_index == stream_index)
      {
	fr->update_rewrite = 1;
	fr->last_template_sent = 0;
      }
}

int
vnet_stream_change (ipfix_exporter_t *exp, u32 old_domain_id, u16 old_src_port,
		    u32 new_domain_id, u16 new_src_port)
{
  i32 stream_index = find_stream (exp, old_domain_id, old_src_port);

  if (stream_index < 0)
    return 1;
  flow_report_stream_t *stream = &exp->streams[stream_index];
  stream->domain_id = new_domain_id;
  stream->src_port = new_src_port;
  if (old_domain_id != new_domain_id || old_src_port != new_src_port)
    vnet_stream_reset (exp, stream_index);
  return 0;
}

static clib_error_t *
set_ipfix_exporter_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  flow_report_main_t *frm = &flow_report_main;
  ip_address_t collector = IP_ADDRESS_V4_ALL_0S, src = IP_ADDRESS_V4_ALL_0S;
  u16 collector_port = UDP_DST_PORT_ipfix;
  u32 fib_id;
  u32 fib_index = ~0;

  u32 path_mtu = 512;		// RFC 7011 section 10.3.3.
  u32 template_interval = 20;
  u8 udp_checksum = 0;
  ipfix_exporter_t *exp = pool_elt_at_index (frm->exporters, 0);
  u32 ip_header_size;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "collector %U", unformat_ip4_address,
		    &collector.ip.ip4))
	;
      else if (unformat (input, "port %U", unformat_udp_port,
			 &collector_port))
	;
      else if (unformat (input, "src %U", unformat_ip4_address, &src.ip.ip4))
	;
      else if (unformat (input, "fib-id %u", &fib_id))
	{
	  ip4_main_t *im = &ip4_main;
	  uword *p = hash_get (im->fib_index_by_table_id, fib_id);
	  if (!p)
	    return clib_error_return (0, "fib ID %d doesn't exist\n", fib_id);
	  fib_index = p[0];
	}
      else if (unformat (input, "path-mtu %u", &path_mtu))
	;
      else if (unformat (input, "template-interval %u", &template_interval))
	;
      else if (unformat (input, "udp-checksum"))
	udp_checksum = 1;
      else
	break;
    }

  /*
   * If the collector address is set then the src must be too.
   * Collector address can be set to 0 to disable exporter
   */
  if (!ip_address_is_zero (&collector) && ip_address_is_zero (&src))
    return clib_error_return (0, "src address required");
  if (collector.version != src.version)
    return clib_error_return (
      0, "src address and dest address must use same IP version");

  if (path_mtu > 1450 /* vpp does not support fragmentation */ )
    return clib_error_return (0, "too big path-mtu value, maximum is 1450");

  if (path_mtu < 68)
    return clib_error_return (0, "too small path-mtu value, minimum is 68");

  /* Calculate how much header data we need. */
  if (collector.version == AF_IP4)
    ip_header_size = sizeof (ip4_header_t);
  else
    ip_header_size = sizeof (ip6_header_t);
  exp->all_headers_size = ip_header_size + sizeof (udp_header_t) +
			  sizeof (ipfix_message_header_t) +
			  sizeof (ipfix_set_header_t);

  /* Reset report streams if we are reconfiguring IP addresses */
  if (ip_address_cmp (&exp->ipfix_collector, &collector) ||
      ip_address_cmp (&exp->src_address, &src) ||
      exp->collector_port != collector_port)
    vnet_flow_reports_reset (exp);

  exp->ipfix_collector = collector;
  exp->collector_port = collector_port;
  exp->src_address = src;
  exp->fib_index = fib_index;
  exp->path_mtu = path_mtu;
  exp->template_interval = template_interval;
  exp->udp_checksum = udp_checksum;

  if (collector.ip.ip4.as_u32)
    vlib_cli_output (vm,
		     "Collector %U, src address %U, "
		     "fib index %d, path MTU %u, "
		     "template resend interval %us, "
		     "udp checksum %s",
		     format_ip4_address, &exp->ipfix_collector.ip.ip4,
		     format_ip4_address, &exp->src_address.ip.ip4, fib_index,
		     path_mtu, template_interval,
		     udp_checksum ? "enabled" : "disabled");
  else
    vlib_cli_output (vm, "IPFIX Collector is disabled");

  /* Turn on the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index, 1, 0);
  return 0;
}

VLIB_CLI_COMMAND (set_ipfix_exporter_command, static) = {
    .path = "set ipfix exporter",
    .short_help = "set ipfix exporter "
                  "collector <ip4-address> [port <port>] "
                  "src <ip4-address> [fib-id <fib-id>] "
                  "[path-mtu <path-mtu>] "
                  "[template-interval <template-interval>] "
                  "[udp-checksum]",
    .function = set_ipfix_exporter_command_fn,
};


static clib_error_t *
ipfix_flush_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  /* poke the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index, 1, 0);
  return 0;
}

VLIB_CLI_COMMAND (ipfix_flush_command, static) = {
    .path = "ipfix flush",
    .short_help = "flush the current ipfix data [for make test]",
    .function = ipfix_flush_command_fn,
};

static clib_error_t *
flow_report_init (vlib_main_t * vm)
{
  flow_report_main_t *frm = &flow_report_main;
  ipfix_exporter_t *exp;

  frm->vlib_main = vm;
  frm->vnet_main = vnet_get_main ();
  frm->unix_time_0 = time (0);
  frm->vlib_time_0 = vlib_time_now (frm->vlib_main);
  /*
   * Make sure that we can always access the first exporter for
   * backwards compatibility reasons.
   */
  pool_alloc (frm->exporters, IPFIX_EXPORTERS_MAX);
  pool_get (frm->exporters, exp);
  /* Verify that this is at index 0 */
  ASSERT (frm->exporters == exp);
  exp->fib_index = ~0;
  return 0;
}

VLIB_INIT_FUNCTION (flow_report_init);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
