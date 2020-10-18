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
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/api_errno.h>

flow_report_main_t flow_report_main;

static_always_inline u8
stream_index_valid (u32 index)
{
  flow_report_main_t *frm = &flow_report_main;
  return index < vec_len (frm->streams) &&
    frm->streams[index].domain_id != ~0;
}

static_always_inline flow_report_stream_t *
add_stream (void)
{
  flow_report_main_t *frm = &flow_report_main;
  u32 i;
  for (i = 0; i < vec_len (frm->streams); i++)
    if (!stream_index_valid (i))
      return &frm->streams[i];
  u32 index = vec_len (frm->streams);
  vec_validate (frm->streams, index);
  return &frm->streams[index];
}

static_always_inline void
delete_stream (u32 index)
{
  flow_report_main_t *frm = &flow_report_main;
  ASSERT (index < vec_len (frm->streams));
  ASSERT (frm->streams[index].domain_id != ~0);
  frm->streams[index].domain_id = ~0;
}

static i32
find_stream (u32 domain_id, u16 src_port)
{
  flow_report_main_t *frm = &flow_report_main;
  flow_report_stream_t *stream;
  u32 i;
  for (i = 0; i < vec_len (frm->streams); i++)
    if (stream_index_valid (i))
      {
	stream = &frm->streams[i];
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
send_template_packet (flow_report_main_t * frm,
		      flow_report_t * fr, u32 * buffer_indexp)
{
  u32 bi0;
  vlib_buffer_t *b0;
  ip4_ipfix_template_packet_t *tp;
  ipfix_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  vlib_main_t *vm = frm->vlib_main;
  flow_report_stream_t *stream;

  ASSERT (buffer_indexp);

  if (fr->update_rewrite || fr->rewrite == 0)
    {
      if (frm->ipfix_collector.as_u32 == 0 || frm->src_address.as_u32 == 0)
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
      fr->rewrite = fr->rewrite_callback (frm, fr,
					  &frm->ipfix_collector,
					  &frm->src_address,
					  frm->collector_port,
					  fr->report_elements,
					  fr->n_report_elements,
					  fr->stream_indexp);
      fr->update_rewrite = 0;
    }

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return -1;

  b0 = vlib_get_buffer (vm, bi0);

  /* Initialize the buffer */
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

  ASSERT (vec_len (fr->rewrite) < vlib_buffer_get_default_data_size (vm));

  clib_memcpy_fast (b0->data, fr->rewrite, vec_len (fr->rewrite));
  b0->current_data = 0;
  b0->current_length = vec_len (fr->rewrite);
  b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_FLOW_REPORT);
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = frm->fib_index;

  tp = vlib_buffer_get_current (b0);
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);

  /* FIXUP: message header export_time */
  h->export_time = (u32)
    (((f64) frm->unix_time_0) +
     (vlib_time_now (frm->vlib_main) - frm->vlib_time_0));
  h->export_time = clib_host_to_net_u32 (h->export_time);

  stream = &frm->streams[fr->stream_index];

  /* FIXUP: message header sequence_number. Templates do not increase it */
  h->sequence_number = clib_host_to_net_u32 (stream->sequence_number);

  /* FIXUP: udp length */
  udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

  if (frm->udp_checksum)
    {
      /* RFC 7011 section 10.3.2. */
      udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
      if (udp->checksum == 0)
	udp->checksum = 0xffff;
    }

  *buffer_indexp = bi0;

  fr->last_template_sent = vlib_time_now (vm);

  return 0;
}

u8 *
vnet_flow_rewrite_generic_callback (flow_report_main_t * frm,
				    flow_report_t * fr,
				    ip4_address_t * collector_address,
				    ip4_address_t * src_address,
				    u16 collector_port,
				    ipfix_report_element_t * report_elts,
				    u32 n_elts, u32 * stream_indexp)
{
  ip4_header_t *ip;
  udp_header_t *udp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  ipfix_template_header_t *t;
  ipfix_field_specifier_t *f;
  ipfix_field_specifier_t *first_field;
  u8 *rewrite = 0;
  ip4_ipfix_template_packet_t *tp;
  flow_report_stream_t *stream;
  int i;
  ipfix_report_element_t *ep;

  ASSERT (stream_indexp);
  ASSERT (n_elts);
  ASSERT (report_elts);

  stream = &frm->streams[fr->stream_index];
  *stream_indexp = fr->stream_index;

  /* allocate rewrite space */
  vec_validate_aligned (rewrite,
			sizeof (ip4_ipfix_template_packet_t)
			+ n_elts * sizeof (ipfix_field_specifier_t) - 1,
			CLIB_CACHE_LINE_BYTES);

  /* create the packet rewrite string */
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

  /* FIXUP LATER: message header export_time */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  ep = report_elts;

  for (i = 0; i < n_elts; i++)
    {
      f->e_id_length = ipfix_e_id_length (0, ep->info_element, ep->size);
      f++;
      ep++;
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

static uword
flow_report_process (vlib_main_t * vm,
		     vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  flow_report_main_t *frm = &flow_report_main;
  flow_report_t *fr;
  u32 ip4_lookup_node_index;
  vlib_node_t *ip4_lookup_node;
  vlib_frame_t *nf = 0;
  u32 template_bi;
  u32 *to_next = NULL;
  int send_template;
  f64 now;
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

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 5.0);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      vec_foreach (fr, frm->reports)
      {
	now = vlib_time_now (vm);

	/* Need to send a template packet? */
	send_template =
	  now > (fr->last_template_sent + frm->template_interval);
	send_template += fr->last_template_sent == 0;
	template_bi = ~0;
	rv = 0;

	if (send_template)
	  rv = send_template_packet (frm, fr, &template_bi);

	if (rv < 0)
	  continue;

	nf = NULL;

	if (template_bi != ~0)
	  {
	    nf = vlib_get_frame_to_node (vm, ip4_lookup_node_index);
	    nf->n_vectors = 0;
	    to_next = vlib_frame_vector_args (nf);
	    to_next[0] = template_bi;
	    to_next++;
	    nf->n_vectors++;
	  }

	fr->flow_data_callback (frm, NULL, NULL, NULL, -1); 
	if (nf && nf->n_vectors)
	  vlib_put_frame_to_node (vm, ip4_lookup_node_index, nf);
      }
    }

  return 0;			/* not so much */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flow_report_process_node) = {
    .function = flow_report_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "flow-report-process",
};
/* *INDENT-ON* */

int
vnet_flow_report_add_del (flow_report_main_t * frm,
			  vnet_flow_report_add_del_args_t * a,
			  u16 * template_id)
{
  int i;
  int found_index = ~0;
  flow_report_t *fr;
  flow_report_stream_t *stream;
  u32 si;

  si = find_stream (a->domain_id, a->src_port);
  if (si == -2)
    return VNET_API_ERROR_INVALID_VALUE;
  if (si == -1 && a->is_add == 0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  for (i = 0; i < vec_len (frm->reports); i++)
    {
      fr = vec_elt_at_index (frm->reports, i);
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
	  vec_delete (frm->reports, 1, found_index);
	  stream = &frm->streams[si];
	  stream->n_reports--;
	  if (stream->n_reports == 0)
	    delete_stream (si);
	  return 0;
	}
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (found_index != ~0)
    return VNET_API_ERROR_VALUE_EXIST;

  if (si == -1)
    {
      stream = add_stream ();
      stream->domain_id = a->domain_id;
      stream->src_port = a->src_port;
      stream->sequence_number = 0;
      stream->n_reports = 0;
      si = stream - frm->streams;
    }
  else
    stream = &frm->streams[si];

  stream->n_reports++;

  vec_add2 (frm->reports, fr, 1);

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
vnet_flow_reports_reset (flow_report_main_t * frm)
{
  flow_report_t *fr;
  u32 i;

  for (i = 0; i < vec_len (frm->streams); i++)
    if (stream_index_valid (i))
      frm->streams[i].sequence_number = 0;

  vec_foreach (fr, frm->reports)
  {
    fr->update_rewrite = 1;
    fr->last_template_sent = 0;
  }
}

void
vnet_stream_reset (flow_report_main_t * frm, u32 stream_index)
{
  flow_report_t *fr;

  frm->streams[stream_index].sequence_number = 0;

  vec_foreach (fr, frm->reports)
    if (frm->reports->stream_index == stream_index)
    {
      fr->update_rewrite = 1;
      fr->last_template_sent = 0;
    }
}

int
vnet_stream_change (flow_report_main_t * frm,
		    u32 old_domain_id, u16 old_src_port,
		    u32 new_domain_id, u16 new_src_port)
{
  i32 stream_index = find_stream (old_domain_id, old_src_port);
  if (stream_index < 0)
    return 1;
  flow_report_stream_t *stream = &frm->streams[stream_index];
  stream->domain_id = new_domain_id;
  stream->src_port = new_src_port;
  if (old_domain_id != new_domain_id || old_src_port != new_src_port)
    vnet_stream_reset (frm, stream_index);
  return 0;
}

static clib_error_t *
set_ipfix_exporter_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  flow_report_main_t *frm = &flow_report_main;
  ip4_address_t collector, src;
  u16 collector_port = UDP_DST_PORT_ipfix;
  u32 fib_id;
  u32 fib_index = ~0;

  collector.as_u32 = 0;
  src.as_u32 = 0;
  u32 path_mtu = 512;		// RFC 7011 section 10.3.3.
  u32 template_interval = 20;
  u8 udp_checksum = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "collector %U", unformat_ip4_address, &collector))
	;
      else if (unformat (input, "port %U", unformat_udp_port,
			 &collector_port))
	;
      else if (unformat (input, "src %U", unformat_ip4_address, &src))
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

  if (collector.as_u32 != 0 && src.as_u32 == 0)
    return clib_error_return (0, "src address required");

  if (path_mtu > 1450 /* vpp does not support fragmentation */ )
    return clib_error_return (0, "too big path-mtu value, maximum is 1450");

  if (path_mtu < 68)
    return clib_error_return (0, "too small path-mtu value, minimum is 68");

  /* Reset report streams if we are reconfiguring IP addresses */
  if (frm->ipfix_collector.as_u32 != collector.as_u32 ||
      frm->src_address.as_u32 != src.as_u32 ||
      frm->collector_port != collector_port)
    vnet_flow_reports_reset (frm);

  frm->ipfix_collector.as_u32 = collector.as_u32;
  frm->collector_port = collector_port;
  frm->src_address.as_u32 = src.as_u32;
  frm->fib_index = fib_index;
  frm->path_mtu = path_mtu;
  frm->template_interval = template_interval;
  frm->udp_checksum = udp_checksum;

  if (collector.as_u32)
    vlib_cli_output (vm, "Collector %U, src address %U, "
		     "fib index %d, path MTU %u, "
		     "template resend interval %us, "
		     "udp checksum %s",
		     format_ip4_address, &frm->ipfix_collector,
		     format_ip4_address, &frm->src_address,
		     fib_index, path_mtu, template_interval,
		     udp_checksum ? "enabled" : "disabled");
  else
    vlib_cli_output (vm, "IPFIX Collector is disabled");

  /* Turn on the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index, 1, 0);
  return 0;
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */


static clib_error_t *
ipfix_flush_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  /* poke the flow reporting process */
  vlib_process_signal_event (vm, flow_report_process_node.index, 1, 0);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipfix_flush_command, static) = {
    .path = "ipfix flush",
    .short_help = "flush the current ipfix data [for make test]",
    .function = ipfix_flush_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
flow_report_init (vlib_main_t * vm)
{
  flow_report_main_t *frm = &flow_report_main;

  frm->vlib_main = vm;
  frm->vnet_main = vnet_get_main ();
  frm->unix_time_0 = time (0);
  frm->vlib_time_0 = vlib_time_now (frm->vlib_main);
  frm->fib_index = ~0;

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
