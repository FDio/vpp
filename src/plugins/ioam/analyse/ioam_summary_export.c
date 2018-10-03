/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/ip/ip6_packet.h>
#include <ioam/analyse/ioam_summary_export.h>
#include <ioam/analyse/ip6/ip6_ioam_analyse.h>

u8 *
ioam_template_rewrite (flow_report_main_t * frm, flow_report_t * fr,
		       ip4_address_t * collector_address,
		       ip4_address_t * src_address, u16 collector_port,
		       ipfix_report_element_t * elts,
		       u32 n_elts, u32 * stream_index)
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
  u32 field_count = 0;
  u32 field_index = 0;
  flow_report_stream_t *stream;

  stream = &frm->streams[fr->stream_index];

  /* Determine field count */
#define _(field,mask,item,length)                                   \
    {                                                               \
  field_count++;                                                    \
  fr->fields_to_send = clib_bitmap_set (fr->fields_to_send,         \
                                        field_index, 1);            \
    }                                                               \
    field_index++;

  foreach_ioam_ipfix_field;
#undef _

  /* Add Src address, dest address, src port, dest port
   * path map,  number of paths manually */
  field_count += 6;

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
  udp->src_port = clib_host_to_net_u16 (collector_port);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipfix);
  udp->length = clib_host_to_net_u16 (vec_len (rewrite) - sizeof (*ip));

  h->domain_id = clib_host_to_net_u32 (stream->domain_id);	//fr->domain_id);

  /* Add Src address, dest address, src port, dest port
   * path map,  number of paths manually */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceIPv6Address,
				      sizeof (ip6_address_t));
  f++;

  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationIPv6Address,
				      sizeof (ip6_address_t));
  f++;

  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceTransportPort, 2);
  f++;

  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationTransportPort, 2);
  f++;

#define _(field,mask,item,length)                               \
    {                                                           \
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */,       \
    item, length);                                              \
    f++;                                                        \
    }
  foreach_ioam_ipfix_field;
#undef _

  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      ioamNumberOfPaths, 2);
  f++;

  /* Add ioamPathMap manually */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      ioamPathMap,
				      (sizeof (ioam_path) +
				       (sizeof (ioam_path_map_t) *
					IOAM_TRACE_MAX_NODES)));
  f++;

  /* Back to the template packet... */
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (IOAM_FLOW_TEMPLATE_ID, f - first_field);

  /* set length in octets */
  s->set_id_length =
    ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
  ip->checksum = ip4_header_checksum (ip);

  return rewrite;
}

u16
ioam_analyse_add_ipfix_record (flow_report_t * fr,
			       ioam_analyser_data_t * record,
			       vlib_buffer_t * b0, u16 offset,
			       ip6_address_t * src, ip6_address_t * dst,
			       u16 src_port, u16 dst_port)
{
  while (clib_atomic_test_and_set (record->writer_lock))
    ;

  int field_index = 0;
  u16 tmp;
  int i, j;
  u16 num_paths = 0;
  u16 num_paths_offset;


  /* Add IPv6 source address manually */
  memcpy (b0->data + offset, &src->as_u64[0], sizeof (u64));
  offset += sizeof (u64);
  memcpy (b0->data + offset, &src->as_u64[1], sizeof (u64));
  offset += sizeof (u64);

  /* Add IPv6 destination address manually */
  memcpy (b0->data + offset, &dst->as_u64[0], sizeof (u64));
  offset += sizeof (u64);
  memcpy (b0->data + offset, &dst->as_u64[1], sizeof (u64));
  offset += sizeof (u64);

  /* Add source port manually */
  tmp = clib_host_to_net_u16 (src_port);
  memcpy (b0->data + offset, &tmp, sizeof (u16));
  offset += sizeof (u16);

  /* Add dest port manually */
  tmp = clib_host_to_net_u16 (dst_port);
  memcpy (b0->data + offset, &tmp, sizeof (u16));
  offset += sizeof (u16);

#define _(field,mask,item,length)                            \
    if (clib_bitmap_get (fr->fields_to_send, field_index))   \
    {                                                        \
      /* Expect only 4 bytes */               \
      u32 tmp;                                             \
      tmp = clib_host_to_net_u32((u32)record->field - (u32)record->chached_data_list->field);\
      memcpy (b0->data + offset, &tmp, length);       \
      offset += length;                                 \
    }
  field_index++;
  foreach_ioam_ipfix_field;
#undef _

  /* Store num_paths_offset here and update later */
  num_paths_offset = offset;
  offset += sizeof (u16);

  /* Add ioamPathMap manually */
  for (i = 0; i < IOAM_MAX_PATHS_PER_FLOW; i++)
    {
      ioam_analyse_trace_record *trace = record->trace_data.path_data + i;
      ioam_analyse_trace_record *trace_cached =
	record->chached_data_list->trace_data.path_data + i;
      ioam_path *path = (ioam_path *) (b0->data + offset);

      if (!trace->is_free)
	{
	  num_paths++;

	  path->num_nodes = trace->num_nodes;

	  path->trace_type = trace->trace_type;
	  if (0 < (trace->pkt_counter - trace_cached->pkt_counter))
	    {
	      u64 new_sum = trace->mean_delay * record->seqno_data.rx_packets;
	      u64 old_sum =
		trace_cached->mean_delay *
		record->chached_data_list->seqno_data.rx_packets;
	      path->mean_delay =
		(u32) ((new_sum - old_sum) / (trace->pkt_counter -
					      trace_cached->pkt_counter));
	      path->mean_delay = clib_host_to_net_u32 (path->mean_delay);
	    }
	  else
	    path->mean_delay = 0;

	  path->bytes_counter =
	    trace->bytes_counter - trace_cached->bytes_counter;
	  path->bytes_counter = clib_host_to_net_u32 (path->bytes_counter);

	  path->pkt_counter = trace->pkt_counter - trace_cached->pkt_counter;
	  path->pkt_counter = clib_host_to_net_u32 (path->pkt_counter);
	  offset += sizeof (ioam_path);

	  for (j = 0; j < trace->num_nodes; j++)
	    {
	      path->path[j].node_id =
		clib_host_to_net_u32 (trace->path[j].node_id);
	      path->path[j].ingress_if =
		clib_host_to_net_u16 (trace->path[j].ingress_if);
	      path->path[j].egress_if =
		clib_host_to_net_u16 (trace->path[j].egress_if);
	      path->path[j].state_up = trace->path[j].state_up;
	    }

	  //offset += (sizeof(ioam_path_map_t) * trace->num_nodes);
	  offset += (sizeof (ioam_path_map_t) * IOAM_TRACE_MAX_NODES);	//FIXME
	}
    }

  num_paths = clib_host_to_net_u16 (num_paths);
  memcpy (b0->data + num_paths_offset, &num_paths, sizeof (u16));

  /* Update cache */
  *(record->chached_data_list) = *record;
  record->chached_data_list->chached_data_list = NULL;

  clib_atomic_release (record->writer_lock);
  return offset;
}

vlib_frame_t *
ioam_send_flows (flow_report_main_t * frm, flow_report_t * fr,
		 vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  vlib_buffer_t *b0 = NULL;
  u32 next_offset = 0;
  u32 bi0 = ~0;
  int i;
  ip4_ipfix_template_packet_t *tp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s = NULL;
  ip4_header_t *ip;
  udp_header_t *udp;
  u32 records_this_buffer;
  u16 new_l0, old_l0;
  ip_csum_t sum0;
  vlib_main_t *vm = frm->vlib_main;
  ip6_address_t temp;
  ioam_analyser_data_t *record = NULL;
  flow_report_stream_t *stream;
  ioam_analyser_data_t *aggregated_data;
  u16 data_len;

  stream = &frm->streams[fr->stream_index];

  memset (&temp, 0, sizeof (ip6_address_t));

  aggregated_data = ioam_analyser_main.aggregated_data;
  data_len = vec_len (aggregated_data);

  vec_foreach_index (i, aggregated_data)
  {
    u8 flush = 0;
    record = aggregated_data + i;

    /* Flush if last entry */
    if (i == (data_len - 1))
      flush = 1;

    if (!record->is_free)
      {

	if (PREDICT_FALSE (b0 == NULL))
	  {
	    if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	      break;

	    b0 = vlib_get_buffer (vm, bi0);
	    memcpy (b0->data, fr->rewrite, vec_len (fr->rewrite));
	    b0->current_data = 0;
	    b0->current_length = vec_len (fr->rewrite);
	    b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	    vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

	    tp = vlib_buffer_get_current (b0);
	    ip = &tp->ip4;
	    h = &tp->ipfix.h;
	    s = &tp->ipfix.s;

	    /* FIXUP: message header export_time */
	    h->export_time = clib_host_to_net_u32 (((u32) time (NULL)));

	    /* FIXUP: message header sequence_number */
	    h->sequence_number = stream->sequence_number++;
	    h->sequence_number = clib_host_to_net_u32 (h->sequence_number);
	    next_offset = (u32) (((u8 *) (s + 1)) - (u8 *) tp);
	    records_this_buffer = 0;
	  }

	next_offset = ioam_analyse_add_ipfix_record (fr, record,
						     b0, next_offset,
						     &temp, &temp, 0, 0);
	records_this_buffer++;

	/* Flush data if packet len is about to reach path mtu */
	if (next_offset > (frm->path_mtu - 250))
	  flush = 1;
      }

    if (PREDICT_FALSE (flush && b0))
      {
	s->set_id_length = ipfix_set_id_length (IOAM_FLOW_TEMPLATE_ID,
						next_offset - (sizeof (*ip) +
							       sizeof (*udp) +
							       sizeof (*h)));
	b0->current_length = next_offset;
	b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	tp = vlib_buffer_get_current (b0);
	ip = (ip4_header_t *) & tp->ip4;
	udp = (udp_header_t *) (ip + 1);

	sum0 = ip->checksum;
	old_l0 = ip->length;
	new_l0 = clib_host_to_net_u16 ((u16) next_offset);
	sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
			       length /* changed member */ );

	ip->checksum = ip_csum_fold (sum0);
	ip->length = new_l0;
	udp->length =
	  clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

	if (frm->udp_checksum)
	  {
	    /* RFC 7011 section 10.3.2. */
	    udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
	    if (udp->checksum == 0)
	      udp->checksum = 0xffff;
	  }

	to_next[0] = bi0;
	f->n_vectors++;
	to_next++;

	if (f->n_vectors == VLIB_FRAME_SIZE)
	  {
	    vlib_put_frame_to_node (vm, node_index, f);
	    f = vlib_get_frame_to_node (vm, node_index);
	    f->n_vectors = 0;
	    to_next = vlib_frame_vector_args (f);
	  }
	b0 = 0;
	bi0 = ~0;
      }
  }

  return f;
}

clib_error_t *
ioam_flow_create (u8 del)
{
  vnet_flow_report_add_del_args_t args;
  int rv;
  u32 domain_id = 0;
  flow_report_main_t *frm = &flow_report_main;
  u16 template_id;

  memset (&args, 0, sizeof (args));
  args.rewrite_callback = ioam_template_rewrite;
  args.flow_data_callback = ioam_send_flows;
  del ? (args.is_add = 0) : (args.is_add = 1);
  args.domain_id = domain_id;

  rv = vnet_flow_report_add_del (frm, &args, &template_id);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "registration not found...");
    default:
      return clib_error_return (0, "vnet_flow_report_add_del returned %d",
				rv);
    }

  return 0;
}

clib_error_t *
ioam_flow_report_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, flow_report_init)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (ioam_flow_report_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
