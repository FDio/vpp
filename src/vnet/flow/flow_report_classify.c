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
#include <vnet/flow/flow_report.h>
#include <vnet/flow/flow_report_classify.h>
#include <vnet/api_errno.h>

/* Common prefix of tcp and udp headers
 * containing only source and destination port fields */
typedef struct
{
  u16 src_port, dst_port;
} tcpudp_header_t;

flow_report_classify_main_t flow_report_classify_main;

u8 *
ipfix_classify_template_rewrite (flow_report_main_t * frm,
				 flow_report_t * fr,
				 ip4_address_t * collector_address,
				 ip4_address_t * src_address,
				 u16 collector_port)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  vnet_classify_table_t *tblp;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  u32 flow_table_index = fr->opaque.as_uword;
  u8 *ip_start;
  ip4_header_t *ip;
  ip6_header_t *ip6;
  tcpudp_header_t *tcpudp;
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
  u8 ip_version;
  u8 transport_protocol;
  u8 *virt_mask;
  u8 *real_mask;

  stream = &frm->streams[fr->stream_index];

  ipfix_classify_table_t *table = &fcm->tables[flow_table_index];

  ip_version = table->ip_version;
  transport_protocol = table->transport_protocol;

  tblp = pool_elt_at_index (vcm->tables, table->classify_table_index);

  virt_mask = (u8 *) (tblp->mask - tblp->skip_n_vectors);
  real_mask = (u8 *) (tblp->mask);

  /* Determine field count */
  ip_start = virt_mask + sizeof (ethernet_header_t);
#define _(field,mask,item,length)                                             \
  if (((u8 *)&field >= real_mask) && (memcmp(&field, &mask, length) == 0))    \
    {                                                                         \
      field_count++;                                                          \
                                                                              \
      fr->fields_to_send = clib_bitmap_set (fr->fields_to_send,               \
                                            field_index, 1);                  \
    }                                                                         \
  field_index++;
  foreach_ipfix_field;
#undef _

  /* Add packetTotalCount manually */
  field_count += 1;

  /* $$$ enterprise fields, at some later date */

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
  /* FIXUP: message header sequence_number */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* Take another trip through the mask and build the template */
  ip_start = virt_mask + sizeof (ethernet_header_t);
#define _(field,mask,item,length)                                             \
  if (((u8 *)&field >= real_mask) && (memcmp(&field, &mask, length) == 0))    \
    {                                                                         \
      f->e_id_length = ipfix_e_id_length (0 /* enterprise */,                 \
                                          item, length);                      \
      f++;                                                                    \
    }
  foreach_ipfix_field;
#undef _

  /* Add packetTotalCount manually */
  f->e_id_length =
    ipfix_e_id_length (0 /* enterprise */ , packetTotalCount, 8);
  f++;

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

vlib_frame_t *
ipfix_classify_send_flows (flow_report_main_t * frm,
			   flow_report_t * fr,
			   vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  u32 flow_table_index = fr->opaque.as_uword;
  vnet_classify_table_t *t;
  vnet_classify_bucket_t *b;
  vnet_classify_entry_t *v, *save_v;
  vlib_buffer_t *b0 = 0;
  u32 next_offset = 0;
  u32 record_offset = 0;
  u32 bi0 = ~0;
  int i, j, k;
  ip4_ipfix_template_packet_t *tp;
  ipfix_message_header_t *h = 0;
  ipfix_set_header_t *s = 0;
  u8 *ip_start;
  ip4_header_t *ip;
  ip6_header_t *ip6;
  tcpudp_header_t *tcpudp;
  udp_header_t *udp;
  int field_index;
  u32 records_this_buffer;
  u16 new_l0, old_l0;
  ip_csum_t sum0;
  vlib_main_t *vm = frm->vlib_main;
  flow_report_stream_t *stream;
  u8 ip_version;
  u8 transport_protocol;
  u8 *virt_key;

  stream = &frm->streams[fr->stream_index];

  ipfix_classify_table_t *table = &fcm->tables[flow_table_index];

  ip_version = table->ip_version;
  transport_protocol = table->transport_protocol;

  t = pool_elt_at_index (vcm->tables, table->classify_table_index);

  while (__sync_lock_test_and_set (t->writer_lock, 1))
    ;

  for (i = 0; i < t->nbuckets; i++)
    {
      b = &t->buckets[i];
      if (b->offset == 0)
	continue;

      save_v = vnet_classify_get_entry (t, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < t->entries_per_page; k++)
	    {
	      v = vnet_classify_entry_at_index
		(t, save_v, j * t->entries_per_page + k);

	      if (vnet_classify_entry_is_free (v))
		continue;

	      /* OK, we have something to send... */
	      if (PREDICT_FALSE (b0 == 0))
		{
		  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
		    goto flush;
		  b0 = vlib_get_buffer (vm, bi0);

		  u32 copy_len = sizeof (ip4_header_t) +
		    sizeof (udp_header_t) + sizeof (ipfix_message_header_t);
		  clib_memcpy (b0->data, fr->rewrite, copy_len);
		  b0->current_data = 0;
		  b0->current_length = copy_len;
		  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] = frm->fib_index;

		  tp = vlib_buffer_get_current (b0);
		  ip = (ip4_header_t *) & tp->ip4;
		  udp = (udp_header_t *) (ip + 1);
		  h = (ipfix_message_header_t *) (udp + 1);
		  s = (ipfix_set_header_t *) (h + 1);

		  /* FIXUP: message header export_time */
		  h->export_time = (u32)
		    (((f64) frm->unix_time_0) +
		     (vlib_time_now (frm->vlib_main) - frm->vlib_time_0));
		  h->export_time = clib_host_to_net_u32 (h->export_time);

		  /* FIXUP: message header sequence_number */
		  h->sequence_number = stream->sequence_number;
		  h->sequence_number =
		    clib_host_to_net_u32 (h->sequence_number);

		  next_offset = (u32) (((u8 *) (s + 1)) - (u8 *) tp);
		  record_offset = next_offset;
		  records_this_buffer = 0;
		}

	      field_index = 0;
	      virt_key = (u8 *) (v->key - t->skip_n_vectors);
	      ip_start = virt_key + sizeof (ethernet_header_t);
#define _(field,mask,item,length)                                       \
              if (clib_bitmap_get (fr->fields_to_send, field_index))    \
                {                                                       \
                  clib_memcpy (b0->data + next_offset, &field,          \
                          length);                                      \
                  next_offset += length;                                \
                }                                                       \
              field_index++;
	      foreach_ipfix_field;
#undef _

	      /* Add packetTotalCount manually */
	      {
		u64 packets = clib_host_to_net_u64 (v->hits);
		clib_memcpy (b0->data + next_offset, &packets,
			     sizeof (packets));
		next_offset += sizeof (packets);
	      }
	      records_this_buffer++;
	      stream->sequence_number++;

	      /* Next record will have the same size as this record */
	      u32 next_record_size = next_offset - record_offset;
	      record_offset = next_offset;

	      if (next_offset + next_record_size > frm->path_mtu)
		{
		  s->set_id_length = ipfix_set_id_length (fr->template_id,
							  next_offset -
							  (sizeof (*ip) +
							   sizeof (*udp) +
							   sizeof (*h)));
		  h->version_length =
		    version_length (next_offset -
				    (sizeof (*ip) + sizeof (*udp)));
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
		      udp->checksum =
			ip4_tcp_udp_compute_checksum (vm, b0, ip);
		      if (udp->checksum == 0)
			udp->checksum = 0xffff;
		    }

		  ASSERT (ip->checksum == ip4_header_checksum (ip));

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
	}
    }

flush:
  if (b0)
    {
      s->set_id_length = ipfix_set_id_length (fr->template_id,
					      next_offset -
					      (sizeof (*ip) + sizeof (*udp) +
					       sizeof (*h)));
      h->version_length = version_length (next_offset -
					  (sizeof (*ip) + sizeof (*udp)));
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
      udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

      if (frm->udp_checksum)
	{
	  /* RFC 7011 section 10.3.2. */
	  udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
	  if (udp->checksum == 0)
	    udp->checksum = 0xffff;
	}

      ASSERT (ip->checksum == ip4_header_checksum (ip));

      to_next[0] = bi0;
      f->n_vectors++;

      b0 = 0;
      bi0 = ~0;
    }

  *(t->writer_lock) = 0;
  return f;
}

static clib_error_t *
ipfix_classify_table_add_del_command_fn (vlib_main_t * vm,
					 unformat_input_t * input,
					 vlib_cli_command_t * cmd)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  flow_report_main_t *frm = &flow_report_main;
  vnet_flow_report_add_del_args_t args;
  ipfix_classify_table_t *table;
  int rv;
  int is_add = -1;
  u32 classify_table_index = ~0;
  u8 ip_version = 0;
  u8 transport_protocol = 255;
  clib_error_t *error = 0;

  if (fcm->src_port == 0)
    clib_error_return (0, "call 'set ipfix classify stream' first");

  memset (&args, 0, sizeof (args));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "%d", &classify_table_index))
	;
      else if (unformat (input, "ip4"))
	ip_version = 4;
      else if (unformat (input, "ip6"))
	ip_version = 6;
      else if (unformat (input, "tcp"))
	transport_protocol = 6;
      else if (unformat (input, "udp"))
	transport_protocol = 17;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (is_add == -1)
    return clib_error_return (0, "expecting: add|del");
  if (classify_table_index == ~0)
    return clib_error_return (0, "classifier table not specified");
  if (ip_version == 0)
    return clib_error_return (0, "IP version not specified");

  table = 0;
  int i;
  for (i = 0; i < vec_len (fcm->tables); i++)
    if (ipfix_classify_table_index_valid (i))
      if (fcm->tables[i].classify_table_index == classify_table_index)
	{
	  table = &fcm->tables[i];
	  break;
	}

  if (is_add)
    {
      if (table)
	return clib_error_return (0,
				  "Specified classifier table already used");
      table = ipfix_classify_add_table ();
      table->classify_table_index = classify_table_index;
    }
  else
    {
      if (!table)
	return clib_error_return (0,
				  "Specified classifier table not registered");
    }

  table->ip_version = ip_version;
  table->transport_protocol = transport_protocol;

  args.opaque.as_uword = table - fcm->tables;
  args.rewrite_callback = ipfix_classify_template_rewrite;
  args.flow_data_callback = ipfix_classify_send_flows;
  args.is_add = is_add;
  args.domain_id = fcm->domain_id;
  args.src_port = fcm->src_port;

  rv = vnet_flow_report_add_del (frm, &args, NULL);

  error = flow_report_add_del_error_to_clib_error (rv);

  /* If deleting, or add failed */
  if (is_add == 0 || (rv && is_add))
    ipfix_classify_delete_table (table - fcm->tables);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipfix_classify_table_add_del_command, static) = {
  .path = "ipfix classify table",
  .short_help = "ipfix classify table add|del <table-index>",
  .function = ipfix_classify_table_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_ipfix_classify_stream_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  flow_report_classify_main_t *fcm = &flow_report_classify_main;
  flow_report_main_t *frm = &flow_report_main;
  u32 domain_id = 1;
  u32 src_port = UDP_DST_PORT_ipfix;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "domain %d", &domain_id))
	;
      else if (unformat (input, "src-port %d", &src_port))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (fcm->src_port != 0 &&
      (fcm->domain_id != domain_id || fcm->src_port != (u16) src_port))
    {
      int rv = vnet_stream_change (frm, fcm->domain_id, fcm->src_port,
				   domain_id, (u16) src_port);
      ASSERT (rv == 0);
    }

  fcm->domain_id = domain_id;
  fcm->src_port = (u16) src_port;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ipfix_classify_stream_command, static) = {
  .path = "set ipfix classify stream",
  .short_help = "set ipfix classify stream"
                "[domain <domain-id>] [src-port <src-port>]",
  .function = set_ipfix_classify_stream_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
flow_report_classify_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, flow_report_init)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (flow_report_classify_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
