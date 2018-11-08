/*
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
#include <ioam/analyse/ioam_summary_export.h>
#include <vnet/api_errno.h>
#include <ioam/udp-ping/udp_ping.h>

#define UDP_PING_EXPORT_RECORD_SIZE 400

static u8 *
udp_ping_template_rewrite (flow_report_main_t * frm, flow_report_t * fr,
			   ip4_address_t * collector_address,
			   ip4_address_t * src_address, u16 collector_port,
			   ipfix_report_element_t * elts,
			   u32 n_elts, u32 * stream_index)
{
  return ioam_template_rewrite (frm, fr, collector_address,
				src_address, collector_port, elts, n_elts,
				stream_index);
}

static vlib_frame_t *
udp_ping_send_flows (flow_report_main_t * frm, flow_report_t * fr,
		     vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  vlib_buffer_t *b0 = NULL;
  u32 next_offset = 0;
  u32 bi0 = ~0;
  int i, j;
  ip4_ipfix_template_packet_t *tp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s = NULL;
  ip4_header_t *ip;
  udp_header_t *udp;
  u32 records_this_buffer;
  u16 new_l0, old_l0;
  ip_csum_t sum0;
  vlib_main_t *vm = frm->vlib_main;
  flow_report_stream_t *stream;
  udp_ping_flow_data *stats;
  ip46_udp_ping_flow *ip46_flow;
  u16 src_port, dst_port;
  u16 data_len;

  stream = &frm->streams[fr->stream_index];
  data_len = vec_len (udp_ping_main.ip46_flow);

  for (i = 0; i < data_len; i++)
    {
      if (pool_is_free_index (udp_ping_main.ip46_flow, i))
	continue;

      ip46_flow = pool_elt_at_index (udp_ping_main.ip46_flow, i);
      j = 0;
      for (src_port = ip46_flow->udp_data.start_src_port;
	   src_port <= ip46_flow->udp_data.end_src_port; src_port++)
	{
	  for (dst_port = ip46_flow->udp_data.start_dst_port;
	       dst_port <= ip46_flow->udp_data.end_dst_port; dst_port++, j++)
	    {
	      stats = ip46_flow->udp_data.stats + j;
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
		  h->sequence_number =
		    clib_host_to_net_u32 (h->sequence_number);
		  next_offset = (u32) (((u8 *) (s + 1)) - (u8 *) tp);
		  records_this_buffer = 0;
		}

	      next_offset = ioam_analyse_add_ipfix_record (fr,
							   &stats->analyse_data,
							   b0, next_offset,
							   &ip46_flow->
							   src.ip6,
							   &ip46_flow->
							   dst.ip6, src_port,
							   dst_port);

	      //u32 pak_sent = clib_host_to_net_u32(stats->pak_sent);
	      //memcpy (b0->data + next_offset, &pak_sent, sizeof(u32));
	      //next_offset += sizeof(u32);

	      records_this_buffer++;

	      /* Flush data if packet len is about to reach path mtu */
	      if (next_offset > (frm->path_mtu - UDP_PING_EXPORT_RECORD_SIZE))
		{
		  b0->current_length = next_offset;
		  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
		  tp = vlib_buffer_get_current (b0);
		  ip = (ip4_header_t *) & tp->ip4;
		  udp = (udp_header_t *) (ip + 1);
		  h = &tp->ipfix.h;
		  s = &tp->ipfix.s;

		  s->set_id_length =
		    ipfix_set_id_length (IOAM_FLOW_TEMPLATE_ID,
					 next_offset - (sizeof (*ip) +
							sizeof (*udp) +
							sizeof (*h)));
		  h->version_length =
		    version_length (next_offset -
				    (sizeof (*ip) + sizeof (*udp)));

		  sum0 = ip->checksum;
		  old_l0 = ip->length;
		  new_l0 = clib_host_to_net_u16 ((u16) next_offset);
		  sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
					 length /* changed member */ );

		  ip->checksum = ip_csum_fold (sum0);
		  ip->length = new_l0;
		  udp->length =
		    clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

		  udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
		  if (udp->checksum == 0)
		    udp->checksum = 0xffff;

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

  if (b0)
    {
      b0->current_length = next_offset;
      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
      tp = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) & tp->ip4;
      udp = (udp_header_t *) (ip + 1);
      h = &tp->ipfix.h;
      s = &tp->ipfix.s;

      s->set_id_length = ipfix_set_id_length (IOAM_FLOW_TEMPLATE_ID,
					      next_offset - (sizeof (*ip) +
							     sizeof (*udp) +
							     sizeof (*h)));
      h->version_length =
	version_length (next_offset - (sizeof (*ip) + sizeof (*udp)));

      sum0 = ip->checksum;
      old_l0 = ip->length;
      new_l0 = clib_host_to_net_u16 ((u16) next_offset);
      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
			     length /* changed member */ );

      ip->checksum = ip_csum_fold (sum0);
      ip->length = new_l0;
      udp->length = clib_host_to_net_u16 (b0->current_length - sizeof (*ip));

      udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
      if (udp->checksum == 0)
	udp->checksum = 0xffff;

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
  return f;
}

clib_error_t *
udp_ping_flow_create (u8 del)
{
  vnet_flow_report_add_del_args_t args;
  int rv;
  u32 domain_id = 0;
  flow_report_main_t *frm = &flow_report_main;
  u16 template_id;

  clib_memset (&args, 0, sizeof (args));
  args.rewrite_callback = udp_ping_template_rewrite;
  args.flow_data_callback = udp_ping_send_flows;
  del ? (args.is_add = 0) : (args.is_add = 1);
  args.domain_id = domain_id;
  args.src_port = UDP_DST_PORT_ipfix;

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

static clib_error_t *
set_udp_ping_export_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  //int rv;
  int is_add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "export-ipfix"))
	is_add = 1;
      else if (unformat (input, "disable"))
	is_add = 0;
      else
	break;
    }

  if (is_add)
    (void) udp_ping_flow_create (0);
  else
    (void) udp_ping_flow_create (1);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_udp_ping_export_command, static) = {
    .path = "set udp-ping export-ipfix",
    .short_help = "set udp-ping export-ipfix [disable]",
    .function = set_udp_ping_export_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
udp_ping_flow_report_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, flow_report_init)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (udp_ping_flow_report_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
