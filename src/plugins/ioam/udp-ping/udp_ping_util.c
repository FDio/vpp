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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <ioam/encap/ip6_ioam_e2e.h>
#include <ioam/encap/ip6_ioam_trace.h>
#include <ioam/udp-ping/udp_ping_packet.h>
#include <ioam/udp-ping/udp_ping.h>

#define UDP_PING_REWRITE_LEN 1000

u16
udp_ping_fill_udp_data (udp_ping_t * udp_ping,
			u16 src_port, u16 dst_port, u8 msg_type, u16 ctx)
{
  /* Populate udp ping header */
  udp_ping->udp.src_port = clib_host_to_net_u16 (src_port);
  udp_ping->udp.dst_port = clib_host_to_net_u16 (dst_port);
  udp_ping->udp.length = clib_host_to_net_u16 (sizeof (udp_ping_t));
  udp_ping->udp.checksum = 0;
  udp_ping->ping_data.probe_marker1 =
    clib_host_to_net_u32 (UDP_PING_PROBE_MARKER1);
  udp_ping->ping_data.probe_marker2 =
    clib_host_to_net_u32 (UDP_PING_PROBE_MARKER2);
  udp_ping->ping_data.version = 1;
  udp_ping->ping_data.msg_type = msg_type;
  udp_ping->ping_data.flags = clib_host_to_net_u16 (0);
  udp_ping->ping_data.tel_req_vec = clib_host_to_net_u16 (0);
  udp_ping->ping_data.hop_limit = 254;
  udp_ping->ping_data.hop_count = 0;
  udp_ping->ping_data.reserve = clib_host_to_net_u16 (0);
  udp_ping->ping_data.max_len =
    udp_ping->ping_data.cur_len = clib_host_to_net_u16 (0);
  udp_ping->ping_data.sender_handle = clib_host_to_net_u16 (ctx);
  udp_ping->ping_data.seq_no = clib_host_to_net_u16 (0);

  return (sizeof (udp_ping_t));
}

/**
 * @brief Frame IPv6 udp-ping probe packet.
 *
 * Creates IPv6 UDP-Ping probe packet along with iOAM headers.
 *
 */
int
udp_ping_create_ip6_pak (u8 * buf,	/*u16 len, */
			 ip6_address_t src, ip6_address_t dst,
			 u16 src_port, u16 dst_port, u8 msg_type, u16 ctx)
{
  ip6_header_t *ip0;
  ip6_hop_by_hop_header_t *hbh0;
  //trace_profile *profile = NULL;
  u16 hbh_len = 0, rnd_size = 0, ip0_len = 0, udp_len = 0;
  u16 trace_len = 0, trace_data_size = 0;
  u16 e2e_len = sizeof (ioam_e2e_option_t) - sizeof (ip6_hop_by_hop_option_t);
  u8 *current = NULL;
  ioam_trace_option_t *trace_option;
  ioam_e2e_option_t *e2e;

  ip0 = (ip6_header_t *) buf;

  ip0->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);

  ip0->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  ip0->hop_limit = 255;

  ip0->src_address = src;
  ip0->dst_address = dst;

  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);

  /* Calculate hbh header len */
  //profile = trace_profile_find();
  trace_data_size = fetch_trace_data_size (TRACE_TYPE_IF_TS_APP);
  /* We need 2 times data for trace as packet traverse back to source */
  trace_len = sizeof (ioam_trace_option_t) +
    (5 * trace_data_size * 2) - sizeof (ip6_hop_by_hop_option_t);
  //(profile->num_elts * trace_data_size * 2);
  hbh_len = e2e_len + trace_len + sizeof (ip6_hop_by_hop_header_t);
  rnd_size = (hbh_len + 7) & ~7;

  /* Length of header in 8 octet units, not incl first 8 octets */
  hbh0->length = (rnd_size >> 3) - 1;
  hbh0->protocol = IP_PROTOCOL_UDP;

  /* Populate hbh header */
  current = (u8 *) (hbh0 + 1);

  /* Populate trace */
  trace_option = (ioam_trace_option_t *) current;
  trace_option->hdr.type = HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST |
    HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE;
  trace_option->hdr.length = trace_len;
  trace_option->trace_hdr.ioam_trace_type =
    TRACE_TYPE_IF_TS_APP & TRACE_TYPE_MASK;

  trace_option->trace_hdr.data_list_elts_left = 5 * 2;
  //profile->num_elts * 2;

  current += trace_option->hdr.length + sizeof (ip6_hop_by_hop_option_t);

  /* Populate e2e */
  e2e = (ioam_e2e_option_t *) current;
  e2e->hdr.type = HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE;
  e2e->hdr.length = e2e_len;

  /* Move past hbh header */
  current = ((u8 *) hbh0) + ((hbh0->length + 1) << 3);

  /* Populate udp ping header */
  udp_len = udp_ping_fill_udp_data ((udp_ping_t *) current,
				    src_port, dst_port, msg_type, ctx);

  /* Calculate total length and set it in ip6 header */
  ip0_len = ((hbh0->length + 1) << 3) + udp_len;
  //ip0_len = (len > ip0_len) ? len : ip0_len;
  ip0->payload_length = clib_host_to_net_u16 (ip0_len);

  return (ip0_len + sizeof (ip6_header_t));
}

int
udp_ping_compare_flow (ip46_address_t src, ip46_address_t dst,
		       u16 start_src_port, u16 end_src_port,
		       u16 start_dst_port, u16 end_dst_port,
		       ip46_udp_ping_flow * flow)
{
  if ((0 == ip46_address_cmp (&flow->src, &src)) &&
      (0 == ip46_address_cmp (&flow->dst, &dst)) &&
      (flow->udp_data.start_src_port == start_src_port) &&
      (flow->udp_data.end_src_port == end_src_port) &&
      (flow->udp_data.start_dst_port == start_dst_port) &&
      (flow->udp_data.end_dst_port == end_dst_port))
    {
      return 0;
    }

  return -1;
}

void
udp_ping_populate_flow (ip46_address_t src, ip46_address_t dst,
			u16 start_src_port, u16 end_src_port,
			u16 start_dst_port, u16 end_dst_port,
			u16 interval, u8 fault_det, ip46_udp_ping_flow * flow)
{
  flow->src = src;
  flow->dst = dst;
  flow->udp_data.start_src_port = start_src_port;
  flow->udp_data.end_src_port = end_src_port;
  flow->udp_data.start_dst_port = start_dst_port;
  flow->udp_data.end_dst_port = end_dst_port;
  flow->udp_data.interval = interval;
  flow->udp_data.next_send_time = 0;
  flow->fault_det = fault_det;
}

void
udp_ping_create_rewrite (ip46_udp_ping_flow * flow, u16 ctx)
{
  u16 src_port;
  u16 dst_port;
  u16 no_flows;
  int i;
  udp_ping_flow_data *stats;

  no_flows =
    (flow->udp_data.end_dst_port - flow->udp_data.start_dst_port) + 1;
  no_flows *=
    ((flow->udp_data.end_src_port - flow->udp_data.start_src_port) + 1);

  vec_validate_aligned (flow->udp_data.stats,
			no_flows - 1, CLIB_CACHE_LINE_BYTES);

  i = 0;
  for (src_port = flow->udp_data.start_src_port;
       src_port <= flow->udp_data.end_src_port; src_port++)
    {
      for (dst_port = flow->udp_data.start_dst_port;
	   dst_port <= flow->udp_data.end_dst_port; dst_port++)
	{
	  u8 *rewrite = NULL;

	  stats = flow->udp_data.stats + i;
	  ioam_analyse_init_data (&stats->analyse_data);
	  stats->analyse_data.is_free = 0;

	  vec_validate (rewrite, UDP_PING_REWRITE_LEN - 1);
	  stats->ping_rewrite = rewrite;
	  stats->rewrite_len =
	    udp_ping_create_ip6_pak (rewrite,
				     flow->src.ip6, flow->dst.ip6,
				     src_port, dst_port, UDP_PING_PROBE, ctx);
	  /* For each flow we need to create ioam e2e flow */
	  stats->flow_ctx = ioam_flow_add (1, (u8 *) "udp_ping");	//FIXME
	  i++;
	}
    }
}

void
udp_ping_free_flow_data (ip46_udp_ping_flow * flow)
{
  int i;
  udp_ping_flow_data *stats;

  for (i = 0; i < vec_len (flow->udp_data.stats); i++)
    {
      stats = flow->udp_data.stats + i;
      vec_free (stats->ping_rewrite);
      stats->ping_rewrite = NULL;
      stats->rewrite_len = 0;
    }

  vec_free (flow->udp_data.stats);
  flow->udp_data.stats = NULL;
}

/**
 * @brief Create and send ipv6 udp-ping probe packet.
 *
 */
void
udp_ping_send_ip6_pak (vlib_main_t * vm, ip46_udp_ping_flow * flow)
{
  u16 no_pak;
  u32 *buffers = NULL;
  int i;
  vlib_buffer_t *b0;
  udp_ping_flow_data *stats;
  vlib_frame_t *nf = 0;
  u32 *to_next;
  vlib_node_t *next_node;

  next_node = vlib_get_node_by_name (vm, (u8 *) "ip6-lookup");
  nf = vlib_get_frame_to_node (vm, next_node->index);
  nf->n_vectors = 0;
  to_next = vlib_frame_vector_args (nf);

  no_pak = vec_len (flow->udp_data.stats);
  vec_validate (buffers, (no_pak - 1));
  if (vlib_buffer_alloc (vm, buffers, vec_len (buffers)) != no_pak)
    {
      //Error
      return;
    }

  for (i = 0; i < no_pak; i++)
    {
      int bogus;
      b0 = vlib_get_buffer (vm, buffers[i]);
      stats = flow->udp_data.stats + i;
      clib_memcpy (b0->data, stats->ping_rewrite, stats->rewrite_len);
      b0->current_data = 0;
      b0->current_length = stats->rewrite_len;
      b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

      /* If session is going down, then set path down */
      if ((stats->retry != 0) && ((stats->retry % MAX_PING_RETRIES) == 0))
	ip6_ioam_analyse_set_paths_down (&stats->analyse_data);

      stats->retry++;
      stats->analyse_data.pkt_sent++;
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
      vnet_buffer (b0)->l2_classify.opaque_index = stats->flow_ctx;

      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      ip6_hop_by_hop_header_t *hbh = (ip6_hop_by_hop_header_t *) (ip6 + 1);
      udp_header_t *udp =
	(udp_header_t *) ((u8 *) hbh + ((hbh->length + 1) << 3));

      /* If session is down, then set loopback flag in probe.
       * This is for fault isolation.
       */
      if (flow->fault_det && (stats->retry > MAX_PING_RETRIES))
	{
	  ioam_trace_option_t *opt = (ioam_trace_option_t *)
	    ip6_hbh_get_option (hbh, HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST);
	  ip6_hbh_ioam_trace_set_bit (opt, BIT_LOOPBACK);
	}

      /* Checksum not pre-computed as we intend to vary packet length for every
       * probe. its isnt done yet, but to be taken up later.
       */
      udp->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6, &bogus);
      ASSERT (bogus == 0);
      if (udp->checksum == 0)
	udp->checksum = 0xffff;

      if (nf->n_vectors == VLIB_FRAME_SIZE)
	{
	  vlib_put_frame_to_node (vm, next_node->index, nf);
	  nf = vlib_get_frame_to_node (vm, next_node->index);
	  nf->n_vectors = 0;
	  to_next = vlib_frame_vector_args (nf);
	}
      *to_next = buffers[i];
      nf->n_vectors++;
      to_next++;
    }
  vlib_put_frame_to_node (vm, next_node->index, nf);

  flow->udp_data.next_send_time =
    vlib_time_now (vm) + flow->udp_data.interval;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
