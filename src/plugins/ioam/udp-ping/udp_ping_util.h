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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_UTIL_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_UTIL_H_

int udp_ping_create_ip6_pak (u8 * buf,	/*u16 len, */
			     ip6_address_t src, ip6_address_t dst,
			     u16 src_port, u16 dst_port,
			     u8 msg_type, u16 ctx);

int
udp_ping_compare_flow (ip46_address_t src, ip46_address_t dst,
		       u16 start_src_port, u16 end_src_port,
		       u16 start_dst_port, u16 end_dst_port,
		       ip46_udp_ping_flow * flow);

void
udp_ping_populate_flow (ip46_address_t src, ip46_address_t dst,
			u16 start_src_port, u16 end_src_port,
			u16 start_dst_port, u16 end_dst_port,
			u16 interval, u8 fault_det,
			ip46_udp_ping_flow * flow);

void udp_ping_free_flow_data (ip46_udp_ping_flow * flow);

void udp_ping_create_rewrite (ip46_udp_ping_flow * flow, u16 ctx);

void udp_ping_send_ip6_pak (vlib_main_t * vm, ip46_udp_ping_flow * flow);

/**
 * @brief Create and send ipv6 udp-ping response packet.
 *
 */
always_inline void
udp_ping_create_reply_from_probe_ip6 (ip6_header_t * ip,
				      ip6_hop_by_hop_header_t * hbh,
				      udp_ping_t * udp)
{
  ip6_address_t src;
  u16 src_port;
  ioam_trace_option_t *trace;

  src = ip->src_address;

  ip->src_address = ip->dst_address;
  ip->dst_address = src;

  trace = (ioam_trace_option_t *)
    ip6_hbh_get_option (hbh, HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST);
  ip6_hbh_ioam_trace_reset_bit (trace, BIT_LOOPBACK);

  /* No need of endian transform */
  src_port = udp->udp.src_port;

  udp->udp.src_port = udp->udp.dst_port;
  udp->udp.dst_port = src_port;
  udp->udp.checksum = 0;	//FIXME

  udp->ping_data.msg_type = UDP_PING_REPLY;
}

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_UTIL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
