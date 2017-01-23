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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_H_

#include <ioam/analyse/ioam_analyse.h>

#define MAX_PING_RETRIES 5

#define EVENT_SIG_RECHECK 2

/** @brief udp-ping session data.
    @note cache aligned.
*/
typedef struct
{
  /** UDP ping packet */
  u8 *ping_rewrite;

  /** Ping packet rewrite string len. */
  u16 rewrite_len;

  /** Number of times ping response was dropped.
   * If retry > MAX_PING_RETRIES then declare connectivity as down.
   */
  u16 retry;

  u16 reserve[2];

  /** Analysed data. */
  ioam_analyser_data_t analyse_data;

  /** This is used by ioam e2e for identifying flow and add seq number. */
  u32 flow_ctx;

  /** No of packets sent for this flow. */
  u32 pak_sent;
} udp_ping_flow_data;

/** @brief udp-ping flow data.
    @note cache aligned.
*/
typedef struct
{
  /** Time at which next udp-ping probe has to be sent out. */
  f64 next_send_time;

  /** Interval for which ping packet to be sent. */
  u16 interval;

  u16 reserve[3];

  /** Defines start port of the src port range. */
  u16 start_src_port;

  /** Defines end port of the src port range. */
  u16 end_src_port;

  /** Defines start port of the dest port range. */
  u16 start_dst_port;

  /** Defines end port of the dest port range. */
  u16 end_dst_port;

  /** Ping statistics. */
  udp_ping_flow_data *stats;

} udp_ping_flow;

/** @brief udp-ping data.
*/
typedef struct
{
  /** Local source IPv4/6 address to be used. */
  ip46_address_t src;

  /** Remote destination IPv4/6 address to be used. */
  ip46_address_t dst;

  /** Per flow data. */
  udp_ping_flow udp_data;

  /** To enable fault detection/isolation in network. */
  u8 fault_det;
} ip46_udp_ping_flow;

/** @brief udp-ping main data-structure.
*/
typedef struct
{
  /** Vector od udp-ping data */
  ip46_udp_ping_flow *ip46_flow;

  /** Stores the time interval at which process node has to wake up. */
  u64 timer_interval;

  /** Pointer to VLib main for the node - ipfix-collector. */
  vlib_main_t *vlib_main;

  /** Pointer to vnet main for convenience. */
  vnet_main_t *vnet_main;

  /** API message ID base */
  u16 msg_id_base;
} udp_ping_main_t;

extern udp_ping_main_t udp_ping_main;

void
ip46_udp_ping_set_flow (ip46_address_t src, ip46_address_t dst,
			u16 start_src_port, u16 end_src_port,
			u16 start_dst_port, u16 end_dst_port,
			u16 interval, u8 fault_det, u8 is_disable);

clib_error_t *udp_ping_flow_create (u8 del);

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_UDP_PING_UDP_PING_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
