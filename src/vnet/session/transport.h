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

#ifndef VNET_VNET_URI_TRANSPORT_H_
#define VNET_VNET_URI_TRANSPORT_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vnet/tcp/tcp_debug.h>

/*
 * Protocol independent transport properties associated to a session
 */
typedef struct _transport_connection
{
  ip46_address_t rmt_ip;	/**< Remote IP */
  ip46_address_t lcl_ip;	/**< Local IP */
  u16 lcl_port;			/**< Local port */
  u16 rmt_port;			/**< Remote port */
  u8 transport_proto;		/**< Protocol id */
  u8 is_ip4;			/**< Flag if IP4 connection */
  u32 vrf;			/**< FIB table id */

  u32 s_index;			/**< Parent session index */
  u32 c_index;			/**< Connection index in transport pool */
  u32 thread_index;		/**< Worker-thread index */

  fib_node_index_t rmt_fei;	/**< FIB entry index for rmt */
  dpo_id_t rmt_dpo;		/**< Forwarding DPO for rmt */

#if TRANSPORT_DEBUG
  elog_track_t elog_track;	/**< Event logging */
  u32 cc_stat_tstamp;		/**< CC stats timestamp */
#endif

  /** Macros for 'derived classes' where base is named "connection" */
#define c_lcl_ip connection.lcl_ip
#define c_rmt_ip connection.rmt_ip
#define c_lcl_ip4 connection.lcl_ip.ip4
#define c_rmt_ip4 connection.rmt_ip.ip4
#define c_lcl_ip6 connection.lcl_ip.ip6
#define c_rmt_ip6 connection.rmt_ip.ip6
#define c_lcl_port connection.lcl_port
#define c_rmt_port connection.rmt_port
#define c_transport_proto connection.transport_proto
#define c_vrf connection.vrf
#define c_state connection.state
#define c_s_index connection.s_index
#define c_c_index connection.c_index
#define c_is_ip4 connection.is_ip4
#define c_thread_index connection.thread_index
#define c_elog_track connection.elog_track
#define c_cc_stat_tstamp connection.cc_stat_tstamp
#define c_rmt_fei connection.rmt_fei
#define c_rmt_dpo connection.rmt_dpo
} transport_connection_t;

typedef enum _transport_proto
{
  TRANSPORT_PROTO_TCP,
  TRANSPORT_PROTO_UDP
} transport_proto_t;

typedef struct _transport_endpoint
{
  ip46_address_t ip;	/** ip address */
  u16 port;		/** port in host order */
  u8 is_ip4;		/** 1 if ip4 */
  u32 vrf;		/** fib table the endpoint is associated with */
} transport_endpoint_t;

#endif /* VNET_VNET_URI_TRANSPORT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
