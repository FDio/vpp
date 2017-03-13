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
#ifndef __included_vnet_flow_report_h__
#define __included_vnet_flow_report_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vlib/cli.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>

#include <vnet/flow/ipfix_packet.h>

/* Used to build the rewrite */
typedef struct {
  ip4_header_t ip4;
  udp_header_t udp;
  ipfix_template_packet_t ipfix;
} ip4_ipfix_template_packet_t;

struct flow_report_main;
struct flow_report;

typedef u8 * (vnet_flow_rewrite_callback_t)(struct flow_report_main *, 
                                            struct flow_report *,
                                            ip4_address_t *,
                                            ip4_address_t *,
                                            u16);

typedef vlib_frame_t * (vnet_flow_data_callback_t) (struct flow_report_main *, 
                                                    struct flow_report *,
                                                    vlib_frame_t *, u32 *, 
                                                    u32);

typedef union {
  void * as_ptr;
  uword as_uword;
} opaque_t;

typedef struct {
  u32 domain_id;
  u32 sequence_number;
  u16 src_port;
  u16 n_reports;
  u16 next_template_no;
} flow_report_stream_t;

typedef struct flow_report {
  /* ipfix rewrite, set by callback */
  u8 * rewrite;
  u16 template_id;
  u32 stream_index;
  f64 last_template_sent;
  int update_rewrite;

  /* Bitmap of fields to send */
  uword * fields_to_send;

  /* Opaque data */
  opaque_t opaque;

  /* build-the-rewrite callback */
  vnet_flow_rewrite_callback_t *rewrite_callback;

  /* Send-flow-data callback */
  vnet_flow_data_callback_t *flow_data_callback;
} flow_report_t;

typedef struct flow_report_main {
  flow_report_t * reports;
  flow_report_stream_t * streams;

  /* ipfix collector ip address, port, our ip address, fib index */
  ip4_address_t ipfix_collector;
  u16 collector_port;
  ip4_address_t src_address;
  u32 fib_index;

  /* Path MTU */
  u32 path_mtu;

  /* time interval in seconds after which to resend templates */
  u32 template_interval;

  /* UDP checksum calculation enable flag */
  u8 udp_checksum;

  /* time scale transform. Joy. */
  u32 unix_time_0;
  f64 vlib_time_0;

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} flow_report_main_t;

extern flow_report_main_t flow_report_main;

extern vlib_node_registration_t flow_report_process_node;

int vnet_flow_report_enable_disable (u32 sw_if_index, u32 table_index,
                                       int enable_disable);
typedef struct {
  vnet_flow_data_callback_t *flow_data_callback;
  vnet_flow_rewrite_callback_t *rewrite_callback;
  opaque_t opaque;
  int is_add;
  u32 domain_id;
  u16 src_port;
} vnet_flow_report_add_del_args_t;  

int vnet_flow_report_add_del (flow_report_main_t *frm, 
                              vnet_flow_report_add_del_args_t *a,
			      u16 *template_id);

clib_error_t * flow_report_add_del_error_to_clib_error (int error);

void vnet_flow_reports_reset (flow_report_main_t * frm);

void vnet_stream_reset (flow_report_main_t * frm, u32 stream_index);

int vnet_stream_change (flow_report_main_t * frm,
                        u32 old_domain_id, u16 old_src_port,
                        u32 new_domain_id, u16 new_src_port);

#endif /* __included_vnet_flow_report_h__ */
