/*
 * ipfix_logging.h - NAT Events IPFIX logging
 *
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
#ifndef __included_nat_lib_ipfix_logging_h__
#define __included_nat_lib_ipfix_logging_h__

#include <vlib/buffer.h>
#include <vlib/node.h>

#include <nat/lib/lib.h>

typedef enum {
  NAT_ADDRESSES_EXHAUTED = 3,
  NAT44_SESSION_CREATE = 4,
  NAT44_SESSION_DELETE = 5,
  NAT64_SESSION_CREATE = 6,
  NAT64_SESSION_DELETE = 7,
  NAT64_BIB_CREATE = 10,
  NAT64_BIB_DELETE = 11,
  NAT_PORTS_EXHAUSTED = 12,
  QUOTA_EXCEEDED = 13,
} nat_event_t;

typedef enum {
  MAX_SESSION_ENTRIES = 1,
  MAX_BIB_ENTRIES = 2,
  MAX_ENTRIES_PER_USER = 3,
} quota_exceed_event_t;

typedef struct {

  /** ipfix buffers under construction */
  vlib_buffer_t *nat44_session_buffer;
  vlib_buffer_t *addr_exhausted_buffer;
  vlib_buffer_t *max_entries_per_user_buffer;
  vlib_buffer_t *max_sessions_buffer;
  vlib_buffer_t *max_bibs_buffer;
  vlib_buffer_t *max_frags_ip4_buffer;
  vlib_buffer_t *max_frags_ip6_buffer;
  vlib_buffer_t *nat64_bib_buffer;
  vlib_buffer_t *nat64_ses_buffer;

  /** frames containing ipfix buffers */
  vlib_frame_t *nat44_session_frame;
  vlib_frame_t *addr_exhausted_frame;
  vlib_frame_t *max_entries_per_user_frame;
  vlib_frame_t *max_sessions_frame;
  vlib_frame_t *max_bibs_frame;
  vlib_frame_t *max_frags_ip4_frame;
  vlib_frame_t *max_frags_ip6_frame;
  vlib_frame_t *nat64_bib_frame;
  vlib_frame_t *nat64_ses_frame;

  /** next record offset */
  u32 nat44_session_next_record_offset;
  u32 addr_exhausted_next_record_offset;
  u32 max_entries_per_user_next_record_offset;
  u32 max_sessions_next_record_offset;
  u32 max_bibs_next_record_offset;
  u32 max_frags_ip4_next_record_offset;
  u32 max_frags_ip6_next_record_offset;
  u32 nat64_bib_next_record_offset;
  u32 nat64_ses_next_record_offset;

} nat_ipfix_per_thread_data_t;

typedef struct {
  /** NAT plugin IPFIX logging enabled */
  u8 enabled;

  /** Time reference pair */
  u64 milisecond_time_0;
  f64 vlib_time_0;

  /* Per thread data */
  nat_ipfix_per_thread_data_t *per_thread_data;

  /** template IDs */
  u16 nat44_session_template_id;
  u16 addr_exhausted_template_id;
  u16 max_entries_per_user_template_id;
  u16 max_sessions_template_id;
  u16 max_bibs_template_id;
  u16 max_frags_ip4_template_id;
  u16 max_frags_ip6_template_id;
  u16 nat64_bib_template_id;
  u16 nat64_ses_template_id;

  /** stream index */
  u32 stream_index;

  /** vector of worker vlib mains */
  vlib_main_t **worker_vms;

  /** nat data callbacks call counter */
  u16 call_counter;

  /** rate-limit locks */
  clib_spinlock_t addr_exhausted_lock;
  clib_spinlock_t max_sessions_lock;
  clib_spinlock_t max_bibs_lock;
} nat_ipfix_logging_main_t;

extern nat_ipfix_logging_main_t nat_ipfix_logging_main;

int nat_ipfix_logging_enabled ();

void nat_ipfix_logging_init (vlib_main_t * vm);
int nat_ipfix_logging_enable_disable (int enable, u32 domain_id, u16 src_port);
void nat_ipfix_logging_nat44_ses_create (clib_thread_index_t thread_index,
					 u32 src_ip, u32 nat_src_ip,
					 ip_protocol_t proto, u16 src_port,
					 u16 nat_src_port, u32 fib_index);
void nat_ipfix_logging_nat44_ses_delete (clib_thread_index_t thread_index,
					 u32 src_ip, u32 nat_src_ip,
					 ip_protocol_t proto, u16 src_port,
					 u16 nat_src_port, u32 fib_index);
void nat_ipfix_logging_addresses_exhausted (clib_thread_index_t thread_index,
					    u32 pool_id);
void nat_ipfix_logging_max_entries_per_user (clib_thread_index_t thread_index,
					     u32 limit, u32 src_ip);
void nat_ipfix_logging_max_sessions (clib_thread_index_t thread_index,
				     u32 limit);
void nat_ipfix_logging_max_bibs (clib_thread_index_t thread_index, u32 limit);
void nat_ipfix_logging_nat64_session (
  clib_thread_index_t thread_index, ip6_address_t *src_ip,
  ip4_address_t *nat_src_ip, u8 proto, u16 src_port, u16 nat_src_port,
  ip6_address_t *dst_ip, ip4_address_t *nat_dst_ip, u16 dst_port,
  u16 nat_dst_port, u32 vrf_id, u8 is_create);
void nat_ipfix_logging_nat64_bib (clib_thread_index_t thread_index,
				  ip6_address_t *src_ip,
				  ip4_address_t *nat_src_ip, u8 proto,
				  u16 src_port, u16 nat_src_port, u32 vrf_id,
				  u8 is_create);

#endif /* __included_nat_lib_ipfix_logging_h__ */
