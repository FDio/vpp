/*
 * snat_ipfix_logging.h - NAT Events IPFIX logging
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
#ifndef __included_snat_ipfix_logging_h__
#define __included_snat_ipfix_logging_h__

typedef enum {
  NAT_ADDRESSES_EXHAUTED = 3,
  NAT44_SESSION_CREATE = 4,
  NAT44_SESSION_DELETE = 5,
  NAT_PORTS_EXHAUSTED = 12,
} nat_event_t;

typedef struct {
  /** S-NAT IPFIX logging enabled */
  u8 enabled;

  /** ipfix buffers under construction */
  vlib_buffer_t *nat44_session_buffer;
  vlib_buffer_t *addr_exhausted_buffer;

  /** frames containing ipfix buffers */
  vlib_frame_t *nat44_session_frame;
  vlib_frame_t *addr_exhausted_frame;

  /** next record offset */
  u32 nat44_session_next_record_offset;
  u32 addr_exhausted_next_record_offset;

  /** Time reference pair */
  u64 milisecond_time_0;
  f64 vlib_time_0;

  /** template IDs */
  u16 nat44_session_template_id;
  u16 addr_exhausted_template_id;

  /** stream index */
  u32 stream_index;
} snat_ipfix_logging_main_t;

extern snat_ipfix_logging_main_t snat_ipfix_logging_main;

void snat_ipfix_logging_init (vlib_main_t * vm);
int snat_ipfix_logging_enable_disable (int enable, u32 domain_id, u16 src_port);
void snat_ipfix_logging_nat44_ses_create (u32 src_ip, u32 nat_src_ip,
                                          snat_protocol_t snat_proto,
                                          u16 src_port, u16 nat_src_port,
                                          u32 vrf_id);
void snat_ipfix_logging_nat44_ses_delete (u32 src_ip, u32 nat_src_ip,
                                          snat_protocol_t snat_proto,
                                          u16 src_port, u16 nat_src_port,
                                          u32 vrf_id);
void snat_ipfix_logging_addresses_exhausted(u32 pool_id);
#endif /* __included_snat_ipfix_logging_h__ */
