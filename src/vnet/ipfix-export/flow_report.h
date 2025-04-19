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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vlib/cli.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>

#include <vnet/ipfix-export/ipfix_packet.h>

/* ipfix field definitions for a particular report */
typedef struct
{
  u32 info_element;
  u32 size;
} ipfix_report_element_t;

/* Used to build the rewrite */
typedef struct
{
  ip4_header_t ip4;
  udp_header_t udp;
  ipfix_template_packet_t ipfix;
} ip4_ipfix_template_packet_t;

/* Used to build the rewrite */
typedef struct
{
  ip6_header_t ip6;
  udp_header_t udp;
  ipfix_template_packet_t ipfix;
} ip6_ipfix_template_packet_t;

struct flow_report_main;
struct flow_report;
struct ipfix_exporter;

typedef vlib_frame_t *(vnet_flow_data_callback_t) (
  struct flow_report_main *frm, struct ipfix_exporter *exp,
  struct flow_report *, vlib_frame_t *, u32 *, u32);

typedef u8 *(vnet_flow_rewrite_callback_t) (struct ipfix_exporter *exp,
					    struct flow_report *,
					    u16, ipfix_report_element_t *elts,
					    u32 n_elts, u32 *stream_index);

u8 *vnet_flow_rewrite_generic_callback (struct ipfix_exporter *exp,
					struct flow_report *, u16,
					ipfix_report_element_t *elts,
					u32 n_elts, u32 *stream_index);

typedef union
{
  void *as_ptr;
  uword as_uword;
} opaque_t;

/*
 * A stream represents an IPFIX session to a destination. We can have
 * multiple streams to the same destination, but each one has its own
 * domain and source port. A stream has a sequence number for that
 * session. A stream may contain multiple templates (i.e multiple for
 * reports) and each stream also has its own template space.
 *
 * A stream has per thread state so that data packets can be built
 * and send on multiple threads at the same time.
 */
typedef struct
{
  u32 domain_id;
  u32 sequence_number;
  u16 src_port;
  u16 n_reports;
  u16 next_template_no;
} flow_report_stream_t;

/*
 * For each flow_report we want to be able to build buffers/frames per thread.
 */
typedef struct
{
  vlib_buffer_t *buffer;
  vlib_frame_t *frame;
  u16 next_data_offset;
  /*
   * We need this per stream as the IPFIX sequence number is the count of
   * data record sent, not the count of packets with data records sent.
   * See RFC 7011, Sec 3.1
   */
  u8 n_data_records;
} flow_report_per_thread_t;

/*
 * A flow report represents a group of fields that are to be exported.
 * Each flow_report has an associated template that is generated when
 * the flow_report is added. Each flow_report is associated with a
 * stream, and multiple flow_reports can use the same stream. When
 * adding a flow_report the keys for the stream are the domain_id
 * and the source_port.
 */
typedef struct flow_report
{
  /* ipfix rewrite, set by callback */
  u8 *rewrite;
  u16 template_id;
  int data_record_size;
  flow_report_per_thread_t *per_thread_data;
  u32 stream_index;
  f64 last_template_sent;
  int update_rewrite;

  /* Bitmap of fields to send */
  uword *fields_to_send;

  /* Opaque data */
  opaque_t opaque;

  /* build-the-template-packet rewrite callback */
  vnet_flow_rewrite_callback_t *rewrite_callback;
  ipfix_report_element_t *report_elements;
  u32 n_report_elements;
  u32 *stream_indexp;

  /* Send-flow-data callback */
  vnet_flow_data_callback_t *flow_data_callback;
} flow_report_t;

/*
 * The maximum number of ipfix exporters we can have at once
 */
#define IPFIX_EXPORTERS_MAX 5

/*
 * We support multiple exporters. Each one has its own configured
 * destination, and its own set of reports and streams.
 */
typedef struct ipfix_exporter
{
  flow_report_t *reports;
  flow_report_stream_t *streams;

  /* ipfix collector ip address, port, our ip address, fib index */
  ip_address_t ipfix_collector;
  u16 collector_port;
  ip_address_t src_address;
  u32 fib_index;

  /* Path MTU */
  u32 path_mtu;

  /* time interval in seconds after which to resend templates */
  u32 template_interval;

  /* UDP checksum calculation enable flag */
  u8 udp_checksum;

  /*
   * The amount of data needed for all the headers, prior to the first
   * flowset (template or data or ...) This is mostly dependent on the
   * L3 and L4 protocols in use.
   */
  u32 all_headers_size;
} ipfix_exporter_t;

typedef struct flow_report_main
{
  /*
   * A pool of the exporters. Entry 0 is always there for backwards
   * compatability reasons. Entries 1 and above have to be created by
   * the users.
   */
  ipfix_exporter_t *exporters;

  /* time scale transform. Joy. */
  u32 unix_time_0;
  f64 vlib_time_0;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u16 msg_id_base;
} flow_report_main_t;

extern flow_report_main_t flow_report_main;

extern vlib_node_registration_t flow_report_process_node;

typedef struct
{
  vnet_flow_data_callback_t *flow_data_callback;
  vnet_flow_rewrite_callback_t *rewrite_callback;
  ipfix_report_element_t *report_elements;
  u32 n_report_elements;
  opaque_t opaque;
  int is_add;
  u32 domain_id;
  u16 src_port;
  u32 *stream_indexp;
  /*
   * When adding a flow report, the index of the flow report is stored
   * here on success.
   */
  u32 flow_report_index;
} vnet_flow_report_add_del_args_t;

int vnet_flow_report_add_del (ipfix_exporter_t *exp,
			      vnet_flow_report_add_del_args_t *a,
			      u16 *template_id);

clib_error_t *flow_report_add_del_error_to_clib_error (int error);

void vnet_flow_reports_reset (ipfix_exporter_t *exp);

void vnet_stream_reset (ipfix_exporter_t *exp, u32 stream_index);

int vnet_stream_change (ipfix_exporter_t *exp, u32 old_domain_id,
			u16 old_src_port, u32 new_domain_id, u16 new_src_port);

/*
 * Search all the exporters for one that has a matching destination address.
 */
ipfix_exporter_t *
vnet_ipfix_exporter_lookup (const ip_address_t *ipfix_collector);

/*
 * Get the currently in use buffer for the given stream on the given core.
 * If there is no current buffer then allocate a new one and return that.
 * This is the buffer that data records should be written into. The offset
 * currently in use is stored in the per-thread data for the stream and
 * should be updated as new records are written in.
 */
vlib_buffer_t *vnet_ipfix_exp_get_buffer (vlib_main_t *vm,
					  ipfix_exporter_t *exp,
					  flow_report_t *fr,
					  clib_thread_index_t thread_index);

/*
 * Send the provided buffer. At this stage the buffer should be populated
 * with data records, with the offset in use stored in the stream per thread
 * data. This func will fix up all the headers and then send the buffer.
 */
void vnet_ipfix_exp_send_buffer (vlib_main_t *vm, ipfix_exporter_t *exp,
				 flow_report_t *fr,
				 flow_report_stream_t *stream,
				 clib_thread_index_t thread_index,
				 vlib_buffer_t *b0);

#endif /* __included_vnet_flow_report_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
