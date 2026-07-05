/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef included_ipfix_h
#define included_ipfix_h

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

#include <ipfix/ipfix_packet.h>

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
} ipfix_ip4_template_packet_t;

/* Used to build the rewrite */
typedef struct
{
  ip6_header_t ip6;
  udp_header_t udp;
  ipfix_template_packet_t ipfix;
} ipfix_ip6_template_packet_t;

struct ipfix_main;
struct ipfix_report;
struct ipfix_exporter;

typedef vlib_frame_t *(ipfix_data_callback_t) (struct ipfix_main *im, struct ipfix_exporter *exp,
					       struct ipfix_report *report, vlib_frame_t *frame,
					       u32 *to_next, u32 node_index);

typedef u8 *(ipfix_rewrite_callback_t) (struct ipfix_exporter *exp, struct ipfix_report *, u16,
					ipfix_report_element_t *elts, u32 n_elts,
					u32 *stream_index);

typedef union
{
  void *as_ptr;
  uword as_uword;
} ipfix_opaque_t;

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
} ipfix_stream_t;

/*
 * For each IPFIX report we build buffers and frames per thread.
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
} ipfix_report_per_thread_t;

/*
 * An IPFIX report represents a group of fields that are to be exported.
 * Each report has an associated template that is generated when the report
 * is added. Reports are associated with streams, and multiple reports can
 * use the same stream. The stream keys are the domain ID and source port.
 */
typedef struct ipfix_report
{
  /* ipfix rewrite, set by callback */
  u8 *rewrite;
  u16 template_id;
  int data_record_size;
  ipfix_report_per_thread_t *per_thread_data;
  u32 stream_index;
  f64 last_template_sent;
  int update_rewrite;

  /* Bitmap of fields to send */
  uword *fields_to_send;

  /* Opaque data */
  ipfix_opaque_t opaque;

  /* build-the-template-packet rewrite callback */
  ipfix_rewrite_callback_t *rewrite_callback;
  ipfix_report_element_t *report_elements;
  u32 n_report_elements;
  u32 *stream_indexp;

  /* Send-flow-data callback */
  ipfix_data_callback_t *data_callback;
} ipfix_report_t;

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
  ipfix_report_t *reports;
  ipfix_stream_t *streams;

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

typedef struct ipfix_main
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
} ipfix_main_t;

typedef struct
{
  ipfix_data_callback_t *data_callback;
  ipfix_rewrite_callback_t *rewrite_callback;
  ipfix_report_element_t *report_elements;
  u32 n_report_elements;
  ipfix_opaque_t opaque;
  int is_add;
  u32 domain_id;
  u16 src_port;
  u32 *stream_indexp;
  /*
   * When adding an IPFIX report, its index is stored here on success.
   */
  u32 report_index;
} ipfix_report_add_del_args_t;

typedef int (ipfix_report_add_del_fn_t) (ipfix_exporter_t *exp, ipfix_report_add_del_args_t *args,
					 u16 *template_id);

#define IPFIX_PLUGIN_SO		    "ipfix_plugin.so"
#define IPFIX_MAIN_SYMBOL	    "ipfix_main"
#define IPFIX_REPORT_ADD_DEL_SYMBOL "ipfix_report_add_del"

#endif /* included_ipfix_h */
