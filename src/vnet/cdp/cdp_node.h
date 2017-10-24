/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
#ifndef __included_cdp_node_h__
#define __included_cdp_node_h__

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/snap/snap.h>
#include <vnet/hdlc/hdlc.h>
#include <vnet/hdlc/packet.h>

#include <vppinfra/format.h>
#include <vppinfra/hash.h>

#include <vnet/cdp/cdp_protocol.h>

typedef enum
{
  CDP_PACKET_TEMPLATE_ETHERNET,
  CDP_PACKET_TEMPLATE_HDLC,
  CDP_PACKET_TEMPLATE_SRP,
  CDP_N_PACKET_TEMPLATES,
} cdp_packet_template_id_t;

typedef struct
{
  /* neighbor's vlib software interface index */
  u32 sw_if_index;

  /* Timers */
  f64 last_heard;
  f64 last_sent;

  /* Neighbor time-to-live (usually 180s) */
  u8 ttl_in_seconds;

  /* "no cdp run" or similar */
  u8 disabled;

  /* tx packet template id for this neighbor */
  u8 packet_template_index;

  /* Jenkins hash optimization: avoid tlv scan, send short keepalive msg */
  u8 last_packet_signature_valid;
  uword last_packet_signature;

  /* Info we actually keep about each neighbor */
  u8 *device_name;
  u8 *version;
  u8 *port_id;
  u8 *platform;

  /* last received packet, for the J-hash optimization */
  u8 *last_rx_pkt;
} cdp_neighbor_t;

#define foreach_neighbor_string_field           \
_(device_name)                                  \
_(version)                                      \
_(port_id)                                      \
_(platform)

typedef struct
{
  /* pool of cdp neighbors */
  cdp_neighbor_t *neighbors;

  /* tx pcap debug enable */
  u8 tx_pcap_debug;

  /* rapidly find a neighbor by vlib software interface index */
  uword *neighbor_by_sw_if_index;

  /* Background process node index */
  u32 cdp_process_node_index;

  /* Packet templates for different encap types */
  vlib_packet_template_t packet_templates[CDP_N_PACKET_TEMPLATES];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} cdp_main_t;

extern cdp_main_t cdp_main;

/* Packet counters */
#define foreach_cdp_error                                       \
_ (NONE, "good cdp packets (processed)")	                \
_ (CACHE_HIT, "good cdp packets (cache hit)")			\
_ (BAD_TLV, "cdp packets with bad TLVs")                        \
_ (PROTOCOL_VERSION, "cdp packets with bad protocol versions")  \
_ (CHECKSUM, "cdp packets with bad checksums")                  \
_ (DISABLED, "cdp packets received on disabled interfaces")

typedef enum
{
#define _(sym,str) CDP_ERROR_##sym,
  foreach_cdp_error
#undef _
    CDP_N_ERROR,
} cdp_error_t;

/* cdp packet trace capture */
typedef struct
{
  u32 len;
  u8 data[400];
} cdp_input_trace_t;

typedef enum
{
  CDP_EVENT_SEND_NEIGHBOR,
  CDP_EVENT_SEND_KEEPALIVE,
} cdp_process_event_t;


cdp_error_t cdp_input (vlib_main_t * vm, vlib_buffer_t * b0, u32 bi0);
void cdp_periodic (vlib_main_t * vm);
void cdp_keepalive (cdp_main_t * cm, cdp_neighbor_t * n);
u16 cdp_checksum (void *p, int count);
u8 *cdp_input_format_trace (u8 * s, va_list * args);

serialize_function_t serialize_cdp_main, unserialize_cdp_main;

#endif /* __included_cdp_node_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
