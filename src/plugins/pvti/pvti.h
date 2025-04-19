/*
 * pvti.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) 2024 Cisco and/or its affiliates.
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
#ifndef __included_pvti_h__
#define __included_pvti_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#define VPP_MAX_THREADS (1 << 8)

#define MAX_RX_STREAMS 256

#define PVTI_ALIGN_BYTES 9

typedef CLIB_PACKED (struct {
  u32 seq;
  u8 stream_index; // set to the cpu# on the sending side
  u8 chunk_count;
  u8 reass_chunk_count; // number of chunks in the front that are related to
			// previously started buffer
  // mandatory_flags_mask highlights which of the flags cause packet drop if
  // not understood, and which of them can be just ignored.
  u8 mandatory_flags_mask;
  u8 flags_value;
  u8 pad_bytes;
  u8 pad[0];
}) pvti_packet_header_t;

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  udp_header_t udp;
  // not part of encap header pvti_packet_header_t pv;
}) pvti_ip4_encap_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  udp_header_t udp;
  // not part of encap header pvti_packet_header_t pv;
}) pvti_ip6_encap_header_t;

typedef CLIB_PACKED (struct {
  u16 total_chunk_length;
  // More fragments: this chunk is not the last block fragment
#define CHUNK_FLAGS_MF (1 << 0)
  // More blocks: this block has chained blocks that follow
#define CHUNK_FLAGS_MB (1 << 1)
  u16 _pad0;
  u32 _pad1;
  u8 chunk_data[0];
}) pvti_chunk_header_t;

typedef struct
{
  // a buffer being built from the smaller packets
  u32 bi0;

  // how big can this buffer grow
  u32 bi0_max_current_length;

  // how many chunks are already in the buffer
  u8 chunk_count;
  // leading reassembly chunk count
  u8 reass_chunk_count;

  u32 current_tx_seq;
} pvti_per_tx_stream_data_t;

typedef struct
{
  /* The seq# that we last processed */
  u32 last_rx_seq;

  // a current buffer that is being reassembled
  u32 rx_bi0;
  // The root buffer, most of the times == rx_bi0 except in the case of chained
  // buffers.
  u32 rx_bi0_first;

  // Next index for dispatch when the reassembly is done
  u16 rx_next0;
  // expected totall inner length for the packet
  u16 rx_expected_inner_length;
  u16 rx_received_inner_length;

} pvti_per_rx_stream_data_t;

typedef struct
{
  ip_address_t local_ip;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u16 underlay_mtu;
  u32 underlay_fib_index;

  u32 pvti_if_index;
  bool deleted;
  bool is_bo0_traced;

  u32 bo0_max_current_length;

  u8 chunk_count;
  u8 reass_chunk_count;
  u32 current_tx_seq;
  vlib_buffer_t *bo0;

} pvti_tx_peer_t;

typedef struct
{
  ip_address_t local_ip;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;

  pvti_per_rx_stream_data_t rx_streams[MAX_RX_STREAMS];

  u32 pvti_if_index;
  bool deleted;
} pvti_rx_peer_t;

typedef struct
{
  /* pool of destination-based structures which are used to build the packets
   */
  pvti_tx_peer_t *tx_peers;

  /* vector of buffers to send */
  u32 *pending_tx_buffers;
  u16 *pending_tx_nexts;
  /* pool of source-based structures for the remote peers' data tracking
   */
  pvti_rx_peer_t *rx_peers;

  /* vector of buffers being decapsulated */
  u32 *pending_rx_buffers;
  u16 *pending_rx_nexts;

} pvti_per_thread_data_t;

typedef struct
{
  ip_address_t local_ip;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u16 underlay_mtu;
  u32 underlay_fib_index;
  bool peer_address_from_payload;
  u64 created_at;

  u32 sw_if_index;
  u32 hw_if_index;

  // per-stream data for TX
  pvti_per_tx_stream_data_t tx_streams[256];
  pvti_per_rx_stream_data_t rx_streams[256];

} pvti_if_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* have we initialized the data structures ? */
  bool is_initialized;

  /* interface pool */
  pvti_if_t *if_pool;

  /* if_index in the pool above by sw_if_index */
  index_t *if_index_by_sw_if_index;

  /* indices by port */
  index_t **if_indices_by_port;

  /* per-thread data, ip4[0] and ip6[1] */
  pvti_per_thread_data_t *per_thread_data[2];

  /* on/off switch for the periodic function */
  u8 periodic_timer_enabled;
  /* Node index, non-zero if the periodic process has been created */
  u32 periodic_node_index;

  /* graph node state */
  uword *bm_ip4_bypass_enabled_by_sw_if;
  uword *bm_ip6_bypass_enabled_by_sw_if;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} pvti_main_t;

extern pvti_main_t pvti_main;

extern vlib_node_registration_t pvti_node;
extern vlib_node_registration_t pvti4_input_node;
extern vlib_node_registration_t pvti4_output_node;
extern vlib_node_registration_t pvti6_input_node;
extern vlib_node_registration_t pvti6_output_node;
extern vlib_node_registration_t pvti_periodic_node;

always_inline u8
pvti_get_stream_index (int is_ip6)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();

  ASSERT ((thread_index & 0xffffff80) == 0);

  u8 stream_index = (thread_index & 0x7f) | (is_ip6 ? 0x80 : 0);
  return stream_index;
}

/* attempt to get a new buffer */
always_inline u32
pvti_get_new_buffer (vlib_main_t *vm)
{
  u32 bi0 = INDEX_INVALID;
  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      return INDEX_INVALID;
    }
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  b0->current_data = 0;
  b0->current_length = 0;
  return bi0;
}

/* Periodic function events */
#define PVTI_EVENT1			   1
#define PVTI_EVENT2			   2
#define PVTI_EVENT_PERIODIC_ENABLE_DISABLE 3

void pvti_create_periodic_process (pvti_main_t *);
void pvti_verify_initialized (pvti_main_t *pvm);

#endif /* __included_pvti_h__ */
