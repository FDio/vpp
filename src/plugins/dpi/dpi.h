/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel, Travelping and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef included_vnet_dpi_h
#define included_vnet_dpi_h

#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>

#include <hs/hs.h>
#include <hs/hs_common.h>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>
#include "dpi_app_match.h"

typedef u8 *regex_t;

typedef struct
{
  u8 *name;
  regex_t *expressions;
  u32 *flags;
  u32 *ids;
  hs_database_t *database;
  hs_scratch_t *scratch;
  u32 ref_cnt;
} dpi_entry_t;

typedef struct
{
  int res;
  u32 id;
} dpi_cb_args_t;

typedef struct
{
  union
  {
    struct
    {
      ip46_address_t src_ip;
      ip46_address_t dst_ip;
      u16 src_port;
      u16 dst_port;
      u8 protocol;
      u32 fib_index;
    };
    u64 key[6];
  };
} dpi_flow_key_t;

typedef clib_bihash_kv_24_8_t dpi4_flow_key_t;
typedef clib_bihash_kv_48_8_t dpi6_flow_key_t;

typedef struct
{
  /* SSL */
  u8 ssl_stage;
  u8 ssl_got_server_cert;
} dpi_flow_tcp_t;

typedef struct
{
  /* TBD */
} dpi_flow_udp_t;

typedef struct segment_
{
  u32 send_sn;
  u8 *data;
  u32 len;
  u32 bi;			/* vlib buffer index */
  struct segment_ *next;
} segment;

typedef struct tcp_stream_
{
  u32 send_sn;			/* expected segment sn */
  u32 ack_sn;			/* acked segment sn */
  segment *seg_queue;		/* store out-of-order segments */
} tcp_stream_t;

typedef struct dpi_flow_info
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u16 detected_protocol[2];
  u16 protocol_stack_info;
  u16 pkt_num;
  u16 pkt_direct_counter[2];

  hs_stream_t *stream;
  u8 detect_begin;
  u8 detect_done;
  u32 app_id;			/* L7 APP ID */

  u16 guessed_protocol_id;
  u16 guessed_host_protocol_id;

  u8 max_more_pkts_to_check;

  int (*more_pkts_func) (u8 * payload, u32 payload_len,
			 struct dpi_flow_info * flow);

  u16 dst_port;
  u8 l4_protocol;
  union
  {
    dpi_flow_tcp_t tcp;
    dpi_flow_udp_t udp;
  } l4;

  u8 ssl_cert_detected:4;
  u8 ssl_cert_num_checks:4;

  union
  {
    struct
    {
      char server_cert[64];
    } ssl;
    /* TBD: Add more protocols */
  } protos;
} dpi_flow_info_t;

typedef enum
{
  TCP_STATE_SYN = 1,
  TCP_STATE_SYN_ACK = 2,
  TCP_STATE_ACK = 3,
  TCP_STATE_ESTABLISH = 4,
  TCP_STATE_FIN1 = 5,
  TCP_STATE_CLOSE = 6,
} tcp_state_t;

/* tcp packet direction */
#define DIR_C2S 0
#define DIR_S2C 1

/* tcp reassembly side */
#define REASS_C2S 0
#define REASS_S2C 1
#define REASS_BOTH 2

/* Macros to handle sequence numbers */
#define SN_LT(a,b)  ((int)((a) - (b)) <  0)
#define SN_GT(a,b)  ((int)((a) - (b)) >  0)
#define SN_EQ(a,b)  ((int)((a) - (b)) == 0)

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 flow_index;		/* infra flow index */
  u32 next_index;

  u8 check_more_pkts:1;
  u8 pkt_dir:1;
  u8 forward_is_c2s:1;
  u8 consumed:1;
  u8 reass_en:1;
  u8 reass_dir:2;

  dpi_flow_key_t key;
  dpi_flow_info_t *info;

  /* TCP stream reassembly */
  tcp_state_t tcp_state;
  tcp_stream_t c2s;
  tcp_stream_t s2c;
  segment *first_seg;

} dpi_flow_entry_t;

typedef struct
{
  u32 flow_id;
  u8 reass_en;
  u8 reass_dir;
} tcp_reass_args_t;

typedef struct
{
  u8 is_add;
  u8 is_ipv6;
  ip46_address_t src_ip;
  ip46_address_t dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
  u32 fib_index;
} dpi_add_del_flow_args_t;

typedef struct
{
  u32 app_id;
  u32 db_id;
} dpi_adr_t;

typedef struct
{
  /* lookup tunnel by key */
  clib_bihash_24_8_t dpi4_flow_by_key;
  clib_bihash_48_8_t dpi6_flow_by_key;

  /* vector of dpi flow instances */
  dpi_flow_entry_t *dpi_flows;
  u32 flow_id_start;
  dpi_flow_info_t *dpi_infos;
  segment *seg_pool;

  /* Default hyperscan database */
  dpi_entry_t default_db;

  /* graph node state */
  uword *bm_ip4_bypass_enabled_by_sw_if;
  uword *bm_ip6_bypass_enabled_by_sw_if;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dpi_main_t;

extern dpi_main_t dpi_main;

#define foreach_copy_field              \
_(src_ip)                               \
_(dst_ip)                               \
_(src_port)                             \
_(dst_port)                             \
_(protocol)                             \
_(fib_index)


#define dpi_enqueue_tcp_segments(seg,vm,node,next_index,to_next,n_left_to_next,bi0,next0) \
while(seg)        \
  {               \
    bi0 = seg->bi;  \
    to_next[0] = bi0; \
    to_next++;        \
    n_left_to_next--; \
    next0 = flow0->next_index;         \
    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,  \
                     to_next, n_left_to_next,   \
                     bi0, next0);   \
    prev_seg = seg;  \
    seg=seg->next;   \
    pool_put(dm->seg_pool, prev_seg);  \
  }


#define get_u16_t(X,O)  (*(u16 *)(((u8 *)X) + O))
#define DPI_MAX_SSL_REQUEST_SIZE 10000

int dpi_flow_add_del (dpi_add_del_flow_args_t * a, u32 * flow_idp);
int dpi_reverse_flow_add_del (dpi_add_del_flow_args_t * a, u32 flow_id);
int dpi_add_del_rx_flow (u32 hw_if_index, u32 flow_id, int is_add,
			 u32 is_ipv6);
int dpi_tcp_reass (tcp_reass_args_t * a);
void dpi_flow_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);
int dpi_search_host_protocol (dpi_flow_info_t * flow,
			      char *str_to_match,
			      u32 str_to_match_len,
			      u16 master_protocol_id, u32 * host_protocol_id);
void dpi_search_tcp_ssl (u8 * payload, u32 payload_len,
			 dpi_flow_info_t * flow);

void dpi_detect_application (u8 * payload, u32 payload_len,
			     dpi_flow_info_t * flow);

typedef enum
{
  DPI_PROTOCOL_UNKNOWN = 0,
  DPI_PROTOCOL_SSL = 1,
  DPI_PROTOCOL_SSL_NO_CERT = 2,
  DPI_N_PROTOCOL
} dpi_protocol_id_t;

#define foreach_dpi_input_next        \
_(DROP, "error-drop")                 \
_(IP4_LOOKUP, "ip4-lookup")

typedef enum
{
#define _(s,n) DPI_INPUT_NEXT_##s,
  foreach_dpi_input_next
#undef _
    DPI_INPUT_N_NEXT,
} dpi_input_next_t;

#endif /* included_vnet_dpi_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
