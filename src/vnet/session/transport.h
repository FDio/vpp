/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_TRANSPORT_H_
#define SRC_VNET_SESSION_TRANSPORT_H_

#include <vnet/vnet.h>
#include <vnet/session/transport_types.h>

/*
 * Transport protocol virtual function table
 */
/* *INDENT-OFF* */
typedef struct _transport_proto_vft
{
  /*
   * Setup
   */
  u32 (*start_listen) (u32 session_index, transport_endpoint_t * lcl);
  u32 (*stop_listen) (u32 conn_index);
  int (*connect) (transport_endpoint_cfg_t * rmt);
  void (*close) (u32 conn_index, u32 thread_index);
  void (*cleanup) (u32 conn_index, u32 thread_index);
  clib_error_t *(*enable) (vlib_main_t * vm, u8 is_en);

  /*
   * Transmission
   */

  u32 (*push_header) (transport_connection_t * tconn, vlib_buffer_t * b);
  u16 (*send_mss) (transport_connection_t * tc);
  u32 (*send_space) (transport_connection_t * tc);
  u32 (*tx_fifo_offset) (transport_connection_t * tc);
  void (*update_time) (f64 time_now, u8 thread_index);
  void (*flush_data) (transport_connection_t *tconn);
  int (*custom_tx) (void *session);
  int (*app_rx_evt) (transport_connection_t *tconn);

  /*
   * Connection retrieval
   */
  transport_connection_t *(*get_connection) (u32 conn_idx, u32 thread_idx);
  transport_connection_t *(*get_listener) (u32 conn_index);
  transport_connection_t *(*get_half_open) (u32 conn_index);

  /*
   * Format
   */
  u8 *(*format_connection) (u8 * s, va_list * args);
  u8 *(*format_listener) (u8 * s, va_list * args);
  u8 *(*format_half_open) (u8 * s, va_list * args);

  /*
   *  Properties retrieval
   */
  void (*get_transport_endpoint) (u32 conn_index, u32 thread_index,
				  transport_endpoint_t *tep, u8 is_lcl);
  void (*get_transport_listener_endpoint) (u32 conn_index,
					   transport_endpoint_t *tep,
					   u8 is_lcl);

  /*
   * Properties
   */
  transport_tx_fn_type_t tx_type;
  transport_service_type_t service_type;
} transport_proto_vft_t;
/* *INDENT-ON* */

extern transport_proto_vft_t *tp_vfts;

#define transport_proto_foreach(VAR, BODY)			\
do {								\
    for (VAR = 0; VAR < vec_len (tp_vfts); VAR++)		\
      if (tp_vfts[VAR].push_header != 0)			\
	do { BODY; } while (0);					\
} while (0)

int transport_connect (transport_proto_t tp, transport_endpoint_cfg_t * tep);
void transport_close (transport_proto_t tp, u32 conn_index, u8 thread_index);
u32 transport_start_listen (transport_proto_t tp, u32 session_index,
			    transport_endpoint_t * tep);
u32 transport_stop_listen (transport_proto_t tp, u32 conn_index);
void transport_cleanup (transport_proto_t tp, u32 conn_index,
			u8 thread_index);
void transport_get_endpoint (transport_proto_t tp, u32 conn_index,
			     u32 thread_index, transport_endpoint_t * tep,
			     u8 is_lcl);
void transport_get_listener_endpoint (transport_proto_t tp, u32 conn_index,
				      transport_endpoint_t * tep, u8 is_lcl);

static inline transport_connection_t *
transport_get_connection (transport_proto_t tp, u32 conn_index,
			  u8 thread_index)
{
  return tp_vfts[tp].get_connection (conn_index, thread_index);
}

static inline transport_connection_t *
transport_get_listener (transport_proto_t tp, u32 conn_index)
{
  return tp_vfts[tp].get_listener (conn_index);
}

static inline transport_connection_t *
transport_get_half_open (transport_proto_t tp, u32 conn_index)
{
  return tp_vfts[tp].get_half_open (conn_index);
}

static inline int
transport_custom_tx (transport_proto_t tp, void *s)
{
  return tp_vfts[tp].custom_tx (s);
}

static inline int
transport_app_rx_evt (transport_proto_t tp, u32 conn_index, u32 thread_index)
{
  transport_connection_t *tc;
  if (!tp_vfts[tp].app_rx_evt)
    return 0;
  tc = transport_get_connection (tp, conn_index, thread_index);
  return tp_vfts[tp].app_rx_evt (tc);
}

void transport_register_protocol (transport_proto_t transport_proto,
				  const transport_proto_vft_t * vft,
				  fib_protocol_t fib_proto, u32 output_node);
transport_proto_vft_t *transport_protocol_get_vft (transport_proto_t tp);
void transport_update_time (f64 time_now, u8 thread_index);

int transport_alloc_local_port (u8 proto, ip46_address_t * ip);
int transport_alloc_local_endpoint (u8 proto, transport_endpoint_cfg_t * rmt,
				    ip46_address_t * lcl_addr,
				    u16 * lcl_port);
void transport_endpoint_cleanup (u8 proto, ip46_address_t * lcl_ip, u16 port);
void transport_enable_disable (vlib_main_t * vm, u8 is_en);
void transport_init (void);

always_inline u32
transport_elog_track_index (transport_connection_t * tc)
{
#if TRANSPORT_DEBUG
  return tc->elog_track.track_index_plus_one - 1;
#else
  return ~0;
#endif
}

void transport_connection_tx_pacer_reset (transport_connection_t * tc,
					  u32 rate_bytes_per_sec,
					  u32 initial_bucket, u64 time_now);
/**
 * Initialize tx pacer for connection
 *
 * @param tc				transport connection
 * @param rate_bytes_per_second		initial byte rate
 * @param burst_bytes			initial burst size in bytes
 */
void transport_connection_tx_pacer_init (transport_connection_t * tc,
					 u32 rate_bytes_per_sec,
					 u32 initial_bucket);

/**
 * Update tx pacer pacing rate
 *
 * @param tc			transport connection
 * @param bytes_per_sec		new pacing rate
 */
void transport_connection_tx_pacer_update (transport_connection_t * tc,
					   u64 bytes_per_sec);

/**
 * Get maximum tx burst allowed for transport connection
 *
 * @param tc		transport connection
 * @param time_now	current cpu time as returned by @ref clib_cpu_time_now
 * @param mss		transport's mss
 */
u32 transport_connection_snd_space (transport_connection_t * tc,
				    u64 time_now, u16 mss);

u32 transport_connection_tx_pacer_burst (transport_connection_t * tc,
					 u64 time_now);

/**
 * Initialize period for tx pacers
 *
 * Defines a unit of time with respect to number of cpu cycles that is to
 * be used by all tx pacers.
 */
void transport_init_tx_pacers_period (void);

/**
 * Check if transport connection is paced
 */
always_inline u8
transport_connection_is_tx_paced (transport_connection_t * tc)
{
  return (tc->flags & TRANSPORT_CONNECTION_F_IS_TX_PACED);
}

u8 *format_transport_pacer (u8 * s, va_list * args);

/**
 * Update tx byte stats for transport connection
 *
 * If tx pacing is enabled, this also updates pacer bucket to account for the
 * amount of bytes that have been sent.
 *
 * @param tc		transport connection
 * @param pkts		packets recently sent
 * @param bytes		bytes recently sent
 */
void transport_connection_update_tx_stats (transport_connection_t * tc,
					   u32 bytes);

void
transport_connection_tx_pacer_update_bytes (transport_connection_t * tc,
					    u32 bytes);

#endif /* SRC_VNET_SESSION_TRANSPORT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
