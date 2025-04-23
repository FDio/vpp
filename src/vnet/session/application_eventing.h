/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_SESSION_APP_EVENTING_H_
#define SRC_VNET_SESSION_APP_EVENTING_H_

#include <vnet/session/session_types.h>
#include <vnet/session/application.h>
#include <vnet/tcp/tcp_types.h>

typedef enum app_evt_msg_type_
{
  APP_EVT_MSG_CTRL,
  APP_EVT_MSG_DATA
} __clib_packed app_evt_msg_type_t;

typedef enum app_evt_msg_ctrl_type_
{
  APP_EVT_MSG_CTRL_INIT,
  APP_EVT_MSG_CTRL_REPLY_INIT,
} __clib_packed app_evt_msg_ctrl_type_t;

typedef struct app_evt_msg_ctrl_
{
  app_evt_msg_ctrl_type_t ctrl_type;
  u32 msg_len;
  u8 data[0];
} __clib_packed app_evt_msg_ctrl_t;

typedef enum app_evt_msg_data_msg_type_
{
  APP_EVT_MSG_DATA_SESSION_STATS,
} __clib_packed app_evt_msg_data_msg_type_t;

typedef struct app_evt_msg_data_
{
  app_evt_msg_data_msg_type_t data_type;
  u32 msg_len;
  u8 data[0];
} __clib_packed app_evt_msg_data_t;

typedef struct app_evt_msg_data_session_stats_
{
  u8 transport_proto_type; /**< vpp transport proto */
  u32 msg_len;
  u8 data[0];
} __clib_packed app_evt_msg_data_session_stats_t;

typedef struct app_evt_msg_
{
  app_evt_msg_type_t msg_type;
  u32 msg_len;
  u8 data[0];
} __clib_packed app_evt_msg_t;

#define foreach_tcp_transport_stat                                            \
  _ (u64, segs_in)                                                            \
  _ (u64, bytes_in)                                                           \
  _ (u64, segs_out)                                                           \
  _ (u64, bytes_out)                                                          \
  _ (u64, data_segs_in)                                                       \
  _ (u64, data_segs_out)                                                      \
  _ (u32, snd_mss)                                                            \
  _ (u32, dupacks_in)                                                         \
  _ (u32, dupacks_out)                                                        \
  _ (u32, fr_occurences)                                                      \
  _ (u32, tr_occurences)                                                      \
  _ (u64, bytes_retrans)                                                      \
  _ (u64, segs_retrans)                                                       \
  _ (u32, srtt)                                                               \
  _ (u32, rttvar)                                                             \
  _ (f64, mrtt_us)                                                            \
  _ (tcp_errors_t, errors)                                                    \
  _ (f64, start_ts)

typedef struct tcp_transport_stats_
{
  u8 conn_id[TRANSPORT_CONN_ID_LEN];
#define _(type, name) type name;
  foreach_tcp_transport_stat
#undef _
    f64 end_ts;
} __clib_packed tcp_session_stats_t;

#define foreach_udp_transport_stat                                            \
  _ (u64, bytes_in)                                                           \
  _ (u64, dgrams_in)                                                          \
  _ (u64, bytes_out)                                                          \
  _ (u64, dgrams_out)                                                         \
  _ (u32, errors_in)                                                          \
  _ (u16, mss)

typedef struct udp_transport_stats_
{
  u8 conn_id[TRANSPORT_CONN_ID_LEN];
#define _(type, name) type name;
  foreach_udp_transport_stat
#undef _
    f64 end_ts;
} __clib_packed udp_session_stats_t;

typedef struct app_evt_collector_cfg_
{
  session_endpoint_cfg_t sep; /**< collector endpoint */
  u8 is_server : 1;	      /**< collector is server */
} app_evt_collector_cfg_t;

typedef struct app_evt_buffer_chunk_
{
  u32 chunk_index; /**< index in pool  */
  u32 next_index;  /**< next in linked list */
  u32 len;	   /**< evt data length */
  u8 data[512];	   /**< evt data */
} __clib_packed app_evt_buffer_chunk_t;

static inline void
app_evt_buf_chunk_append (app_evt_buffer_chunk_t *chunk, const void *data,
			  u32 len)
{
  clib_memcpy (chunk->data + chunk->len, data, len);
  chunk->len += len;
  ASSERT (chunk->len <= sizeof (chunk->data));
}

static inline void *
app_evt_buf_chunk_append_uninit (app_evt_buffer_chunk_t *chunk, u32 len)
{
  u8 *start = chunk->data + chunk->len;
  chunk->len += len;
  ASSERT (chunk->len <= sizeof (chunk->data));
  return start;
}

typedef struct app_evt_buffer_
{
  app_evt_buffer_chunk_t *chunks; /**< pool of chunks */
  u32 head_chunk;		  /**< head of linked list */
  u32 tail_chunk;		  /**< tail of linked list  */
  u32 len;			  /**< evt data length */
} app_evt_buffer_t;

static inline app_evt_buffer_chunk_t *
app_evt_buffer_alloc_chunk (app_evt_buffer_t *buf)
{
  app_evt_buffer_chunk_t *chunk;

  pool_get_zero (buf->chunks, chunk);
  chunk->chunk_index = chunk - buf->chunks;
  chunk->next_index = ~0;

  return chunk;
}

static inline app_evt_buffer_chunk_t *
app_evt_buffer_get_chunk (app_evt_buffer_t *buf, u32 chunk_index)
{
  if (pool_is_free_index (buf->chunks, chunk_index))
    return 0;
  return pool_elt_at_index (buf->chunks, chunk_index);
}

static inline void
app_evt_buffer_free_chunk (app_evt_buffer_t *buf,
			   app_evt_buffer_chunk_t *chunk)
{
  pool_put (buf->chunks, chunk);
}

void app_evt_buffer_append_chunk (app_evt_buffer_t *buf,
				  app_evt_buffer_chunk_t *chunk);

typedef struct app_evt_collector_wrk_
{
  session_handle_t session_handle; /**< per-worker session handle */
  app_evt_buffer_t buf;		   /**< per-worker evt buffer */
  svm_fifo_seg_t *segs;
} app_evt_collector_wrk_t;

typedef struct app_evt_collector_
{
  app_evt_collector_wrk_t *wrk; /**< per-thread context */
  u8 is_ready : 1;		/**< collector initialized */
  u32 collector_index;		/**< collector index */
  u32 session_map;		/**< map of connected sessions */
  u32 session_map_lock;		/**< lock for session map */
  app_evt_collector_cfg_t cfg;	/**< collector config */
} app_evt_collector_t;

typedef struct app_evt_main_
{
  app_evt_collector_t *collectors; /**< pool of collectors */
  u32 app_index;		   /**< evt collector app index */

  /*
   * application config
   */
  u32 segment_size; /**< segment size */
  u32 fifo_size;    /**< fifo size */
} app_evt_main_t;

int app_evt_collector_add (app_evt_collector_cfg_t *cfg);
app_evt_collector_t *app_evt_collector_get (u32 c_index);
void *app_evt_collector_get_cb_fn ();
void app_evt_collector_wrk_send (app_evt_collector_wrk_t *cwrk);

#endif /* SRC_VNET_SESSION_APP_EVENTING_H_ */