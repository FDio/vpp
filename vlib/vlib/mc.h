/*
 * mc.h: vlib reliable sequenced multicast distributed applications
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#ifndef included_vlib_mc_h
#define included_vlib_mc_h

#include <vppinfra/elog.h>
#include <vppinfra/fifo.h>
#include <vppinfra/mhash.h>
#include <vlib/node.h>

#ifndef MC_EVENT_LOGGING
#define MC_EVENT_LOGGING 1
#endif

always_inline uword
mc_need_byte_swap (void)
{
  return CLIB_ARCH_IS_LITTLE_ENDIAN;
}

/*
 * Used to uniquely identify hosts.
 * For IP4 this would be ip4_address plus tcp/udp port.
 */
typedef union
{
  u8 as_u8[8];
  u64 as_u64;
} mc_peer_id_t;

always_inline mc_peer_id_t
mc_byte_swap_peer_id (mc_peer_id_t i)
{
  /* Peer id is already in network byte order. */
  return i;
}

always_inline int
mc_peer_id_compare (mc_peer_id_t a, mc_peer_id_t b)
{
  return memcmp (a.as_u8, b.as_u8, sizeof (a.as_u8));
}

/* Assert mastership.  Lowest peer_id amount all peers wins mastership.
   Only sent/received over mastership channel (MC_TRANSPORT_MASTERSHIP).
   So, we don't need a message opcode. */
typedef CLIB_PACKED (struct
		     {
		     /* Peer id asserting mastership. */
		     mc_peer_id_t peer_id;
		     /* Global sequence number asserted. */
		     u32 global_sequence;}) mc_msg_master_assert_t;

always_inline void
mc_byte_swap_msg_master_assert (mc_msg_master_assert_t * r)
{
  if (mc_need_byte_swap ())
    {
      r->peer_id = mc_byte_swap_peer_id (r->peer_id);
      r->global_sequence = clib_byte_swap_u32 (r->global_sequence);
    }
}

#define foreach_mc_msg_type			\
  _ (master_assert)				\
  _ (join_or_leave_request)			\
  _ (join_reply)				\
  _ (user_request)				\
  _ (user_ack)					\
  _ (catchup_request)				\
  _ (catchup_reply)

typedef enum
{
#define _(f) MC_MSG_TYPE_##f,
  foreach_mc_msg_type
#undef _
} mc_relay_msg_type_t;

/* Request to join a given stream.  Multicast over MC_TRANSPORT_JOIN. */
typedef CLIB_PACKED (struct
		     {
mc_peer_id_t peer_id; mc_relay_msg_type_t type:32;
		     /* MC_MSG_TYPE_join_or_leave_request */
		     /* Stream to join or leave. */
		     u32 stream_index;
		     /* join = 1, leave = 0 */
		     u8 is_join;}) mc_msg_join_or_leave_request_t;

always_inline void
mc_byte_swap_msg_join_or_leave_request (mc_msg_join_or_leave_request_t * r)
{
  if (mc_need_byte_swap ())
    {
      r->peer_id = mc_byte_swap_peer_id (r->peer_id);
      r->type = clib_byte_swap_u32 (r->type);
      r->stream_index = clib_byte_swap_u32 (r->stream_index);
    }
}

/* Join reply.  Multicast over MC_TRANSPORT_JOIN. */
typedef CLIB_PACKED (struct
		     {
mc_peer_id_t peer_id; mc_relay_msg_type_t type:32;
		     /* MC_MSG_TYPE_join_reply */
		     u32 stream_index;
		     /* Peer ID to contact to catchup with this stream. */
		     mc_peer_id_t catchup_peer_id;}) mc_msg_join_reply_t;

always_inline void
mc_byte_swap_msg_join_reply (mc_msg_join_reply_t * r)
{
  if (mc_need_byte_swap ())
    {
      r->peer_id = mc_byte_swap_peer_id (r->peer_id);
      r->type = clib_byte_swap_u32 (r->type);
      r->stream_index = clib_byte_swap_u32 (r->stream_index);
      r->catchup_peer_id = mc_byte_swap_peer_id (r->catchup_peer_id);
    }
}

/* Generic (application) request.  Multicast over MC_TRANSPORT_USER_REQUEST_TO_RELAY and then
   relayed by relay master after filling in global sequence number. */
typedef CLIB_PACKED (struct
		     {
		     mc_peer_id_t peer_id; u32 stream_index;
		     /* Global sequence number as filled in by relay master. */
		     u32 global_sequence;
		     /* Local sequence number as filled in by peer sending message. */
		     u32 local_sequence;
		     /* Size of request data. */
		     u32 n_data_bytes;
		     /* Opaque request data. */
		     u8 data[0];}) mc_msg_user_request_t;

always_inline void
mc_byte_swap_msg_user_request (mc_msg_user_request_t * r)
{
  if (mc_need_byte_swap ())
    {
      r->peer_id = mc_byte_swap_peer_id (r->peer_id);
      r->stream_index = clib_byte_swap_u32 (r->stream_index);
      r->global_sequence = clib_byte_swap_u32 (r->global_sequence);
      r->local_sequence = clib_byte_swap_u32 (r->local_sequence);
      r->n_data_bytes = clib_byte_swap_u32 (r->n_data_bytes);
    }
}

/* Sent unicast over ACK channel. */
typedef CLIB_PACKED (struct
		     {
		     mc_peer_id_t peer_id;
		     u32 global_sequence; u32 stream_index;
		     u32 local_sequence;
		     i32 seq_cmp_result;}) mc_msg_user_ack_t;

always_inline void
mc_byte_swap_msg_user_ack (mc_msg_user_ack_t * r)
{
  if (mc_need_byte_swap ())
    {
      r->peer_id = mc_byte_swap_peer_id (r->peer_id);
      r->stream_index = clib_byte_swap_u32 (r->stream_index);
      r->global_sequence = clib_byte_swap_u32 (r->global_sequence);
      r->local_sequence = clib_byte_swap_u32 (r->local_sequence);
      r->seq_cmp_result = clib_byte_swap_i32 (r->seq_cmp_result);
    }
}

/* Sent/received unicast over catchup channel (e.g. using TCP). */
typedef CLIB_PACKED (struct
		     {
		     mc_peer_id_t peer_id;
		     u32 stream_index;}) mc_msg_catchup_request_t;

always_inline void
mc_byte_swap_msg_catchup_request (mc_msg_catchup_request_t * r)
{
  if (mc_need_byte_swap ())
    {
      r->peer_id = mc_byte_swap_peer_id (r->peer_id);
      r->stream_index = clib_byte_swap_u32 (r->stream_index);
    }
}

/* Sent/received unicast over catchup channel. */
typedef CLIB_PACKED (struct
		     {
		     mc_peer_id_t peer_id; u32 stream_index;
		     /* Last global sequence number included in catchup data. */
		     u32 last_global_sequence_included;
		     /* Size of catchup data. */
		     u32 n_data_bytes;
		     /* Catchup data. */
		     u8 data[0];}) mc_msg_catchup_reply_t;

always_inline void
mc_byte_swap_msg_catchup_reply (mc_msg_catchup_reply_t * r)
{
  if (mc_need_byte_swap ())
    {
      r->peer_id = mc_byte_swap_peer_id (r->peer_id);
      r->stream_index = clib_byte_swap_u32 (r->stream_index);
      r->last_global_sequence_included =
	clib_byte_swap_u32 (r->last_global_sequence_included);
      r->n_data_bytes = clib_byte_swap_u32 (r->n_data_bytes);
    }
}

typedef struct _mc_serialize_msg
{
  /* Name for this type. */
  char *name;

  /* Functions to serialize/unserialize data. */
  serialize_function_t *serialize;
  serialize_function_t *unserialize;

  /* Maximum message size in bytes when serialized.
     If zero then this will be set to the largest sent message. */
  u32 max_n_bytes_serialized;

  /* Opaque to use for first argument to serialize/unserialize function. */
  u32 opaque;

  /* Index in global message vector. */
  u32 global_index;

  /* Registration list */
  struct _mc_serialize_msg *next_registration;
} mc_serialize_msg_t;

typedef struct
{
  /* Index into global message vector. */
  u32 global_index;
} mc_serialize_stream_msg_t;

#define MC_SERIALIZE_MSG(x,...)                                 \
    __VA_ARGS__ mc_serialize_msg_t x;                           \
static void __mc_serialize_msg_registration_##x (void)          \
    __attribute__((__constructor__)) ;                          \
static void __mc_serialize_msg_registration_##x (void)          \
{                                                               \
    vlib_main_t * vm = vlib_get_main();                         \
    x.next_registration = vm->mc_msg_registrations;             \
    vm->mc_msg_registrations = &x;                              \
}                                                               \
__VA_ARGS__ mc_serialize_msg_t x

typedef enum
{
  MC_TRANSPORT_MASTERSHIP,
  MC_TRANSPORT_JOIN,
  MC_TRANSPORT_USER_REQUEST_TO_RELAY,
  MC_TRANSPORT_USER_REQUEST_FROM_RELAY,
  MC_N_TRANSPORT_TYPE,
} mc_transport_type_t;

typedef struct
{
  clib_error_t *(*tx_buffer) (void *opaque, mc_transport_type_t type,
			      u32 buffer_index);

  clib_error_t *(*tx_ack) (void *opaque, mc_peer_id_t peer_id,
			   u32 buffer_index);

  /* Returns catchup opaque. */
    uword (*catchup_request_fun) (void *opaque, u32 stream_index,
				  mc_peer_id_t catchup_peer_id);

  void (*catchup_send_fun) (void *opaque, uword catchup_opaque,
			    u8 * data_vector);

  /* Opaque passed to callbacks. */
  void *opaque;

  mc_peer_id_t our_ack_peer_id;
  mc_peer_id_t our_catchup_peer_id;

  /* Max packet size (MTU) for this transport.
     For IP this is interface MTU less IP + UDP header size. */
  u32 max_packet_size;

  format_function_t *format_peer_id;
} mc_transport_t;

typedef struct
{
  /* Count of messages received from this peer from the past/future
     (with seq_cmp != 0). */
  u64 n_msgs_from_past;
  u64 n_msgs_from_future;
} mc_stream_peer_stats_t;

typedef struct
{
  /* ID of this peer. */
  mc_peer_id_t id;

  /* The last sequence we received from this peer. */
  u32 last_sequence_received;

  mc_stream_peer_stats_t stats, stats_last_clear;
} mc_stream_peer_t;

typedef struct
{
  u32 buffer_index;

  /* Cached copy of local sequence number from buffer. */
  u32 local_sequence;

  /* Number of times this buffer has been sent (retried). */
  u32 n_retries;

  /* Previous/next retries in doubly-linked list. */
  u32 prev_index, next_index;

  /* Bitmap of all peers which have acked this msg */
  uword *unacked_by_peer_bitmap;

  /* Message send or resend time */
  f64 sent_at;
} mc_retry_t;

typedef struct
{
  /* Number of retries sent for this stream. */
  u64 n_retries;
} mc_stream_stats_t;

struct mc_main_t;
struct mc_stream_t;

typedef struct
{
  /* Stream name. */
  char *name;

  /* Number of outstanding messages. */
  u32 window_size;

  /* Retry interval, in seconds */
  f64 retry_interval;

  /* Retry limit */
  u32 retry_limit;

  /* User rx buffer callback */
  void (*rx_buffer) (struct mc_main_t * mc_main,
		     struct mc_stream_t * stream,
		     mc_peer_id_t peer_id, u32 buffer_index);

  /* User callback to create a snapshot */
  u8 *(*catchup_snapshot) (struct mc_main_t * mc_main,
			   u8 * snapshot_vector,
			   u32 last_global_sequence_included);

  /* User callback to replay a snapshot */
  void (*catchup) (struct mc_main_t * mc_main,
		   u8 * snapshot_data, u32 n_snapshot_data_bytes);

  /* Callback to save a snapshot for offline replay */
  void (*save_snapshot) (struct mc_main_t * mc_main,
			 u32 is_catchup,
			 u8 * snapshot_data, u32 n_snapshot_data_bytes);

  /* Called when a peer dies */
  void (*peer_died) (struct mc_main_t * mc_main,
		     struct mc_stream_t * stream, mc_peer_id_t peer_id);
} mc_stream_config_t;

#define foreach_mc_stream_state			\
  _ (invalid)					\
  _ (name_known)				\
  _ (join_in_progress)				\
  _ (catchup)					\
  _ (ready)

typedef enum
{
#define _(f) MC_STREAM_STATE_##f,
  foreach_mc_stream_state
#undef _
} mc_stream_state_t;

typedef struct mc_stream_t
{
  mc_stream_config_t config;

  mc_stream_state_t state;

  /* Index in stream pool. */
  u32 index;

  /* Stream index 0 is always for MC internal use. */
#define MC_STREAM_INDEX_INTERNAL 0

  mc_retry_t *retry_pool;

  /* Head and tail index of retry pool. */
  u32 retry_head_index, retry_tail_index;

  /*
   * Country club for recently retired messages
   * If the set of peers is expanding and a new peer
   * misses a message, we can easily retire the FIFO
   * element before we even know about the new peer
   */
  mc_retry_t *retired_fifo;

  /* Hash mapping local sequence to retry pool index. */
  uword *retry_index_by_local_sequence;

  /* catch-up fifo of VLIB buffer indices.
     start recording when catching up. */
  u32 *catchup_fifo;

  mc_stream_stats_t stats, stats_last_clear;

  /* Peer pool. */
  mc_stream_peer_t *peers;

  /* Bitmap with ones for all peers in peer pool. */
  uword *all_peer_bitmap;

  /* Map of 64 bit id to index in stream pool. */
  mhash_t peer_index_by_id;

  /* Timeout, in case we're alone in the world */
  f64 join_timeout;

  vlib_one_time_waiting_process_t *procs_waiting_for_join_done;

  vlib_one_time_waiting_process_t *procs_waiting_for_open_window;

  /* Next sequence number to use */
  u32 our_local_sequence;

  /*
   * Last global sequence we processed.
   * When supplying catchup data, we need to tell
   * the client precisely where to start replaying
   */
  u32 last_global_sequence_processed;

  /* Vector of unique messages we've sent on this stream. */
  mc_serialize_stream_msg_t *stream_msgs;

  /* Vector global message index into per stream message index. */
  u32 *stream_msg_index_by_global_index;

  /* Hashed by message name. */
  uword *stream_msg_index_by_name;

  u64 user_requests_sent;
  u64 user_requests_received;
} mc_stream_t;

always_inline void
mc_stream_free (mc_stream_t * s)
{
  pool_free (s->retry_pool);
  hash_free (s->retry_index_by_local_sequence);
  clib_fifo_free (s->catchup_fifo);
  pool_free (s->peers);
  mhash_free (&s->peer_index_by_id);
  vec_free (s->procs_waiting_for_join_done);
  vec_free (s->procs_waiting_for_open_window);
}

always_inline void
mc_stream_init (mc_stream_t * s)
{
  memset (s, 0, sizeof (s[0]));
  s->retry_head_index = s->retry_tail_index = ~0;
}

typedef struct
{
  u32 stream_index;
  u32 catchup_opaque;
  u8 *catchup_snapshot;
} mc_catchup_process_arg_t;

typedef enum
{
  MC_RELAY_STATE_NEGOTIATE,
  MC_RELAY_STATE_MASTER,
  MC_RELAY_STATE_SLAVE,
} mc_relay_state_t;

typedef struct
{
  mc_peer_id_t peer_id;

  f64 time_last_master_assert_received;
} mc_mastership_peer_t;

typedef struct
{
  u32 stream_index;
  u32 buffer_index;
} mc_stream_and_buffer_t;

typedef struct mc_main_t
{
  mc_relay_state_t relay_state;

  /* Mastership */
  u32 we_can_be_relay_master;

  u64 relay_master_peer_id;

  mc_mastership_peer_t *mastership_peers;

  /* Map of 64 bit id to index in stream pool. */
  mhash_t mastership_peer_index_by_id;

  /* The transport we're using. */
  mc_transport_t transport;

  /* Last-used global sequence number. */
  u32 relay_global_sequence;

  /* Vector of streams. */
  mc_stream_t *stream_vector;

  /* Hash table mapping stream name to pool index. */
  uword *stream_index_by_name;

  uword *procs_waiting_for_stream_name_by_name;

  vlib_one_time_waiting_process_t **procs_waiting_for_stream_name_pool;

  int joins_in_progress;

  mc_catchup_process_arg_t *catchup_process_args;

  /* Node indices for mastership, join ager,
     retry and catchup processes. */
  u32 mastership_process;
  u32 join_ager_process;
  u32 retry_process;
  u32 catchup_process;
  u32 unserialize_process;

  /* Global vector of messages. */
  mc_serialize_msg_t **global_msgs;

  /* Hash table mapping message name to index. */
  uword *global_msg_index_by_name;

  /* Shared serialize/unserialize main. */
  serialize_main_t serialize_mains[VLIB_N_RX_TX];

  vlib_serialize_buffer_main_t serialize_buffer_mains[VLIB_N_RX_TX];

  /* Convenience variables */
  struct vlib_main_t *vlib_main;
  elog_main_t *elog_main;

  /* Maps 64 bit peer id to elog string table offset for this formatted peer id. */
  mhash_t elog_id_by_peer_id;

  uword *elog_id_by_msg_name;

  /* For mc_unserialize. */
  mc_stream_and_buffer_t *mc_unserialize_stream_and_buffers;
} mc_main_t;

always_inline mc_stream_t *
mc_stream_by_name (mc_main_t * m, char *name)
{
  uword *p = hash_get (m->stream_index_by_name, name);
  return p ? vec_elt_at_index (m->stream_vector, p[0]) : 0;
}

always_inline mc_stream_t *
mc_stream_by_index (mc_main_t * m, u32 i)
{
  return i < vec_len (m->stream_vector) ? m->stream_vector + i : 0;
}

always_inline void
mc_clear_stream_stats (mc_main_t * m)
{
  mc_stream_t *s;
  mc_stream_peer_t *p;
  vec_foreach (s, m->stream_vector)
  {
    s->stats_last_clear = s->stats;
      /* *INDENT-OFF* */
      pool_foreach (p, s->peers, ({
	p->stats_last_clear = p->stats;
      }));
      /* *INDENT-ON* */
  }
}

/* Declare all message handlers. */
#define _(f) void mc_msg_##f##_handler (mc_main_t * mcm, mc_msg_##f##_t * msg, u32 buffer_index);
foreach_mc_msg_type
#undef _
  u32 mc_stream_join (mc_main_t * mcm, mc_stream_config_t *);

void mc_stream_leave (mc_main_t * mcm, u32 stream_index);

void mc_wait_for_stream_ready (mc_main_t * m, char *stream_name);

u32 mc_stream_send (mc_main_t * mcm, u32 stream_index, u32 buffer_index);

void mc_main_init (mc_main_t * mcm, char *tag);

void mc_enable_disable_mastership (mc_main_t * mcm, int we_can_be_master);

void *mc_get_vlib_buffer (struct vlib_main_t *vm, u32 n_bytes,
			  u32 * bi_return);

format_function_t format_mc_main;

clib_error_t *mc_serialize_internal (mc_main_t * mc,
				     u32 stream_index,
				     u32 multiple_messages_per_vlib_buffer,
				     mc_serialize_msg_t * msg, ...);

clib_error_t *mc_serialize_va (mc_main_t * mc,
			       u32 stream_index,
			       u32 multiple_messages_per_vlib_buffer,
			       mc_serialize_msg_t * msg, va_list * va);

#define mc_serialize_stream(mc,si,msg,args...)			\
  mc_serialize_internal((mc),(si),(0),(msg),(msg)->serialize,args)

#define mc_serialize(mc,msg,args...)				\
  mc_serialize_internal((mc),(~0),(0),(msg),(msg)->serialize,args)

#define mc_serialize2(mc,add,msg,args...)				\
  mc_serialize_internal((mc),(~0),(add),(msg),(msg)->serialize,args)

void mc_unserialize (mc_main_t * mcm, mc_stream_t * s, u32 buffer_index);
uword mc_unserialize_message (mc_main_t * mcm, mc_stream_t * s,
			      serialize_main_t * m);

serialize_function_t serialize_mc_main, unserialize_mc_main;

always_inline uword
mc_max_message_size_in_bytes (mc_main_t * mcm)
{
  return mcm->transport.max_packet_size - sizeof (mc_msg_user_request_t);
}

always_inline word
mc_serialize_n_bytes_left (mc_main_t * mcm, serialize_main_t * m)
{
  return mc_max_message_size_in_bytes (mcm) -
    serialize_vlib_buffer_n_bytes (m);
}

void unserialize_mc_stream (serialize_main_t * m, va_list * va);
void mc_stream_join_process_hold (void);

#endif /* included_vlib_mc_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
