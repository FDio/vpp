/*
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
#ifndef __included_uri_h__
#define __included_uri_h__

#include <svm/svm_fifo_segment.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/tls/tls.h>

typedef struct _vnet_app_attach_args_t
{
#define _(_type, _name) _type _name;
  foreach_app_init_args
#undef _
  ssvm_private_t * segment;
  svm_msg_q_t *app_evt_q;
  u64 segment_handle;
} vnet_app_attach_args_t;

typedef struct _vnet_app_detach_args_t
{
  u32 app_index;
  u32 api_client_index;
} vnet_app_detach_args_t;

typedef struct _vnet_bind_args_t
{
  union
  {
    session_endpoint_cfg_t sep_ext;
    session_endpoint_t sep;
    char *uri;
  };

  u32 app_index;
  u32 wrk_map_index;

  /*
   * Results
   */
  char *segment_name;
  u32 segment_name_length;
  u64 server_event_queue_address;
  u64 handle;
} vnet_bind_args_t;

typedef struct _vnet_unbind_args_t
{
  union
  {
    char *uri;
    u64 handle;			/**< Session handle */
  };
  u32 app_index;		/**< Owning application index */
  u32 wrk_map_index;		/**< App's local pool worker index */
} vnet_unbind_args_t;

typedef struct _vnet_connect_args
{
  union
  {
    session_endpoint_cfg_t sep_ext;
    session_endpoint_t sep;
    char *uri;
  };
  u32 app_index;
  u32 wrk_map_index;
  u32 api_context;

  session_handle_t session_handle;
} vnet_connect_args_t;

typedef struct _vnet_disconnect_args_t
{
  session_handle_t handle;
  u32 app_index;
} vnet_disconnect_args_t;

typedef struct _vnet_application_add_tls_cert_args_t
{
  u32 app_index;
  u8 *cert;
} vnet_app_add_tls_cert_args_t;

typedef struct _vnet_application_add_tls_key_args_t
{
  u32 app_index;
  u8 *key;
} vnet_app_add_tls_key_args_t;

/* Application attach options */
typedef enum
{
  APP_OPTIONS_FLAGS,
  APP_OPTIONS_EVT_QUEUE_SIZE,
  APP_OPTIONS_SEGMENT_SIZE,
  APP_OPTIONS_ADD_SEGMENT_SIZE,
  APP_OPTIONS_PRIVATE_SEGMENT_COUNT,
  APP_OPTIONS_RX_FIFO_SIZE,
  APP_OPTIONS_TX_FIFO_SIZE,
  APP_OPTIONS_PREALLOC_FIFO_PAIRS,
  APP_OPTIONS_NAMESPACE,
  APP_OPTIONS_NAMESPACE_SECRET,
  APP_OPTIONS_PROXY_TRANSPORT,
  APP_OPTIONS_ACCEPT_COOKIE,
  APP_OPTIONS_TLS_ENGINE,
  APP_OPTIONS_N_OPTIONS
} app_attach_options_index_t;

#define foreach_app_options_flags				\
  _(ACCEPT_REDIRECT, "Use FIFO with redirects")			\
  _(ADD_SEGMENT, "Add segment and signal app if needed")	\
  _(IS_BUILTIN, "Application is builtin")			\
  _(IS_TRANSPORT_APP, "Application is a transport proto")	\
  _(IS_PROXY, "Application is proxying")			\
  _(USE_GLOBAL_SCOPE, "App can use global session scope")	\
  _(USE_LOCAL_SCOPE, "App can use local session scope")		\
  _(USE_MQ_FOR_CTRL_MSGS, "Use message queue for ctr msgs")	\
  _(EVT_MQ_USE_EVENTFD, "Use eventfds for signaling")		\

typedef enum _app_options
{
#define _(sym, str) APP_OPTIONS_##sym,
  foreach_app_options_flags
#undef _
} app_options_t;

typedef enum _app_options_flags
{
#define _(sym, str) APP_OPTIONS_FLAGS_##sym = 1 << APP_OPTIONS_##sym,
  foreach_app_options_flags
#undef _
} app_options_flags_t;

#define foreach_fd_type						\
  _(VPP_MQ_SEGMENT, "Fd for vpp's event mq segment")		\
  _(MEMFD_SEGMENT, "Fd for memfd segment")			\
  _(MQ_EVENTFD, "Event fd used by message queue")		\
  _(VPP_MQ_EVENTFD, "Event fd used by vpp's message queue")	\

typedef enum session_fd_type_
{
#define _(sym, str) SESSION_FD_##sym,
  foreach_fd_type
#undef _
  SESSION_N_FD_TYPE
} session_fd_type_t;

typedef enum session_fd_flag_
{
#define _(sym, str) SESSION_FD_F_##sym = 1 << SESSION_FD_##sym,
  foreach_fd_type
#undef _
} session_fd_flag_t;

int vnet_bind_uri (vnet_bind_args_t *);
int vnet_unbind_uri (vnet_unbind_args_t * a);
clib_error_t *vnet_connect_uri (vnet_connect_args_t * a);

clib_error_t *vnet_application_attach (vnet_app_attach_args_t * a);
clib_error_t *vnet_bind (vnet_bind_args_t * a);
clib_error_t *vnet_connect (vnet_connect_args_t * a);
clib_error_t *vnet_unbind (vnet_unbind_args_t * a);
int vnet_application_detach (vnet_app_detach_args_t * a);
int vnet_disconnect_session (vnet_disconnect_args_t * a);

clib_error_t *vnet_app_add_tls_cert (vnet_app_add_tls_cert_args_t * a);
clib_error_t *vnet_app_add_tls_key (vnet_app_add_tls_key_args_t * a);

extern const char test_srv_crt_rsa[];
extern const u32 test_srv_crt_rsa_len;
extern const char test_srv_key_rsa[];
extern const u32 test_srv_key_rsa_len;

typedef struct app_session_transport_
{
  ip46_address_t rmt_ip;	/**< remote ip */
  ip46_address_t lcl_ip;	/**< local ip */
  u16 rmt_port;			/**< remote port (network order) */
  u16 lcl_port;			/**< local port (network order) */
  u8 is_ip4;			/**< set if uses ip4 networking */
} app_session_transport_t;

#define foreach_app_session_field					\
  _(svm_fifo_t, *rx_fifo)		/**< rx fifo */			\
  _(svm_fifo_t, *tx_fifo)		/**< tx fifo */			\
  _(session_type_t, session_type)	/**< session type */		\
  _(volatile u8, session_state)		/**< session state */		\
  _(u32, session_index)			/**< index in owning pool */	\
  _(app_session_transport_t, transport)	/**< transport info */		\
  _(svm_msg_q_t, *vpp_evt_q)		/**< vpp event queue  */	\
  _(u8, is_dgram)			/**< flag for dgram mode */	\

typedef struct
{
#define _(type, name) type name;
  foreach_app_session_field
#undef _
} app_session_t;

typedef struct session_bound_msg_
{
  u32 context;
  u64 handle;
  i32 retval;
  u8 lcl_is_ip4;
  u8 lcl_ip[16];
  u16 lcl_port;
  uword rx_fifo;
  uword tx_fifo;
  uword vpp_evt_q;
  u32 segment_size;
  u8 segment_name_length;
  u8 segment_name[128];
} __clib_packed session_bound_msg_t;

typedef struct session_accepted_msg_
{
  u32 context;
  u64 listener_handle;
  u64 handle;
  uword server_rx_fifo;
  uword server_tx_fifo;
  u64 segment_handle;
  uword vpp_event_queue_address;
  uword server_event_queue_address;
  uword client_event_queue_address;
  u16 port;
  u8 is_ip4;
  u8 ip[16];
} __clib_packed session_accepted_msg_t;

typedef struct session_accepted_reply_msg_
{
  u32 context;
  i32 retval;
  u64 handle;
} __clib_packed session_accepted_reply_msg_t;

/* Make sure this is not too large, otherwise it won't fit when dequeued in
 * the session queue node */
STATIC_ASSERT (sizeof (session_accepted_reply_msg_t) <= 16, "accept reply");

typedef struct session_connected_msg_
{
  u32 context;
  i32 retval;
  u64 handle;
  uword server_rx_fifo;
  uword server_tx_fifo;
  u64 segment_handle;
  uword vpp_event_queue_address;
  uword client_event_queue_address;
  uword server_event_queue_address;
  u32 segment_size;
  u8 segment_name_length;
  u8 segment_name[64];
  u8 lcl_ip[16];
  u8 is_ip4;
  u16 lcl_port;
} __clib_packed session_connected_msg_t;

typedef struct session_disconnected_msg_
{
  u32 client_index;
  u32 context;
  u64 handle;
} __clib_packed session_disconnected_msg_t;

typedef struct session_disconnected_reply_msg_
{
  u32 context;
  i32 retval;
  u64 handle;
} __clib_packed session_disconnected_reply_msg_t;

typedef struct session_reset_msg_
{
  u32 client_index;
  u32 context;
  u64 handle;
} __clib_packed session_reset_msg_t;

typedef struct session_reset_reply_msg_
{
  u32 context;
  i32 retval;
  u64 handle;
} __clib_packed session_reset_reply_msg_t;

typedef struct session_req_worker_update_msg_
{
  u64 session_handle;
} __clib_packed session_req_worker_update_msg_t;

/* NOTE: using u16 for wrk indices because message needs to fit in 18B */
typedef struct session_worker_update_msg_
{
  u32 client_index;
  u16 wrk_index;
  u16 req_wrk_index;
  u64 handle;
} __clib_packed session_worker_update_msg_t;

typedef struct session_worker_update_reply_msg_
{
  u64 handle;
  uword rx_fifo;
  uword tx_fifo;
  u64 segment_handle;
} __clib_packed session_worker_update_reply_msg_t;

typedef struct app_session_event_
{
  svm_msg_q_msg_t msg;
  session_event_t *evt;
} __clib_packed app_session_evt_t;

static inline void
app_alloc_ctrl_evt_to_vpp (svm_msg_q_t * mq, app_session_evt_t * app_evt,
			   u8 evt_type)
{
  svm_msg_q_lock_and_alloc_msg_w_ring (mq,
				       SESSION_MQ_CTRL_EVT_RING,
				       SVM_Q_WAIT, &app_evt->msg);
  svm_msg_q_unlock (mq);
  app_evt->evt = svm_msg_q_msg_data (mq, &app_evt->msg);
  clib_memset (app_evt->evt, 0, sizeof (*app_evt->evt));
  app_evt->evt->event_type = evt_type;
}

static inline void
app_send_ctrl_evt_to_vpp (svm_msg_q_t * mq, app_session_evt_t * app_evt)
{
  svm_msg_q_add (mq, &app_evt->msg, SVM_Q_WAIT);
}

/**
 * Send fifo io event to vpp worker thread
 *
 * Because there may be multiple writers to one of vpp's queues, this
 * protects message allocation and enqueueing.
 *
 * @param mq		vpp message queue
 * @param f		fifo for which the event is sent
 * @param evt_type	type of event
 * @param noblock	flag to indicate is request is blocking or not
 * @return		0 if success, negative integer otherwise
 */
static inline int
app_send_io_evt_to_vpp (svm_msg_q_t * mq, svm_fifo_t * f, u8 evt_type,
			u8 noblock)
{
  session_event_t *evt;
  svm_msg_q_msg_t msg;

  if (noblock)
    {
      if (svm_msg_q_try_lock (mq))
	return -1;
      if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
	{
	  svm_msg_q_unlock (mq);
	  return -2;
	}
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      if (PREDICT_FALSE (svm_msg_q_msg_is_invalid (&msg)))
	{
	  svm_msg_q_unlock (mq);
	  return -2;
	}
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->fifo = f;
      evt->event_type = evt_type;
      svm_msg_q_add_and_unlock (mq, &msg);
      return 0;
    }
  else
    {
      svm_msg_q_lock (mq);
      while (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING))
	svm_msg_q_wait (mq);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->fifo = f;
      evt->event_type = evt_type;
      if (svm_msg_q_is_full (mq))
	svm_msg_q_wait (mq);
      svm_msg_q_add_and_unlock (mq, &msg);
      return 0;
    }
}

always_inline int
app_send_dgram_raw (svm_fifo_t * f, app_session_transport_t * at,
		    svm_msg_q_t * vpp_evt_q, u8 * data, u32 len, u8 evt_type,
		    u8 noblock)
{
  u32 max_enqueue, actual_write;
  session_dgram_hdr_t hdr;
  int rv;

  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue <= sizeof (session_dgram_hdr_t))
    return 0;

  max_enqueue -= sizeof (session_dgram_hdr_t);
  actual_write = clib_min (len, max_enqueue);
  hdr.data_length = actual_write;
  hdr.data_offset = 0;
  clib_memcpy_fast (&hdr.rmt_ip, &at->rmt_ip, sizeof (ip46_address_t));
  hdr.is_ip4 = at->is_ip4;
  hdr.rmt_port = at->rmt_port;
  clib_memcpy_fast (&hdr.lcl_ip, &at->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = at->lcl_port;
  rv = svm_fifo_enqueue_nowait (f, sizeof (hdr), (u8 *) & hdr);
  ASSERT (rv == sizeof (hdr));

  if ((rv = svm_fifo_enqueue_nowait (f, actual_write, data)) > 0)
    {
      if (svm_fifo_set_event (f))
	app_send_io_evt_to_vpp (vpp_evt_q, f, evt_type, noblock);
    }
  ASSERT (rv);
  return rv;
}

always_inline int
app_send_dgram (app_session_t * s, u8 * data, u32 len, u8 noblock)
{
  return app_send_dgram_raw (s->tx_fifo, &s->transport, s->vpp_evt_q, data,
			     len, FIFO_EVENT_APP_TX, noblock);
}

always_inline int
app_send_stream_raw (svm_fifo_t * f, svm_msg_q_t * vpp_evt_q, u8 * data,
		     u32 len, u8 evt_type, u8 noblock)
{
  int rv;

  if ((rv = svm_fifo_enqueue_nowait (f, len, data)) > 0)
    {
      if (svm_fifo_set_event (f))
	app_send_io_evt_to_vpp (vpp_evt_q, f, evt_type, noblock);
    }
  return rv;
}

always_inline int
app_send_stream (app_session_t * s, u8 * data, u32 len, u8 noblock)
{
  return app_send_stream_raw (s->tx_fifo, s->vpp_evt_q, data, len,
			      FIFO_EVENT_APP_TX, noblock);
}

always_inline int
app_send (app_session_t * s, u8 * data, u32 len, u8 noblock)
{
  if (s->is_dgram)
    return app_send_dgram (s, data, len, noblock);
  return app_send_stream (s, data, len, noblock);
}

always_inline int
app_recv_dgram_raw (svm_fifo_t * f, u8 * buf, u32 len,
		    app_session_transport_t * at, u8 clear_evt, u8 peek)
{
  session_dgram_pre_hdr_t ph;
  u32 max_deq;
  int rv;

  max_deq = svm_fifo_max_dequeue (f);
  if (max_deq < sizeof (session_dgram_hdr_t))
    {
      if (clear_evt)
	svm_fifo_unset_event (f);
      return 0;
    }

  if (clear_evt)
    svm_fifo_unset_event (f);

  svm_fifo_peek (f, 0, sizeof (ph), (u8 *) & ph);
  ASSERT (ph.data_length >= ph.data_offset);
  if (!ph.data_offset)
    svm_fifo_peek (f, sizeof (ph), sizeof (*at), (u8 *) at);
  len = clib_min (len, ph.data_length - ph.data_offset);
  rv = svm_fifo_peek (f, ph.data_offset + SESSION_CONN_HDR_LEN, len, buf);
  if (peek)
    return rv;
  ph.data_offset += rv;
  if (ph.data_offset == ph.data_length)
    svm_fifo_dequeue_drop (f, ph.data_length + SESSION_CONN_HDR_LEN);
  else
    svm_fifo_overwrite_head (f, (u8 *) & ph, sizeof (ph));
  return rv;
}

always_inline int
app_recv_dgram (app_session_t * s, u8 * buf, u32 len)
{
  return app_recv_dgram_raw (s->rx_fifo, buf, len, &s->transport, 1, 0);
}

always_inline int
app_recv_stream_raw (svm_fifo_t * f, u8 * buf, u32 len, u8 clear_evt, u8 peek)
{
  if (clear_evt)
    svm_fifo_unset_event (f);

  if (peek)
    return svm_fifo_peek (f, 0, len, buf);

  return svm_fifo_dequeue_nowait (f, len, buf);
}

always_inline int
app_recv_stream (app_session_t * s, u8 * buf, u32 len)
{
  return app_recv_stream_raw (s->rx_fifo, buf, len, 1, 0);
}

always_inline int
app_recv (app_session_t * s, u8 * data, u32 len)
{
  if (s->is_dgram)
    return app_recv_dgram (s, data, len);
  return app_recv_stream (s, data, len);
}

#endif /* __included_uri_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
