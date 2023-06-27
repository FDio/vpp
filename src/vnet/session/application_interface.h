/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <svm/message_queue.h>
#include <vnet/session/session_types.h>
#include <vnet/tls/tls_test.h>
#include <svm/fifo_segment.h>

typedef struct certificate_
{
  u32 *app_interests;		/* vec of application index asking for deletion cb */
  u32 cert_key_index;		/* index in cert & key pool */
  u8 *key;
  u8 *cert;
} app_cert_key_pair_t;

typedef struct session_cb_vft_
{
  /** Notify server of new segment */
  int (*add_segment_callback) (u32 app_wrk_index, u64 segment_handle);

  /** Notify server of new segment */
  int (*del_segment_callback) (u32 app_wrk_index, u64 segment_handle);

  /** Notify server of newly accepted session */
  int (*session_accept_callback) (session_t * new_session);

  /** Connection request callback */
  int (*session_connected_callback) (u32 app_wrk_index, u32 opaque,
				     session_t * s, session_error_t code);

  /** Notify app that session is closing */
  void (*session_disconnect_callback) (session_t * s);

  /** Notify app that transport is closed */
  void (*session_transport_closed_callback) (session_t * s);

  /** Notify app that session or transport are about to be removed */
  void (*session_cleanup_callback) (session_t * s, session_cleanup_ntf_t ntf);

  /** Notify app that half open state was cleaned up (optional) */
  void (*half_open_cleanup_callback) (session_t *s);

  /** Notify app that session was reset */
  void (*session_reset_callback) (session_t * s);

  /** Notify app that session pool migration happened */
  void (*session_migrate_callback) (session_t * s, session_handle_t new_sh);

  /** Direct RX callback for built-in application */
  int (*builtin_app_rx_callback) (session_t * session);

  /** Direct TX callback for built-in application */
  int (*builtin_app_tx_callback) (session_t * session);

  /** Cert and key pair delete notification */
  int (*app_cert_key_pair_delete_callback) (app_cert_key_pair_t * ckpair);

  /** Delegate fifo-tuning-logic to application */
  int (*fifo_tuning_callback) (session_t * s, svm_fifo_t * f,
			       session_ft_action_t act, u32 bytes);

} session_cb_vft_t;

#define foreach_app_init_args			\
  _(u32, api_client_index)			\
  _(u8 *, name)					\
  _(u64 *, options)				\
  _(u8 *, namespace_id)				\
  _(session_cb_vft_t *, session_cb_vft)		\
  _(u32, app_index)				\
  _(u8, use_sock_api)				\

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
  u64 handle;
} vnet_listen_args_t;

typedef struct _vnet_unlisten_args_t
{
  union
  {
    char *uri;
    u64 handle;			/**< Session handle */
  };
  u32 app_index;		/**< Owning application index */
  u32 wrk_map_index;		/**< App's local pool worker index */
} vnet_unlisten_args_t;

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

  /* Resulting session, or half-open session, if connect successful */
  session_handle_t sh;
} vnet_connect_args_t;

typedef struct _vnet_shutdown_args_t
{
  session_handle_t handle;
  u32 app_index;
} vnet_shutdown_args_t;

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

typedef enum crypto_engine_type_
{
  CRYPTO_ENGINE_NONE,
  CRYPTO_ENGINE_OPENSSL,
  CRYPTO_ENGINE_MBEDTLS,
  CRYPTO_ENGINE_VPP,
  CRYPTO_ENGINE_PICOTLS,
  CRYPTO_ENGINE_LAST = CRYPTO_ENGINE_PICOTLS,
} crypto_engine_type_t;

typedef struct _vnet_app_add_cert_key_pair_args_
{
  u8 *cert;
  u8 *key;
  u32 cert_len;
  u32 key_len;
  u32 index;
} vnet_app_add_cert_key_pair_args_t;

typedef struct crypto_ctx_
{
  u32 ctx_index;		/**< index in crypto context pool */
  u32 n_subscribers;		/**< refcount of sessions using said context */
  u32 ckpair_index;		/**< certificate & key */
  u8 crypto_engine;
  void *data;			/**< protocol specific data */
} crypto_context_t;

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
  APP_OPTIONS_PREALLOC_FIFO_HDRS,
  APP_OPTIONS_NAMESPACE,
  APP_OPTIONS_NAMESPACE_SECRET,
  APP_OPTIONS_PROXY_TRANSPORT,
  APP_OPTIONS_ACCEPT_COOKIE,
  APP_OPTIONS_TLS_ENGINE,
  APP_OPTIONS_MAX_FIFO_SIZE,
  APP_OPTIONS_HIGH_WATERMARK,
  APP_OPTIONS_LOW_WATERMARK,
  APP_OPTIONS_PCT_FIRST_ALLOC,
  APP_OPTIONS_N_OPTIONS
} app_attach_options_index_t;

#define foreach_app_options_flags                                             \
  _ (ACCEPT_REDIRECT, "Use FIFO with redirects")                              \
  _ (ADD_SEGMENT, "Add segment and signal app if needed")                     \
  _ (IS_BUILTIN, "Application is builtin")                                    \
  _ (IS_TRANSPORT_APP, "Application is a transport proto")                    \
  _ (IS_PROXY, "Application is proxying")                                     \
  _ (USE_GLOBAL_SCOPE, "App can use global session scope")                    \
  _ (USE_LOCAL_SCOPE, "App can use local session scope")                      \
  _ (EVT_MQ_USE_EVENTFD, "Use eventfds for signaling")                        \
  _ (MEMFD_FOR_BUILTIN, "Use memfd for builtin app segs")                     \
  _ (USE_HUGE_PAGE, "Use huge page for FIFO")                                 \
  _ (GET_ORIGINAL_DST, "Get original dst enabled")

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

int parse_uri (char *uri, session_endpoint_cfg_t * sep);
int vnet_bind_uri (vnet_listen_args_t *);
int vnet_unbind_uri (vnet_unlisten_args_t * a);
int vnet_connect_uri (vnet_connect_args_t * a);

int vnet_application_attach (vnet_app_attach_args_t * a);
int vnet_application_detach (vnet_app_detach_args_t * a);
int vnet_listen (vnet_listen_args_t * a);
int vnet_connect (vnet_connect_args_t * a);
int vnet_unlisten (vnet_unlisten_args_t * a);
int vnet_shutdown_session (vnet_shutdown_args_t *a);
int vnet_disconnect_session (vnet_disconnect_args_t * a);

int vnet_app_add_cert_key_pair (vnet_app_add_cert_key_pair_args_t * a);
int vnet_app_del_cert_key_pair (u32 index);
/** Ask for app cb on pair deletion */
int vnet_app_add_cert_key_interest (u32 index, u32 app_index);

uword unformat_vnet_uri (unformat_input_t *input, va_list *args);

typedef struct app_session_transport_
{
  ip46_address_t rmt_ip;	/**< remote ip */
  ip46_address_t lcl_ip;	/**< local ip */
  u16 rmt_port;			/**< remote port (network order) */
  u16 lcl_port;			/**< local port (network order) */
  u8 is_ip4;			/**< set if uses ip4 networking */
} app_session_transport_t;

#define foreach_app_session_field                                             \
  _ (svm_fifo_t, *rx_fifo)		 /**< rx fifo */                      \
  _ (svm_fifo_t, *tx_fifo)		 /**< tx fifo */                      \
  _ (session_type_t, session_type)	 /**< session type */                 \
  _ (volatile u8, session_state)	 /**< session state */                \
  _ (u32, session_index)		 /**< index in owning pool */         \
  _ (app_session_transport_t, transport) /**< transport info */               \
  _ (svm_msg_q_t, *vpp_evt_q)		 /**< vpp event queue  */             \
  _ (u8, is_dgram)			 /**< flag for dgram mode */

typedef struct
{
#define _(type, name) type name;
  foreach_app_session_field
#undef _
} app_session_t;

typedef struct session_listen_msg_
{
  u32 client_index;
  u32 context;			/* Not needed but keeping it for compatibility with bapi */
  u32 wrk_index;
  u32 vrf;
  u16 port;
  u8 proto;
  u8 is_ip4;
  ip46_address_t ip;
  u8 flags;
  uword ext_config;
} __clib_packed session_listen_msg_t;

STATIC_ASSERT (sizeof (session_listen_msg_t) <= SESSION_CTRL_MSG_MAX_SIZE,
	       "msg too large");

typedef struct session_listen_uri_msg_
{
  u32 client_index;
  u32 context;
  u8 uri[56];
} __clib_packed session_listen_uri_msg_t;

STATIC_ASSERT (sizeof (session_listen_uri_msg_t) <= SESSION_CTRL_MSG_MAX_SIZE,
	       "msg too large");

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
  u64 segment_handle;
  u32 mq_index;
} __clib_packed session_bound_msg_t;

typedef struct session_unlisten_msg_
{
  u32 client_index;
  u32 context;
  u32 wrk_index;
  session_handle_t handle;
} __clib_packed session_unlisten_msg_t;

typedef struct session_unlisten_reply_msg_
{
  u32 context;
  u64 handle;
  i32 retval;
} __clib_packed session_unlisten_reply_msg_t;

typedef struct session_accepted_msg_
{
  u32 context;
  u64 listener_handle;
  u64 handle;
  uword server_rx_fifo;
  uword server_tx_fifo;
  u64 segment_handle;
  uword vpp_event_queue_address;
  u32 mq_index;
  transport_endpoint_t lcl;
  transport_endpoint_t rmt;
  u8 flags;
  u32 original_dst_ip4;
  u16 original_dst_port;
} __clib_packed session_accepted_msg_t;

typedef struct session_accepted_reply_msg_
{
  u32 context;
  i32 retval;
  u64 handle;
} __clib_packed session_accepted_reply_msg_t;

typedef struct session_connect_msg_
{
  u32 client_index;
  u32 context;
  u32 wrk_index;
  u32 vrf;
  u16 port;
  u16 lcl_port;
  u8 proto;
  u8 is_ip4;
  ip46_address_t ip;
  ip46_address_t lcl_ip;
  u64 parent_handle;
  u32 ckpair_index;
  u8 crypto_engine;
  u8 flags;
  u8 dscp;
  uword ext_config;
} __clib_packed session_connect_msg_t;

STATIC_ASSERT (sizeof (session_connect_msg_t) <= SESSION_CTRL_MSG_MAX_SIZE,
	       "msg too large");

typedef struct session_connect_uri_msg_
{
  u32 client_index;
  u32 context;
  u8 uri[56];
} __clib_packed session_connect_uri_msg_t;

STATIC_ASSERT (sizeof (session_connect_uri_msg_t) <=
	       SESSION_CTRL_MSG_MAX_SIZE, "msg too large");

typedef struct session_connected_msg_
{
  u32 context;
  i32 retval;
  u64 handle;
  uword server_rx_fifo;
  uword server_tx_fifo;
  u64 segment_handle;
  uword ct_rx_fifo;
  uword ct_tx_fifo;
  u64 ct_segment_handle;
  uword vpp_event_queue_address;
  transport_endpoint_t lcl;
  u32 mq_index;
} __clib_packed session_connected_msg_t;

typedef struct session_shutdown_msg_
{
  u32 client_index;
  u32 context;
  session_handle_t handle;
} __clib_packed session_shutdown_msg_t;

typedef struct session_disconnect_msg_
{
  u32 client_index;
  u32 context;
  session_handle_t handle;
} __clib_packed session_disconnect_msg_t;

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

typedef struct session_app_detach_msg_
{
  u32 client_index;
  u32 context;
} session_app_detach_msg_t;

typedef struct app_map_another_segment_msg_
{
  u32 client_index;
  u32 context;
  u8 fd_flags;
  u32 segment_size;
  u8 segment_name[128];
  u64 segment_handle;
} session_app_add_segment_msg_t;

typedef struct app_unmap_segment_msg_
{
  u32 client_index;
  u32 context;
  u64 segment_handle;
} session_app_del_segment_msg_t;

typedef struct session_migrate_msg_
{
  uword vpp_evt_q;
  session_handle_t handle;
  session_handle_t new_handle;
  u64 segment_handle;
  u32 vpp_thread_index;
} __clib_packed session_migrated_msg_t;

typedef struct session_cleanup_msg_
{
  session_handle_t handle;
  u8 type;
} __clib_packed session_cleanup_msg_t;

typedef struct session_app_wrk_rpc_msg_
{
  u32 client_index;	/**< app client index */
  u32 wrk_index;	/**< dst worker index */
  u8 data[64];		/**< rpc data */
} __clib_packed session_app_wrk_rpc_msg_t;

typedef struct session_transport_attr_msg_
{
  u32 client_index;
  session_handle_t handle;
  transport_endpt_attr_t attr;
  u8 is_get;
} __clib_packed session_transport_attr_msg_t;

typedef struct session_transport_attr_reply_msg_
{
  i32 retval;
  session_handle_t handle;
  transport_endpt_attr_t attr;
  u8 is_get;
} __clib_packed session_transport_attr_reply_msg_t;

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
  app_evt->evt = svm_msg_q_msg_data (mq, &app_evt->msg);
  clib_memset (app_evt->evt, 0, sizeof (*app_evt->evt));
  app_evt->evt->event_type = evt_type;
}

static inline void
app_send_ctrl_evt_to_vpp (svm_msg_q_t * mq, app_session_evt_t * app_evt)
{
  svm_msg_q_add_and_unlock (mq, &app_evt->msg);
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
app_send_io_evt_to_vpp (svm_msg_q_t * mq, u32 session_index, u8 evt_type,
			u8 noblock)
{
  session_event_t *evt;
  svm_msg_q_msg_t msg;

  if (noblock)
    {
      if (svm_msg_q_try_lock (mq))
	return -1;
      if (PREDICT_FALSE (
	    svm_msg_q_or_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
	{
	  svm_msg_q_unlock (mq);
	  return -2;
	}
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->session_index = session_index;
      evt->event_type = evt_type;
      svm_msg_q_add_and_unlock (mq, &msg);
      return 0;
    }
  else
    {
      svm_msg_q_lock (mq);
      while (svm_msg_q_or_ring_is_full (mq, SESSION_MQ_IO_EVT_RING))
	svm_msg_q_or_ring_wait_prod (mq, SESSION_MQ_IO_EVT_RING);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->session_index = session_index;
      evt->event_type = evt_type;
      svm_msg_q_add_and_unlock (mq, &msg);
      return 0;
    }
}

#define app_send_dgram_raw(f, at, vpp_evt_q, data, len, evt_type, do_evt,     \
			   noblock)                                           \
  app_send_dgram_raw_gso (f, at, vpp_evt_q, data, len, 0, evt_type, do_evt,   \
			  noblock)

always_inline int
app_send_dgram_raw_gso (svm_fifo_t *f, app_session_transport_t *at,
			svm_msg_q_t *vpp_evt_q, u8 *data, u32 len,
			u16 gso_size, u8 evt_type, u8 do_evt, u8 noblock)
{
  session_dgram_hdr_t hdr;
  int rv;
  if (svm_fifo_max_enqueue_prod (f) < (sizeof (session_dgram_hdr_t) + len))
    return 0;

  hdr.data_length = len;
  hdr.data_offset = 0;
  clib_memcpy_fast (&hdr.rmt_ip, &at->rmt_ip, sizeof (ip46_address_t));
  hdr.is_ip4 = at->is_ip4;
  hdr.rmt_port = at->rmt_port;
  clib_memcpy_fast (&hdr.lcl_ip, &at->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = at->lcl_port;
  hdr.gso_size = gso_size;
  /* *INDENT-OFF* */
  svm_fifo_seg_t segs[2] = {{ (u8 *) &hdr, sizeof (hdr) }, { data, len }};
  /* *INDENT-ON* */

  rv = svm_fifo_enqueue_segments (f, segs, 2, 0 /* allow partial */ );
  if (PREDICT_FALSE (rv < 0))
    return 0;

  if (do_evt)
    {
      if (svm_fifo_set_event (f))
	app_send_io_evt_to_vpp (vpp_evt_q, f->shr->master_session_index,
				evt_type, noblock);
    }
  return len;
}

always_inline int
app_send_dgram (app_session_t * s, u8 * data, u32 len, u8 noblock)
{
  return app_send_dgram_raw (s->tx_fifo, &s->transport, s->vpp_evt_q, data,
			     len, SESSION_IO_EVT_TX, 1 /* do_evt */ ,
			     noblock);
}

always_inline int
app_send_stream_raw (svm_fifo_t * f, svm_msg_q_t * vpp_evt_q, u8 * data,
		     u32 len, u8 evt_type, u8 do_evt, u8 noblock)
{
  int rv;

  rv = svm_fifo_enqueue (f, len, data);
  if (do_evt)
    {
      if (rv > 0 && svm_fifo_set_event (f))
	app_send_io_evt_to_vpp (vpp_evt_q, f->shr->master_session_index,
				evt_type, noblock);
    }
  return rv;
}

always_inline int
app_send_stream (app_session_t * s, u8 * data, u32 len, u8 noblock)
{
  return app_send_stream_raw (s->tx_fifo, s->vpp_evt_q, data, len,
			      SESSION_IO_EVT_TX, 1 /* do_evt */ , noblock);
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

  max_deq = svm_fifo_max_dequeue_cons (f);
  if (max_deq <= sizeof (session_dgram_hdr_t))
    {
      if (clear_evt)
	svm_fifo_unset_event (f);
      return 0;
    }

  if (clear_evt)
    svm_fifo_unset_event (f);

  svm_fifo_peek (f, 0, sizeof (ph), (u8 *) & ph);
  ASSERT (ph.data_length >= ph.data_offset);

  /* Check if we have the full dgram */
  if (max_deq < (ph.data_length + SESSION_CONN_HDR_LEN)
      && len >= ph.data_length)
    return 0;

  svm_fifo_peek (f, sizeof (ph), sizeof (*at), (u8 *) at);
  len = clib_min (len, ph.data_length - ph.data_offset);
  rv = svm_fifo_peek (f, ph.data_offset + SESSION_CONN_HDR_LEN, len, buf);
  if (peek)
    return rv;

  /* Discards data that did not fit in buffer */
  svm_fifo_dequeue_drop (f, ph.data_length + SESSION_CONN_HDR_LEN);

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

  return svm_fifo_dequeue (f, len, buf);
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

/* *INDENT-OFF* */
static char *session_error_str[] = {
#define _(sym, str) str,
    foreach_session_error
#undef _
};
/* *INDENT-ON* */

static inline u8 *
format_session_error (u8 * s, va_list * args)
{
  session_error_t error = va_arg (*args, session_error_t);
  if (-error >= 0 && -error < SESSION_N_ERRORS)
    s = format (s, "%s", session_error_str[-error]);
  else
    s = format (s, "invalid session err %u", -error);
  return s;
}

/*
 * Socket API messages
 */

typedef enum app_sapi_msg_type
{
  APP_SAPI_MSG_TYPE_NONE,
  APP_SAPI_MSG_TYPE_ATTACH,
  APP_SAPI_MSG_TYPE_ATTACH_REPLY,
  APP_SAPI_MSG_TYPE_ADD_DEL_WORKER,
  APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_REPLY,
  APP_SAPI_MSG_TYPE_SEND_FDS,
  APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY,
  APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY_REPLY,
} __clib_packed app_sapi_msg_type_e;

typedef struct app_sapi_attach_msg_
{
  u8 name[64];
  u64 options[18];
} __clib_packed app_sapi_attach_msg_t;

STATIC_ASSERT (sizeof (u64) * APP_OPTIONS_N_OPTIONS <=
	       sizeof (((app_sapi_attach_msg_t *) 0)->options),
	       "Out of options, fix message definition");

typedef struct app_sapi_attach_reply_msg_
{
  i32 retval;
  u32 app_index;
  u64 app_mq;
  u64 vpp_ctrl_mq;
  u64 segment_handle;
  u32 api_client_handle;
  u8 vpp_ctrl_mq_thread;
  u8 n_fds;
  u8 fd_flags;
} __clib_packed app_sapi_attach_reply_msg_t;

typedef struct app_sapi_worker_add_del_msg_
{
  u32 app_index;
  u32 wrk_index;
  u8 is_add;
} __clib_packed app_sapi_worker_add_del_msg_t;

typedef struct app_sapi_worker_add_del_reply_msg_
{
  i32 retval;
  u32 wrk_index;
  u64 app_event_queue_address;
  u64 segment_handle;
  u32 api_client_handle;
  u8 n_fds;
  u8 fd_flags;
  u8 is_add;
} __clib_packed app_sapi_worker_add_del_reply_msg_t;

typedef struct app_sapi_cert_key_add_del_msg_
{
  u32 context;
  u32 index;
  u16 cert_len;
  u16 certkey_len;
  u8 is_add;
} __clib_packed app_sapi_cert_key_add_del_msg_t;

typedef struct app_sapi_cert_key_add_del_reply_msg_
{
  u32 context;
  i32 retval;
  u32 index;
} __clib_packed app_sapi_cert_key_add_del_reply_msg_t;

typedef struct app_sapi_msg_
{
  app_sapi_msg_type_e type;
  union
  {
    app_sapi_attach_msg_t attach;
    app_sapi_attach_reply_msg_t attach_reply;
    app_sapi_worker_add_del_msg_t worker_add_del;
    app_sapi_worker_add_del_reply_msg_t worker_add_del_reply;
    app_sapi_cert_key_add_del_msg_t cert_key_add_del;
    app_sapi_cert_key_add_del_reply_msg_t cert_key_add_del_reply;
  };
} __clib_packed app_sapi_msg_t;

static inline void
session_endpoint_alloc_ext_cfg (session_endpoint_cfg_t *sep_ext,
				transport_endpt_ext_cfg_type_t type)
{
  transport_endpt_ext_cfg_t *cfg;
  u32 cfg_size;

  cfg_size = sizeof (transport_endpt_ext_cfg_t);
  cfg = clib_mem_alloc (cfg_size);
  clib_memset (cfg, 0, cfg_size);
  cfg->type = type;
  sep_ext->ext_cfg = cfg;
}

#endif /* __included_uri_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
