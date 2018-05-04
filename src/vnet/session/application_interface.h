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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <svm/svm_fifo_segment.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/tls/tls.h>

typedef struct _vnet_app_attach_args_t
{
  /** Binary API client index */
  u32 api_client_index;

  /** Application name. Used by builtin apps */
  u8 *name;

  /** Application and segment manager options */
  u64 *options;

  /** ID of the namespace the app has access to */
  u8 *namespace_id;

  /** Session to application callback functions */
  session_cb_vft_t *session_cb_vft;

  /*
   * Results
   */
  ssvm_private_t *segment;
  u64 app_event_queue_address;
  u32 app_index;
} vnet_app_attach_args_t;

typedef struct _vnet_app_detach_args_t
{
  u32 app_index;
} vnet_app_detach_args_t;

typedef struct _vnet_bind_args_t
{
  union
  {
    char *uri;
    session_endpoint_t sep;
  };

  u32 app_index;

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
    u64 handle;
  };
  u32 app_index;
} vnet_unbind_args_t;

typedef struct _vnet_connect_args
{
  union
  {
    char *uri;
    session_endpoint_extended_t sep;
  };
  u32 app_index;
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
  _(IS_PROXY, "Application is proxying")				\
  _(USE_GLOBAL_SCOPE, "App can use global session scope")	\
  _(USE_LOCAL_SCOPE, "App can use local session scope")

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
  u16 rmt_port;			/**< remote port */
  u16 lcl_port;			/**< local port */
  u8 is_ip4;			/**< set if uses ip4 networking */
} app_session_transport_t;

typedef struct app_session_
{
  svm_fifo_t *rx_fifo;			/**< rx fifo */
  svm_fifo_t *tx_fifo;			/**< tx fifo */
  session_type_t session_type;		/**< session type */
  volatile u8 session_state;		/**< session state */
  u32 session_index;			/**< index in owning pool */
  app_session_transport_t transport;	/**< transport info */
  svm_queue_t *vpp_evt_q;		/**< vpp event queue for session */
  u8 is_dgram;				/**< set if it works in dgram mode */
} app_session_t;

always_inline int
app_send_dgram_raw (svm_fifo_t * f, app_session_transport_t * at,
		    svm_queue_t * vpp_evt_q, u8 * data, u32 len, u8 noblock)
{
  u32 max_enqueue, actual_write;
  session_dgram_hdr_t hdr;
  session_fifo_event_t evt;
  int rv;

  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue <= sizeof (session_dgram_hdr_t))
    return 0;

  max_enqueue -= sizeof (session_dgram_hdr_t);
  actual_write = clib_min (len, max_enqueue);
  hdr.data_length = actual_write;
  hdr.data_offset = 0;
  clib_memcpy (&hdr.rmt_ip, &at->rmt_ip, sizeof (ip46_address_t));
  hdr.is_ip4 = at->is_ip4;
  hdr.rmt_port = at->rmt_port;
  clib_memcpy (&hdr.lcl_ip, &at->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = at->lcl_port;
  rv = svm_fifo_enqueue_nowait (f, sizeof (hdr), (u8 *) & hdr);
  ASSERT (rv == sizeof (hdr));

  if ((rv = svm_fifo_enqueue_nowait (f, actual_write, data)) > 0)
    {
      if (svm_fifo_set_event (f))
	{
	  evt.fifo = f;
	  evt.event_type = FIFO_EVENT_APP_TX;
	  svm_queue_add (vpp_evt_q, (u8 *) & evt, noblock);
	}
    }
  ASSERT (rv);
  return rv;
}

always_inline int
app_send_dgram (app_session_t * s, u8 * data, u32 len, u8 noblock)
{
  return app_send_dgram_raw (s->tx_fifo, &s->transport, s->vpp_evt_q, data,
			     len, noblock);
}

always_inline int
app_send_stream_raw (svm_fifo_t * f, svm_queue_t * vpp_evt_q, u8 * data,
		     u32 len, u8 noblock)
{
  session_fifo_event_t evt;
  int rv;

  if ((rv = svm_fifo_enqueue_nowait (f, len, data)) > 0)
    {
      if (svm_fifo_set_event (f))
	{
	  evt.fifo = f;
	  evt.event_type = FIFO_EVENT_APP_TX;
	  svm_queue_add (vpp_evt_q, (u8 *) & evt, noblock);
	}
    }
  return rv;
}

always_inline int
app_send_stream (app_session_t * s, u8 * data, u32 len, u8 noblock)
{
  return app_send_stream_raw (s->tx_fifo, s->vpp_evt_q, data, len, noblock);
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
		    app_session_transport_t * at, u8 clear_evt)
{
  session_dgram_pre_hdr_t ph;
  u32 max_deq;
  int rv;

  if (clear_evt)
    svm_fifo_unset_event (f);
  max_deq = svm_fifo_max_dequeue (f);
  if (max_deq < sizeof (session_dgram_hdr_t))
    return 0;

  svm_fifo_peek (f, 0, sizeof (ph), (u8 *) & ph);
  ASSERT (ph.data_length >= ph.data_offset);
  if (!ph.data_offset)
    svm_fifo_peek (f, sizeof (ph), sizeof (*at), (u8 *) at);
  len = clib_min (len, ph.data_length - ph.data_offset);
  rv = svm_fifo_peek (f, ph.data_offset + SESSION_CONN_HDR_LEN, len, buf);
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
  return app_recv_dgram_raw (s->rx_fifo, buf, len, &s->transport, 1);
}

always_inline int
app_recv_stream_raw (svm_fifo_t * f, u8 * buf, u32 len, u8 clear_evt)
{
  if (clear_evt)
    svm_fifo_unset_event (f);
  return svm_fifo_dequeue_nowait (f, len, buf);
}

always_inline int
app_recv_stream (app_session_t * s, u8 * buf, u32 len)
{
  return app_recv_stream_raw (s->rx_fifo, buf, len, 1);
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
