/*
 * Copyright (c) 2015-2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>

#include <vnet/vnet_msg_enum.h>
#include "application_interface.h"

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_session_api_msg                                         \
_(MAP_ANOTHER_SEGMENT_REPLY, map_another_segment_reply)                 \
_(BIND_URI, bind_uri)                                                   \
_(UNBIND_URI, unbind_uri)                                               \
_(CONNECT_URI, connect_uri)                                             \
_(DISCONNECT_SESSION, disconnect_session)                               \
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)                   \
_(ACCEPT_SESSION_REPLY, accept_session_reply)                           \
_(RESET_SESSION_REPLY, reset_session_reply)                   		\
_(BIND_SOCK, bind_sock) 		                                \
_(UNBIND_SOCK, unbind_sock)                                             \
_(CONNECT_SOCK, connect_sock)                                          	\
_(DISCONNECT_SOCK, disconnect_sock)                               	\
_(DISCONNECT_SOCK_REPLY, disconnect_sock_reply)                        	\
_(ACCEPT_SOCK_REPLY, accept_sock_reply)                           	\
_(RESET_SOCK_REPLY, reset_sock_reply)                   		\

static int
send_add_segment_callback (u32 api_client_index, const u8 * segment_name,
			   u32 segment_size)
{
  vl_api_map_another_segment_t *mp;
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (api_client_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_MAP_ANOTHER_SEGMENT);
  mp->segment_size = segment_size;
  strncpy ((char *) mp->segment_name, (char *) segment_name,
	   sizeof (mp->segment_name) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & mp);

  return 0;
}

static int
send_session_accept_uri_callback (stream_session_t * s)
{
  vl_api_accept_session_t *mp;
  unix_shared_memory_queue_t *q, *vpp_queue;
  application_t *server = application_get (s->app_index);

  q = vl_api_client_index_to_input_queue (server->api_client_index);
  vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_ACCEPT_SESSION);

  /* Note: session_type is the first octet in all types of sessions */

  mp->accept_cookie = server->accept_cookie;
  mp->server_rx_fifo = (u64) s->server_rx_fifo;
  mp->server_tx_fifo = (u64) s->server_tx_fifo;
  mp->session_thread_index = s->thread_index;
  mp->session_index = s->session_index;
  mp->session_type = s->session_type;
  mp->vpp_event_queue_address = (u64) vpp_queue;
  vl_msg_api_send_shmem (q, (u8 *) & mp);

  return 0;
}

static void
send_session_disconnect_uri_callback (stream_session_t * s)
{
  vl_api_disconnect_session_t *mp;
  unix_shared_memory_queue_t *q;
  application_t *app = application_get (s->app_index);

  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_DISCONNECT_SESSION);

  mp->session_thread_index = s->thread_index;
  mp->session_index = s->session_index;
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static int
send_session_connected_uri_callback (u32 api_client_index,
				     stream_session_t * s, u8 is_fail)
{
  vl_api_connect_uri_reply_t *mp;
  unix_shared_memory_queue_t *q;
  application_t *app = application_lookup (api_client_index);
  u8 *seg_name;
  unix_shared_memory_queue_t *vpp_queue;

  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_CONNECT_URI_REPLY);
  mp->context = app->api_context;
  mp->retval = is_fail;
  if (!is_fail)
    {
      vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);
      mp->server_rx_fifo = (u64) s->server_rx_fifo;
      mp->server_tx_fifo = (u64) s->server_tx_fifo;
      mp->session_thread_index = s->thread_index;
      mp->session_index = s->session_index;
      mp->session_type = s->session_type;
      mp->vpp_event_queue_address = (u64) vpp_queue;
      mp->client_event_queue_address = (u64) app->event_queue;

      session_manager_get_segment_info (s->server_segment_index, &seg_name,
					&mp->segment_size);
      mp->segment_name_length = vec_len (seg_name);
      if (mp->segment_name_length)
	clib_memcpy (mp->segment_name, seg_name, mp->segment_name_length);
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);

  /* Remove client if connect failed */
  if (is_fail)
    application_del (app);

  return 0;
}

/**
 * Redirect a connect_uri message to the indicated server.
 * Only sent if the server has bound the related port with
 * URI_OPTIONS_FLAGS_USE_FIFO
 */
static int
redirect_connect_uri_callback (u32 server_api_client_index, void *mp_arg)
{
  vl_api_connect_uri_t *mp = mp_arg;
  unix_shared_memory_queue_t *server_q, *client_q;
  vlib_main_t *vm = vlib_get_main ();
  f64 timeout = vlib_time_now (vm) + 0.5;
  int rv = 0;

  server_q = vl_api_client_index_to_input_queue (server_api_client_index);

  if (!server_q)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  client_q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!client_q)
    {
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto out;
    }

  /* Tell the server the client's API queue address, so it can reply */
  mp->client_queue_address = (u64) client_q;

  /*
   * Bounce message handlers MUST NOT block the data-plane.
   * Spin waiting for the queue lock, but
   */

  while (vlib_time_now (vm) < timeout)
    {
      rv =
	unix_shared_memory_queue_add (server_q, (u8 *) & mp, 1 /*nowait */ );
      switch (rv)
	{
	  /* correctly enqueued */
	case 0:
	  return VNET_CONNECT_REDIRECTED;

	  /* continue spinning, wait for pthread_mutex_trylock to work */
	case -1:
	  continue;

	  /* queue stuffed, drop the msg */
	case -2:
	  rv = VNET_API_ERROR_QUEUE_FULL;
	  goto out;
	}
    }
out:
  /* Dispose of the message */
  vl_msg_api_free (mp);
  return rv;
}

static u64
make_session_handle (stream_session_t * s)
{
  return (u64) s->session_index << 32 | (u64) s->thread_index;
}

static int
send_session_accept_callback (stream_session_t * s)
{
  vl_api_accept_sock_t *mp;
  unix_shared_memory_queue_t *q, *vpp_queue;
  application_t *server = application_get (s->app_index);

  q = vl_api_client_index_to_input_queue (server->api_client_index);
  vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_ACCEPT_SOCK);

  /* Note: session_type is the first octet in all types of sessions */

  mp->accept_cookie = server->accept_cookie;
  mp->server_rx_fifo = (u64) s->server_rx_fifo;
  mp->server_tx_fifo = (u64) s->server_tx_fifo;
  mp->handle = make_session_handle (s);
  mp->vpp_event_queue_address = (u64) vpp_queue;
  vl_msg_api_send_shmem (q, (u8 *) & mp);

  return 0;
}

static int
send_session_connected_callback (u32 api_client_index, stream_session_t * s,
				 u8 is_fail)
{
  vl_api_connect_sock_reply_t *mp;
  unix_shared_memory_queue_t *q;
  application_t *app = application_lookup (api_client_index);
  u8 *seg_name;
  unix_shared_memory_queue_t *vpp_queue;

  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_CONNECT_SOCK_REPLY);
  mp->context = app->api_context;
  mp->retval = is_fail;
  if (!is_fail)
    {
      vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);
      mp->server_rx_fifo = (u64) s->server_rx_fifo;
      mp->server_tx_fifo = (u64) s->server_tx_fifo;
      mp->handle = make_session_handle (s);
      mp->vpp_event_queue_address = (u64) vpp_queue;
      mp->client_event_queue_address = (u64) app->event_queue;

      session_manager_get_segment_info (s->server_segment_index, &seg_name,
					&mp->segment_size);
      mp->segment_name_length = vec_len (seg_name);
      if (mp->segment_name_length)
	clib_memcpy (mp->segment_name, seg_name, mp->segment_name_length);
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);

  /* Remove client if connect failed */
  if (is_fail)
    application_del (app);

  return 0;
}

static void
send_session_disconnect_callback (stream_session_t * s)
{
  vl_api_disconnect_sock_t *mp;
  unix_shared_memory_queue_t *q;
  application_t *app = application_get (s->app_index);

  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_DISCONNECT_SOCK);

  mp->handle = make_session_handle (s);
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

/**
 * Redirect a connect_uri message to the indicated server.
 * Only sent if the server has bound the related port with
 * URI_OPTIONS_FLAGS_USE_FIFO
 */
static int
redirect_connect_callback (u32 server_api_client_index, void *mp_arg)
{
  vl_api_connect_sock_t *mp = mp_arg;
  unix_shared_memory_queue_t *server_q, *client_q;
  vlib_main_t *vm = vlib_get_main ();
  f64 timeout = vlib_time_now (vm) + 0.5;
  int rv = 0;

  server_q = vl_api_client_index_to_input_queue (server_api_client_index);

  if (!server_q)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  client_q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!client_q)
    {
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto out;
    }

  /* Tell the server the client's API queue address, so it can reply */
  mp->client_queue_address = (u64) client_q;

  /*
   * Bounce message handlers MUST NOT block the data-plane.
   * Spin waiting for the queue lock, but
   */

  while (vlib_time_now (vm) < timeout)
    {
      rv =
	unix_shared_memory_queue_add (server_q, (u8 *) & mp, 1 /*nowait */ );
      switch (rv)
	{
	  /* correctly enqueued */
	case 0:
	  return VNET_CONNECT_REDIRECTED;

	  /* continue spinning, wait for pthread_mutex_trylock to work */
	case -1:
	  continue;

	  /* queue stuffed, drop the msg */
	case -2:
	  rv = VNET_API_ERROR_QUEUE_FULL;
	  goto out;
	}
    }
out:
  /* Dispose of the message */
  vl_msg_api_free (mp);
  return rv;
}

static session_cb_vft_t uri_session_cb_vft = {
  .session_accept_callback = send_session_accept_uri_callback,
  .session_disconnect_callback = send_session_disconnect_uri_callback,
  .session_connected_callback = send_session_connected_uri_callback,
  .add_segment_callback = send_add_segment_callback,
  .redirect_connect_callback = redirect_connect_uri_callback
};

static session_cb_vft_t session_cb_vft = {
  .session_accept_callback = send_session_accept_callback,
  .session_disconnect_callback = send_session_disconnect_callback,
  .session_connected_callback = send_session_connected_callback,
  .add_segment_callback = send_add_segment_callback,
  .redirect_connect_callback = redirect_connect_callback
};

static int
api_session_not_valid (u32 session_index, u32 thread_index)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  stream_session_t *pool;

  if (thread_index >= vec_len (smm->sessions))
    return VNET_API_ERROR_INVALID_VALUE;

  pool = smm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return VNET_API_ERROR_INVALID_VALUE_2;

  return 0;
}

static void
vl_api_bind_uri_t_handler (vl_api_bind_uri_t * mp)
{
  vl_api_bind_uri_reply_t *rmp;
  vnet_bind_args_t _a, *a = &_a;
  char segment_name[128];
  u32 segment_name_length;
  int rv;

  _Static_assert (sizeof (u64) * SESSION_OPTIONS_N_OPTIONS <=
		  sizeof (mp->options),
		  "Out of options, fix api message definition");

  segment_name_length = ARRAY_LEN (segment_name);

  memset (a, 0, sizeof (*a));

  a->uri = (char *) mp->uri;
  a->api_client_index = mp->client_index;
  a->options = mp->options;
  a->segment_name = segment_name;
  a->segment_name_length = segment_name_length;
  a->session_cb_vft = &uri_session_cb_vft;

  a->options[SESSION_OPTIONS_SEGMENT_SIZE] = mp->initial_segment_size;
  a->options[SESSION_OPTIONS_ACCEPT_COOKIE] = mp->accept_cookie;
  rv = vnet_bind_uri (a);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_BIND_URI_REPLY, ({
    rmp->retval = rv;
    if (!rv)
      {
	rmp->segment_name_length = 0;
	/* $$$$ policy? */
	rmp->segment_size = mp->initial_segment_size;
	if (segment_name_length)
	  {
	    memcpy (rmp->segment_name, segment_name, segment_name_length);
	    rmp->segment_name_length = segment_name_length;
	  }
	rmp->server_event_queue_address = a->server_event_queue_address;
      }
  }));
  /* *INDENT-ON* */

}

static void
vl_api_unbind_uri_t_handler (vl_api_unbind_uri_t * mp)
{
  vl_api_unbind_uri_reply_t *rmp;
  int rv;

  rv = vnet_unbind_uri ((char *) mp->uri, mp->client_index);

  REPLY_MACRO (VL_API_UNBIND_URI_REPLY);
}

static void
vl_api_connect_uri_t_handler (vl_api_connect_uri_t * mp)
{
  vnet_connect_args_t _a, *a = &_a;

  a->uri = (char *) mp->uri;
  a->api_client_index = mp->client_index;
  a->api_context = mp->context;
  a->options = mp->options;
  a->session_cb_vft = &uri_session_cb_vft;
  a->mp = mp;
  vnet_connect_uri (a);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  vl_api_disconnect_session_reply_t *rmp;
  int rv;

  rv = api_session_not_valid (mp->session_index, mp->session_thread_index);
  if (!rv)
    rv = vnet_disconnect_session (mp->client_index, mp->session_index,
				  mp->session_thread_index);

  REPLY_MACRO (VL_API_DISCONNECT_SESSION_REPLY);
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  if (api_session_not_valid (mp->session_index, mp->session_thread_index))
    {
      clib_warning ("Invalid session!");
      return;
    }

  /* Client objected to disconnecting the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  /* Disconnect has been confirmed. Confirm close to transport */
  vnet_disconnect_session (mp->client_index, mp->session_index,
			   mp->session_thread_index);
}

static void
vl_api_reset_session_reply_t_handler (vl_api_reset_session_reply_t * mp)
{
  stream_session_t *s;

  if (api_session_not_valid (mp->session_index, mp->session_thread_index))
    {
      clib_warning ("Invalid session!");
      return;
    }

  /* Client objected to resetting the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  s = stream_session_get (mp->session_index, mp->session_thread_index);

  /* This comes as a response to a reset, transport only waiting for
   * confirmation to remove connection state, no need to disconnect */
  stream_session_cleanup (s);
}

static void
vl_api_accept_session_reply_t_handler (vl_api_accept_session_reply_t * mp)
{
  stream_session_t *s;
  int rv;

  if (api_session_not_valid (mp->session_index, mp->session_thread_index))
    return;

  s = stream_session_get (mp->session_index, mp->session_thread_index);
  rv = mp->retval;

  if (rv)
    {
      /* Server isn't interested, kill the session */
      stream_session_disconnect (s);
      return;
    }

  s->session_state = SESSION_STATE_READY;
}

static void
vl_api_map_another_segment_reply_t_handler (vl_api_map_another_segment_reply_t
					    * mp)
{
  clib_warning ("not implemented");
}

static void
vl_api_bind_sock_t_handler (vl_api_bind_sock_t * mp)
{
  vl_api_bind_sock_reply_t *rmp;
  vnet_bind_args_t _a, *a = &_a;
  char segment_name[128];
  u32 segment_name_length;
  int rv;

  STATIC_ASSERT (sizeof (u64) * SESSION_OPTIONS_N_OPTIONS <=
		 sizeof (mp->options),
		 "Out of options, fix api message definition");

  segment_name_length = ARRAY_LEN (segment_name);

  memset (a, 0, sizeof (*a));

  clib_memcpy (&a->tep.ip, mp->ip,
	       (mp->is_ip4 ? sizeof (ip4_address_t) :
		sizeof (ip6_address_t)));
  a->tep.is_ip4 = mp->is_ip4;
  a->tep.port = mp->port;
  a->tep.vrf = mp->vrf;

  a->api_client_index = mp->client_index;
  a->options = mp->options;
  a->segment_name = segment_name;
  a->segment_name_length = segment_name_length;
  a->session_cb_vft = &session_cb_vft;

  rv = vnet_bind_uri (a);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_BIND_SOCK_REPLY, ({
    rmp->retval = rv;
    if (!rv)
      {
	rmp->segment_name_length = 0;
	rmp->segment_size = mp->options[SESSION_OPTIONS_SEGMENT_SIZE];
	if (segment_name_length)
	  {
	    memcpy(rmp->segment_name, segment_name, segment_name_length);
	    rmp->segment_name_length = segment_name_length;
	  }
	rmp->server_event_queue_address = a->server_event_queue_address;
      }
  }));
  /* *INDENT-ON* */
}

static void
vl_api_unbind_sock_t_handler (vl_api_unbind_sock_t * mp)
{
  vl_api_unbind_sock_reply_t *rmp;
  vnet_unbind_args_t _a, *a = &_a;
  int rv;

  a->api_client_index = mp->client_index;
  a->handle = mp->handle;

  rv = vnet_unbind (a);

  REPLY_MACRO (VL_API_UNBIND_SOCK_REPLY);
}

static void
vl_api_connect_sock_t_handler (vl_api_connect_sock_t * mp)
{
  vnet_connect_args_t _a, *a = &_a;

  clib_memcpy (&a->tep.ip, mp->ip,
	       (mp->is_ip4 ? sizeof (ip4_address_t) :
		sizeof (ip6_address_t)));
  a->tep.is_ip4 = mp->is_ip4;
  a->tep.port = mp->port;
  a->tep.vrf = mp->vrf;
  a->options = mp->options;
  a->session_cb_vft = &session_cb_vft;
  a->api_context = mp->context;
  a->mp = mp;

  vnet_connect (a);
}

static void
vl_api_disconnect_sock_t_handler (vl_api_disconnect_sock_t * mp)
{
  vnet_disconnect_args_t _a, *a = &_a;
  vl_api_disconnect_sock_reply_t *rmp;
  int rv;

  a->api_client_index = mp->client_index;
  a->handle = mp->handle;
  rv = vnet_disconnect (a);

  REPLY_MACRO (VL_API_DISCONNECT_SOCK_REPLY);
}

static void
vl_api_disconnect_sock_reply_t_handler (vl_api_disconnect_sock_reply_t * mp)
{
  vnet_disconnect_args_t _a, *a = &_a;

  /* Client objected to disconnecting the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  a->api_client_index = mp->client_index;
  a->handle = mp->handle;

  vnet_disconnect (a);
}

static void
vl_api_reset_sock_reply_t_handler (vl_api_reset_sock_reply_t * mp)
{
  stream_session_t *s;
  u32 session_index, thread_index;

  /* Client objected to resetting the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  if (api_parse_session_handle (mp->handle, &session_index, &thread_index))
    {
      clib_warning ("Invalid handle");
      return;
    }

  s = stream_session_get (session_index, thread_index);

  /* This comes as a response to a reset, transport only waiting for
   * confirmation to remove connection state, no need to disconnect */
  stream_session_cleanup (s);
}

static void
vl_api_accept_sock_reply_t_handler (vl_api_accept_sock_reply_t * mp)
{
  stream_session_t *s;
  u32 session_index, thread_index;

  if (api_parse_session_handle (mp->handle, &session_index, &thread_index))
    {
      clib_warning ("Invalid handle");
      return;
    }
  s = stream_session_get (session_index, thread_index);

  if (mp->retval)
    {
      /* Server isn't interested, kill the session */
      stream_session_disconnect (s);
      return;
    }

  s->session_state = SESSION_STATE_READY;
}

#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_session;
#undef _
}

/*
 * session_api_hookup
 * Add uri's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../open-repo/vlib/memclnt_vlib.c:memclnt_process()
 */
static clib_error_t *
session_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_session_api_msg;
#undef _

  /*
   * Messages which bounce off the data-plane to
   * an API client. Simply tells the message handling infra not
   * to free the message.
   *
   * Bounced message handlers MUST NOT block the data plane
   */
  am->message_bounce[VL_API_CONNECT_URI] = 1;
  am->message_bounce[VL_API_CONNECT_SOCK] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (session_api_hookup);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
