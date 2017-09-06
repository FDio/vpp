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
_(APPLICATION_ATTACH, application_attach)				\
_(APPLICATION_DETACH, application_detach)				\
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
_(SESSION_ENABLE_DISABLE, session_enable_disable)                   	\

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
send_session_accept_callback (stream_session_t * s)
{
  vl_api_accept_session_t *mp;
  unix_shared_memory_queue_t *q, *vpp_queue;
  application_t *server = application_get (s->app_index);
  transport_connection_t *tc;
  transport_proto_vft_t *tp_vft;
  stream_session_t *listener;

  q = vl_api_client_index_to_input_queue (server->api_client_index);
  vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_ACCEPT_SESSION);
  mp->context = server->index;
  listener = listen_session_get (s->session_type, s->listener_index);
  tp_vft = session_get_transport_vft (s->session_type);
  tc = tp_vft->get_connection (s->connection_index, s->thread_index);
  mp->listener_handle = listen_session_get_handle (listener);
  mp->handle = stream_session_handle (s);
  mp->server_rx_fifo = pointer_to_uword (s->server_rx_fifo);
  mp->server_tx_fifo = pointer_to_uword (s->server_tx_fifo);
  mp->vpp_event_queue_address = pointer_to_uword (vpp_queue);
  mp->port = tc->rmt_port;
  mp->is_ip4 = tc->is_ip4;
  clib_memcpy (&mp->ip, &tc->rmt_ip, sizeof (tc->rmt_ip));
  vl_msg_api_send_shmem (q, (u8 *) & mp);

  return 0;
}

static void
send_session_disconnect_callback (stream_session_t * s)
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
  mp->handle = stream_session_handle (s);
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
send_session_reset_callback (stream_session_t * s)
{
  vl_api_reset_session_t *mp;
  unix_shared_memory_queue_t *q;
  application_t *app = application_get (s->app_index);

  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_RESET_SESSION);
  mp->handle = stream_session_handle (s);
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

int
send_session_connected_callback (u32 app_index, u32 api_context,
				 stream_session_t * s, u8 is_fail)
{
  vl_api_connect_session_reply_t *mp;
  unix_shared_memory_queue_t *q;
  application_t *app;
  unix_shared_memory_queue_t *vpp_queue;

  app = application_get (app_index);
  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_CONNECT_SESSION_REPLY);
  mp->context = api_context;
  if (!is_fail)
    {
      vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);
      mp->server_rx_fifo = pointer_to_uword (s->server_rx_fifo);
      mp->server_tx_fifo = pointer_to_uword (s->server_tx_fifo);
      mp->handle = stream_session_handle (s);
      mp->vpp_event_queue_address = pointer_to_uword (vpp_queue);
      mp->retval = 0;
    }
  else
    {
      mp->retval = clib_host_to_net_u32 (VNET_API_ERROR_SESSION_CONNECT_FAIL);
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
  return 0;
}

/**
 * Redirect a connect_uri message to the indicated server.
 * Only sent if the server has bound the related port with
 * URI_OPTIONS_FLAGS_USE_FIFO
 */
static int
redirect_connect_callback (u32 server_api_client_index, void *mp_arg)
{
  vl_api_connect_uri_t *mp = mp_arg;
  unix_shared_memory_queue_t *server_q, *client_q;
  vlib_main_t *vm = vlib_get_main ();
  f64 timeout = vlib_time_now (vm) + 0.5;
  application_t *app;
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
  mp->client_queue_address = pointer_to_uword (client_q);
  app = application_lookup (mp->client_index);
  if (!app)
    {
      clib_warning ("no client application");
      return -1;
    }

  mp->options[SESSION_OPTIONS_RX_FIFO_SIZE] = app->sm_properties.rx_fifo_size;
  mp->options[SESSION_OPTIONS_TX_FIFO_SIZE] = app->sm_properties.tx_fifo_size;

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
  .session_accept_callback = send_session_accept_callback,
  .session_disconnect_callback = send_session_disconnect_callback,
  .session_connected_callback = send_session_connected_callback,
  .session_reset_callback = send_session_reset_callback,
  .add_segment_callback = send_add_segment_callback,
  .redirect_connect_callback = redirect_connect_callback
};

static void
vl_api_session_enable_disable_t_handler (vl_api_session_enable_disable_t * mp)
{
  vl_api_session_enable_disable_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  vnet_session_enable_disable (vm, mp->is_enable);
  REPLY_MACRO (VL_API_SESSION_ENABLE_DISABLE_REPLY);
}

static void
vl_api_application_attach_t_handler (vl_api_application_attach_t * mp)
{
  vl_api_application_attach_reply_t *rmp;
  vnet_app_attach_args_t _a, *a = &_a;
  int rv;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  STATIC_ASSERT (sizeof (u64) * SESSION_OPTIONS_N_OPTIONS <=
		 sizeof (mp->options),
		 "Out of options, fix api message definition");

  memset (a, 0, sizeof (*a));

  a->api_client_index = mp->client_index;
  a->options = mp->options;
  a->session_cb_vft = &uri_session_cb_vft;

  rv = vnet_application_attach (a);

done:

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_APPLICATION_ATTACH_REPLY, ({
    if (!rv)
      {
	rmp->segment_name_length = 0;
	/* $$$$ policy? */
	rmp->segment_size = a->segment_size;
	if (a->segment_name_length)
	  {
	    memcpy (rmp->segment_name, a->segment_name,
		    a->segment_name_length);
	    rmp->segment_name_length = a->segment_name_length;
	  }
	rmp->app_event_queue_address = a->app_event_queue_address;
      }
  }));
  /* *INDENT-ON* */
}

static void
vl_api_application_detach_t_handler (vl_api_application_detach_t * mp)
{
  vl_api_application_detach_reply_t *rmp;
  int rv = VNET_API_ERROR_INVALID_VALUE_2;
  vnet_app_detach_args_t _a, *a = &_a;
  application_t *app;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->app_index = app->index;
      rv = vnet_application_detach (a);
    }

done:
  REPLY_MACRO (VL_API_APPLICATION_DETACH_REPLY);
}

static void
vl_api_bind_uri_t_handler (vl_api_bind_uri_t * mp)
{
  vl_api_bind_uri_reply_t *rmp;
  vnet_bind_args_t _a, *a = &_a;
  application_t *app;
  int rv;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      memset (a, 0, sizeof (*a));
      a->uri = (char *) mp->uri;
      a->app_index = app->index;
      rv = vnet_bind_uri (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

done:
  REPLY_MACRO (VL_API_BIND_URI_REPLY);
}

static void
vl_api_unbind_uri_t_handler (vl_api_unbind_uri_t * mp)
{
  vl_api_unbind_uri_reply_t *rmp;
  application_t *app;
  vnet_unbind_args_t _a, *a = &_a;
  int rv;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->uri = (char *) mp->uri;
      a->app_index = app->index;
      rv = vnet_unbind_uri (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

done:
  REPLY_MACRO (VL_API_UNBIND_URI_REPLY);
}

static void
vl_api_connect_uri_t_handler (vl_api_connect_uri_t * mp)
{
  vl_api_connect_session_reply_t *rmp;
  vnet_connect_args_t _a, *a = &_a;
  application_t *app;
  int rv;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->uri = (char *) mp->uri;
      a->api_context = mp->context;
      a->app_index = app->index;
      a->mp = mp;
      rv = vnet_connect_uri (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  if (rv == 0 || rv == VNET_CONNECT_REDIRECTED)
    return;

  /* Got some error, relay it */

done:
  /* *INDENT-OFF* */
  REPLY_MACRO (VL_API_CONNECT_SESSION_REPLY);
  /* *INDENT-ON* */
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  vl_api_disconnect_session_reply_t *rmp;
  vnet_disconnect_args_t _a, *a = &_a;
  application_t *app;
  int rv = 0;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->handle = mp->handle;
      a->app_index = app->index;
      rv = vnet_disconnect_session (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

done:
  REPLY_MACRO (VL_API_DISCONNECT_SESSION_REPLY);
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  vnet_disconnect_args_t _a, *a = &_a;
  application_t *app;

  /* Client objected to disconnecting the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  /* Disconnect has been confirmed. Confirm close to transport */
  app = application_lookup (mp->client_index);
  if (app)
    {
      a->handle = mp->handle;
      a->app_index = app->index;
      vnet_disconnect_session (a);
    }
}

static void
vl_api_reset_session_reply_t_handler (vl_api_reset_session_reply_t * mp)
{
  application_t *app;
  stream_session_t *s;
  u32 index, thread_index;

  app = application_lookup (mp->client_index);
  if (!app)
    return;

  stream_session_parse_handle (mp->handle, &index, &thread_index);
  s = stream_session_get_if_valid (index, thread_index);
  if (s == 0 || app->index != s->app_index)
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

  /* This comes as a response to a reset, transport only waiting for
   * confirmation to remove connection state, no need to disconnect */
  stream_session_cleanup (s);
}

static void
vl_api_accept_session_reply_t_handler (vl_api_accept_session_reply_t * mp)
{
  stream_session_t *s;
  u32 session_index, thread_index;
  vnet_disconnect_args_t _a, *a = &_a;

  /* Server isn't interested, kill the session */
  if (mp->retval)
    {
      a->app_index = mp->context;
      a->handle = mp->handle;
      vnet_disconnect_session (a);
    }
  else
    {
      stream_session_parse_handle (mp->handle, &session_index, &thread_index);
      s = stream_session_get_if_valid (session_index, thread_index);
      if (!s)
	{
	  clib_warning ("session doesn't exist");
	  return;
	}
      if (s->app_index != mp->context)
	{
	  clib_warning ("app doesn't own session");
	  return;
	}
      /* XXX volatile? */
      s->session_state = SESSION_STATE_READY;
    }
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
  int rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
  application_t *app;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      ip46_address_t *ip46 = (ip46_address_t *) mp->ip;

      memset (a, 0, sizeof (*a));
      a->tep.is_ip4 = mp->is_ip4;
      a->tep.ip = *ip46;
      a->tep.port = mp->port;
      a->tep.vrf = mp->vrf;
      a->app_index = app->index;

      rv = vnet_bind (a);
    }
done:
  REPLY_MACRO (VL_API_BIND_SOCK_REPLY);
}

static void
vl_api_unbind_sock_t_handler (vl_api_unbind_sock_t * mp)
{
  vl_api_unbind_sock_reply_t *rmp;
  vnet_unbind_args_t _a, *a = &_a;
  application_t *app;
  int rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->app_index = mp->client_index;
      a->handle = mp->handle;
      rv = vnet_unbind (a);
    }

done:
  REPLY_MACRO (VL_API_UNBIND_SOCK_REPLY);
}

static void
vl_api_connect_sock_t_handler (vl_api_connect_sock_t * mp)
{
  vl_api_connect_session_reply_t *rmp;
  vnet_connect_args_t _a, *a = &_a;
  application_t *app;
  int rv;

  if (session_manager_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      unix_shared_memory_queue_t *client_q;
      ip46_address_t *ip46 = (ip46_address_t *) mp->ip;

      client_q = vl_api_client_index_to_input_queue (mp->client_index);
      mp->client_queue_address = pointer_to_uword (client_q);
      a->tep.is_ip4 = mp->is_ip4;
      a->tep.ip = *ip46;
      a->tep.port = mp->port;
      a->tep.vrf = mp->vrf;
      a->api_context = mp->context;
      a->app_index = app->index;
      a->proto = mp->proto;
      a->mp = mp;
      rv = vnet_connect (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  if (rv == 0 || rv == VNET_CONNECT_REDIRECTED)
    return;

  /* Got some error, relay it */

done:
  REPLY_MACRO (VL_API_CONNECT_SESSION_REPLY);
}

static clib_error_t *
application_reaper_cb (u32 client_index)
{
  application_t *app = application_lookup (client_index);
  vnet_app_detach_args_t _a, *a = &_a;
  if (app)
    {
      a->app_index = app->index;
      vnet_application_detach (a);
    }
  return 0;
}

VL_MSG_API_REAPER_FUNCTION (application_reaper_cb);

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
