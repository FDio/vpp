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
#include <vnet/session/application_interface.h>
#include <vnet/session/session_rules_table.h>
#include <vnet/session/session_table.h>

#include <vnet/vnet_msg_enum.h>

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
_(BIND_SOCK, bind_sock)							\
_(UNBIND_SOCK, unbind_sock)                                             \
_(CONNECT_SOCK, connect_sock)                                          	\
_(SESSION_ENABLE_DISABLE, session_enable_disable)                   	\
_(APP_NAMESPACE_ADD_DEL, app_namespace_add_del)				\
_(SESSION_RULE_ADD_DEL, session_rule_add_del)				\
_(SESSION_RULES_DUMP, session_rules_dump)				\

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
  tp_vft = transport_protocol_get_vft (s->session_type);
  tc = tp_vft->get_connection (s->connection_index, s->thread_index);
  mp->listener_handle = listen_session_get_handle (listener);
  mp->handle = session_handle (s);
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
  mp->handle = session_handle (s);
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
  mp->handle = session_handle (s);
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
  transport_connection_t *tc;

  app = application_get (app_index);
  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return -1;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_CONNECT_SESSION_REPLY);
  mp->context = api_context;

  if (is_fail)
    goto done;

  tc = session_get_transport (s);
  if (!tc)
    {
      is_fail = 1;
      goto done;
    }

  vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);
  mp->server_rx_fifo = pointer_to_uword (s->server_rx_fifo);
  mp->server_tx_fifo = pointer_to_uword (s->server_tx_fifo);
  mp->handle = session_handle (s);
  mp->vpp_event_queue_address = pointer_to_uword (vpp_queue);
  clib_memcpy (mp->lcl_ip, &tc->lcl_ip, sizeof (tc->lcl_ip));
  mp->is_ip4 = tc->is_ip4;
  mp->lcl_port = tc->lcl_port;

done:
  mp->retval = is_fail ?
    clib_host_to_net_u32 (VNET_API_ERROR_SESSION_CONNECT) : 0;
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
  vl_api_connect_sock_t *mp = mp_arg;
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
	  return VNET_API_ERROR_SESSION_REDIRECT;

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

static session_cb_vft_t session_cb_vft = {
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
  clib_error_t *error = 0;
  int rv = 0;

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
  a->session_cb_vft = &session_cb_vft;

  if (mp->namespace_id_len > 64)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if (mp->namespace_id_len)
    {
      vec_validate (a->namespace_id, mp->namespace_id_len - 1);
      clib_memcpy (a->namespace_id, mp->namespace_id, mp->namespace_id_len);
    }

  if ((error = vnet_application_attach (a)))
    {
      rv = clib_error_get_code (error);
      clib_error_report (error);
    }
  vec_free (a->namespace_id);

done:

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_APPLICATION_ATTACH_REPLY, ({
    if (!rv)
      {
	rmp->segment_name_length = 0;
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
  clib_error_t *error = 0;
  int rv = 0;

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
      if ((error = vnet_connect_uri (a)))
	{
	  rv = clib_error_get_code (error);
	  if (rv != VNET_API_ERROR_SESSION_REDIRECT)
	    clib_error_report (error);
	}
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  /*
   * Don't reply to stream (tcp) connects. The reply will come once
   * the connection is established. In case of the redirects, the reply
   * will come from the server app.
   */
  if (rv == 0 || rv == VNET_API_ERROR_SESSION_REDIRECT)
    return;

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

  session_parse_handle (mp->handle, &index, &thread_index);
  s = session_get_if_valid (index, thread_index);
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
      session_parse_handle (mp->handle, &session_index, &thread_index);
      s = session_get_if_valid (session_index, thread_index);
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
  int rv = 0;
  clib_error_t *error;
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
      a->sep.is_ip4 = mp->is_ip4;
      a->sep.ip = *ip46;
      a->sep.port = mp->port;
      a->sep.fib_index = mp->vrf;
      a->sep.sw_if_index = ENDPOINT_INVALID_INDEX;
      a->sep.transport_proto = mp->proto;
      a->app_index = app->index;

      if ((error = vnet_bind (a)))
	{
	  rv = clib_error_get_code (error);
	  clib_error_report (error);
	}
    }
done:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_BIND_SOCK_REPLY,({
    if (!rv)
      rmp->handle = a->handle;
  }));
  /* *INDENT-ON* */
}

static void
vl_api_unbind_sock_t_handler (vl_api_unbind_sock_t * mp)
{
  vl_api_unbind_sock_reply_t *rmp;
  vnet_unbind_args_t _a, *a = &_a;
  application_t *app;
  clib_error_t *error;
  int rv = 0;

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
      if ((error = vnet_unbind (a)))
	{
	  rv = clib_error_get_code (error);
	  clib_error_report (error);
	}
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
  clib_error_t *error = 0;
  int rv = 0;

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
      a->sep.is_ip4 = mp->is_ip4;
      a->sep.ip = *ip46;
      a->sep.port = mp->port;
      a->sep.transport_proto = mp->proto;
      a->sep.fib_index = mp->vrf;
      a->sep.sw_if_index = ENDPOINT_INVALID_INDEX;
      a->api_context = mp->context;
      a->app_index = app->index;
      a->mp = mp;
      if ((error = vnet_connect (a)))
	{
	  rv = clib_error_get_code (error);
	  if (rv != VNET_API_ERROR_SESSION_REDIRECT)
	    clib_error_report (error);
	}
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  if (rv == 0 || rv == VNET_API_ERROR_SESSION_REDIRECT)
    return;

  /* Got some error, relay it */

done:
  REPLY_MACRO (VL_API_CONNECT_SESSION_REPLY);
}

static void
vl_api_app_namespace_add_del_t_handler (vl_api_app_namespace_add_del_t * mp)
{
  vl_api_app_namespace_add_del_reply_t *rmp;
  u8 *ns_id = 0;
  clib_error_t *error = 0;
  int rv = 0;
  if (!session_manager_is_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  if (mp->namespace_id_len > ARRAY_LEN (mp->namespace_id))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  vec_validate (ns_id, mp->namespace_id_len - 1);
  clib_memcpy (ns_id, mp->namespace_id, mp->namespace_id_len);
  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .secret = clib_net_to_host_u64 (mp->secret),
    .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
    .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
    .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&args);
  if (error)
    {
      rv = clib_error_get_code (error);
      clib_error_report (error);
    }
  vec_free (ns_id);
done:
  REPLY_MACRO (VL_API_APP_NAMESPACE_ADD_DEL_REPLY);
}

static void
vl_api_session_rule_add_del_t_handler (vl_api_session_rule_add_del_t * mp)
{
  vl_api_session_rule_add_del_reply_t *rmp;
  session_rule_add_del_args_t args;
  session_rule_table_add_del_args_t *table_args = &args.table_args;
  clib_error_t *error;
  u8 fib_proto;
  int rv = 0;

  memset (&args, 0, sizeof (args));
  fib_proto = mp->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  table_args->lcl.fp_len = mp->lcl_plen;
  table_args->lcl.fp_proto = fib_proto;
  table_args->rmt.fp_len = mp->rmt_plen;
  table_args->rmt.fp_proto = fib_proto;
  table_args->lcl_port = clib_net_to_host_u16 (mp->lcl_port);
  table_args->rmt_port = clib_net_to_host_u16 (mp->rmt_port);
  table_args->action_index = clib_net_to_host_u32 (mp->action_index);
  table_args->is_add = mp->is_add;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  table_args->tag = format (0, "%s", mp->tag);
  args.appns_index = clib_net_to_host_u32 (mp->appns_index);
  args.scope = mp->scope;

  memset (&table_args->lcl.fp_addr, 0, sizeof (table_args->lcl.fp_addr));
  memset (&table_args->rmt.fp_addr, 0, sizeof (table_args->rmt.fp_addr));
  ip_set (&table_args->lcl.fp_addr, mp->lcl_ip, mp->is_ip4);
  ip_set (&table_args->rmt.fp_addr, mp->rmt_ip, mp->is_ip4);
  error = vnet_session_rule_add_del (&args);
  if (error)
    {
      rv = clib_error_get_code (error);
      clib_error_report (error);
    }
  vec_free (table_args->tag);
  REPLY_MACRO (VL_API_SESSION_RULE_ADD_DEL_REPLY);
}

static void
send_session_rule_details4 (mma_rule_16_t * rule, u8 is_local,
			    u8 transport_proto, u32 appns_index, u8 * tag,
			    unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_session_rules_details_t *rmp = 0;
  session_mask_or_match_4_t *match =
    (session_mask_or_match_4_t *) & rule->match;
  session_mask_or_match_4_t *mask =
    (session_mask_or_match_4_t *) & rule->mask;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  rmp->is_ip4 = 1;
  clib_memcpy (rmp->lcl_ip, &match->lcl_ip, sizeof (match->lcl_ip));
  clib_memcpy (rmp->rmt_ip, &match->rmt_ip, sizeof (match->rmt_ip));
  rmp->lcl_plen = ip4_mask_to_preflen (&mask->lcl_ip);
  rmp->rmt_plen = ip4_mask_to_preflen (&mask->rmt_ip);
  rmp->lcl_port = clib_host_to_net_u16 (match->lcl_port);
  rmp->rmt_port = clib_host_to_net_u16 (match->rmt_port);
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope =
    is_local ? SESSION_RULE_SCOPE_LOCAL : SESSION_RULE_SCOPE_GLOBAL;
  rmp->transport_proto = transport_proto;
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
send_session_rule_details6 (mma_rule_40_t * rule, u8 is_local,
			    u8 transport_proto, u32 appns_index, u8 * tag,
			    unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_session_rules_details_t *rmp = 0;
  session_mask_or_match_6_t *match =
    (session_mask_or_match_6_t *) & rule->match;
  session_mask_or_match_6_t *mask =
    (session_mask_or_match_6_t *) & rule->mask;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  rmp->is_ip4 = 0;
  clib_memcpy (rmp->lcl_ip, &match->lcl_ip, sizeof (match->lcl_ip));
  clib_memcpy (rmp->rmt_ip, &match->rmt_ip, sizeof (match->rmt_ip));
  rmp->lcl_plen = ip6_mask_to_preflen (&mask->lcl_ip);
  rmp->rmt_plen = ip6_mask_to_preflen (&mask->rmt_ip);
  rmp->lcl_port = clib_host_to_net_u16 (match->lcl_port);
  rmp->rmt_port = clib_host_to_net_u16 (match->rmt_port);
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope =
    is_local ? SESSION_RULE_SCOPE_LOCAL : SESSION_RULE_SCOPE_GLOBAL;
  rmp->transport_proto = transport_proto;
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
send_session_rules_table_details (session_rules_table_t * srt, u8 fib_proto,
				  u8 tp, u8 is_local, u32 appns_index,
				  unix_shared_memory_queue_t * q, u32 context)
{
  mma_rule_16_t *rule16;
  mma_rule_40_t *rule40;
  mma_rules_table_16_t *srt16;
  mma_rules_table_40_t *srt40;
  u32 ri;

  if (is_local || fib_proto == FIB_PROTOCOL_IP4)
    {
      u8 *tag = 0;
      /* *INDENT-OFF* */
      srt16 = &srt->session_rules_tables_16;
      pool_foreach (rule16, srt16->rules, ({
	ri = mma_rules_table_rule_index_16 (srt16, rule16);
	tag = session_rules_table_rule_tag (srt, ri, 1);
        send_session_rule_details4 (rule16, is_local, tp, appns_index, tag,
                                    q, context);
      }));
      /* *INDENT-ON* */
    }
  if (is_local || fib_proto == FIB_PROTOCOL_IP6)
    {
      u8 *tag = 0;
      /* *INDENT-OFF* */
      srt40 = &srt->session_rules_tables_40;
      pool_foreach (rule40, srt40->rules, ({
	ri = mma_rules_table_rule_index_40 (srt40, rule40);
	tag = session_rules_table_rule_tag (srt, ri, 1);
        send_session_rule_details6 (rule40, is_local, tp, appns_index, tag,
                                    q, context);
      }));
      /* *INDENT-ON* */
    }
}

static void
vl_api_session_rules_dump_t_handler (vl_api_one_map_server_dump_t * mp)
{
  unix_shared_memory_queue_t *q = NULL;
  session_table_t *st;
  u8 tp;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  session_table_foreach (st, ({
    for (tp = 0; tp < TRANSPORT_N_PROTO; tp++)
      {
        send_session_rules_table_details (&st->session_rules[tp],
                                          st->active_fib_proto, tp,
                                          st->is_local, st->appns_index, q,
                                          mp->context);
      }
  }));
  /* *INDENT-ON* */
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
