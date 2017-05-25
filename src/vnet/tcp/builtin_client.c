/*
 * builtin_client.c - vpp built-in tcp client/connect code
 *
 * Copyright (c) 2017 by Cisco and/or its affiliates.
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
#include <vnet/plugin/plugin.h>
#include <vnet/tcp/builtin_client.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <vpp/api/vpe_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

#define TCP_BUILTIN_CLIENT_DBG (1)

static void
send_test_chunk (tclient_main_t * tm, session_t * s)
{
  u8 *test_data = tm->connect_test_data;
  int test_buf_offset;
  u32 bytes_this_chunk;
  session_fifo_event_t evt;
  static int serial_number = 0;
  int rv;

  ASSERT (vec_len (test_data) > 0);

  test_buf_offset = s->bytes_sent % vec_len (test_data);
  bytes_this_chunk = vec_len (test_data) - test_buf_offset;

  bytes_this_chunk = bytes_this_chunk < s->bytes_to_send
    ? bytes_this_chunk : s->bytes_to_send;

  rv = svm_fifo_enqueue_nowait (s->server_tx_fifo, bytes_this_chunk,
				test_data + test_buf_offset);

  /* If we managed to enqueue data... */
  if (rv > 0)
    {
      /* Account for it... */
      s->bytes_to_send -= rv;
      s->bytes_sent += rv;

      if (TCP_BUILTIN_CLIENT_DBG)
	{
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (e) =
            {
              .format = "tx-enq: xfer %d bytes, sent %u remain %u",
              .format_args = "i4i4i4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 data[3];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = rv;
	  ed->data[1] = s->bytes_sent;
	  ed->data[2] = s->bytes_to_send;
	}

      /* Poke the TCP state machine */
      if (svm_fifo_set_event (s->server_tx_fifo))
	{
	  /* Fabricate TX event, send to vpp */
	  evt.fifo = s->server_tx_fifo;
	  evt.event_type = FIFO_EVENT_APP_TX;
	  evt.event_id = serial_number++;

	  unix_shared_memory_queue_add (tm->vpp_event_queue, (u8 *) & evt,
					0 /* do wait for mutex */ );
	}
    }
}

static void
receive_test_chunk (tclient_main_t * tm, session_t * s)
{
  svm_fifo_t *rx_fifo = s->server_rx_fifo;
  int n_read, test_bytes = 0;

  /* Allow enqueuing of new event */
  // svm_fifo_unset_event (rx_fifo);

  if (test_bytes)
    {
      n_read = svm_fifo_dequeue_nowait (rx_fifo, vec_len (tm->rx_buf),
					tm->rx_buf);
    }
  else
    {
      n_read = svm_fifo_max_dequeue (rx_fifo);
      svm_fifo_dequeue_drop (rx_fifo, n_read);
    }

  if (n_read > 0)
    {
      if (TCP_BUILTIN_CLIENT_DBG)
	{
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (e) =
            {
              .format = "rx-deq: %d bytes",
              .format_args = "i4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 data[1];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = n_read;
	}

      if (test_bytes)
	{
	  int i;
	  for (i = 0; i < n_read; i++)
	    {
	      if (tm->rx_buf[i] != ((s->bytes_received + i) & 0xff))
		{
		  clib_warning ("read %d error at byte %lld, 0x%x not 0x%x",
				n_read, s->bytes_received + i, tm->rx_buf[i],
				((s->bytes_received + i) & 0xff));
		}
	    }
	}
      s->bytes_to_receive -= n_read;
      s->bytes_received += n_read;
    }
}

static uword
builtin_client_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame)
{
  tclient_main_t *tm = &tclient_main;
  int my_thread_index = vlib_get_thread_index ();
  vl_api_disconnect_session_t *dmp;
  session_t *sp;
  int i;
  int delete_session;
  u32 *connection_indices;
  u32 tx_quota = 0;
  u32 delta, prev_bytes_received_this_session;

  connection_indices = tm->connection_index_by_thread[my_thread_index];

  if (tm->run_test == 0 || vec_len (connection_indices) == 0)
    return 0;

  for (i = 0; i < vec_len (connection_indices); i++)
    {
      delete_session = 1;

      sp = pool_elt_at_index (tm->sessions, connection_indices[i]);

      if (tx_quota < 60 && sp->bytes_to_send > 0)
	{
	  send_test_chunk (tm, sp);
	  delete_session = 0;
	  tx_quota++;
	}
      if (sp->bytes_to_receive > 0)
	{
	  prev_bytes_received_this_session = sp->bytes_received;
	  receive_test_chunk (tm, sp);
	  delta = sp->bytes_received - prev_bytes_received_this_session;
	  if (delta > 0)
	    tx_quota--;
	  delete_session = 0;
	}
      if (PREDICT_FALSE (delete_session == 1))
	{
	  __sync_fetch_and_add (&tm->rx_total, sp->bytes_received);
	  dmp = vl_msg_api_alloc_as_if_client (sizeof (*dmp));
	  memset (dmp, 0, sizeof (*dmp));
	  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
	  dmp->client_index = tm->my_client_index;
	  dmp->handle = sp->vpp_session_handle;
//        vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & dmp);
	  if (!unix_shared_memory_queue_add (tm->vl_input_queue, (u8 *) & dmp,
					     1))
	    {
	      vec_delete (connection_indices, 1, i);
	      tm->connection_index_by_thread[my_thread_index] =
		connection_indices;
	      __sync_fetch_and_add (&tm->ready_connections, -1);
	    }
	  else
	    {
	      vl_msg_api_free (dmp);
	    }

	  /* Kick the debug CLI process */
	  if (tm->ready_connections == 0)
	    {
	      tm->test_end_time = vlib_time_now (vm);
	      vlib_process_signal_event (vm, tm->cli_node_index,
					 2, 0 /* data */ );
	    }
	}
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (builtin_client_node) =
{
  .function = builtin_client_node_fn,
  .name = "builtin-tcp-client",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */


/* So we don't get "no handler for... " msgs */
static void
vl_api_memclnt_create_reply_t_handler (vl_api_memclnt_create_reply_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  tclient_main_t *tm = &tclient_main;
  tm->my_client_index = mp->index;
  vlib_process_signal_event (vm, tm->node_index, 1 /* evt */ ,
			     0 /* data */ );
}

static void
vl_api_connect_uri_reply_t_handler (vl_api_connect_uri_reply_t * mp)
{
  tclient_main_t *tm = &tclient_main;
  session_t *session;
  u32 session_index;
  i32 retval = /* clib_net_to_host_u32 ( */ mp->retval /*) */ ;
  int i;

  if (retval < 0)
    {
      clib_warning ("connection failed: retval %d", retval);
      return;
    }

  tm->our_event_queue =
    uword_to_pointer (mp->vpp_event_queue_address,
		      unix_shared_memory_queue_t *);
  tm->vpp_event_queue =
    uword_to_pointer (mp->vpp_event_queue_address,
		      unix_shared_memory_queue_t *);

  /*
   * Setup session
   */
  pool_get (tm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - tm->sessions;
  session->bytes_to_receive = session->bytes_to_send = tm->bytes_to_send;

  session->server_rx_fifo =
    uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  session->server_rx_fifo->client_session_index = session_index;
  session->server_tx_fifo =
    uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  session->server_tx_fifo->client_session_index = session_index;
  session->vpp_session_handle = mp->handle;

  /* Add it to the session lookup table */
  hash_set (tm->session_index_by_vpp_handles, mp->handle, session_index);

  if (tm->ready_connections == tm->expected_connections - 1)
    {
      vlib_thread_main_t *thread_main = vlib_get_thread_main ();
      int thread_index;

      thread_index = 0;
      for (i = 0; i < pool_elts (tm->sessions); i++)
	{
	  vec_add1 (tm->connection_index_by_thread[thread_index], i);
	  thread_index++;
	  if (thread_index == thread_main->n_vlib_mains)
	    thread_index = 0;
	}
    }
  __sync_fetch_and_add (&tm->ready_connections, 1);
  if (tm->ready_connections == tm->expected_connections)
    {
      tm->run_test = 1;
      tm->test_start_time = vlib_time_now (tm->vlib_main);
      /* Signal the CLI process that the action is starting... */
      vlib_process_signal_event (tm->vlib_main, tm->cli_node_index,
				 1, 0 /* data */ );
    }
}

static int
create_api_loopback (tclient_main_t * tm)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_memclnt_create_t _m, *mp = &_m;
  extern void vl_api_memclnt_create_t_handler (vl_api_memclnt_create_t *);
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;
  uword *event_data = 0, event_type;
  int resolved = 0;

  /*
   * Create a "loopback" API client connection
   * Don't do things like this unless you know what you're doing...
   */

  shmem_hdr = am->shmem_hdr;
  tm->vl_input_queue = shmem_hdr->vl_input_queue;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = VL_API_MEMCLNT_CREATE;
  mp->context = 0xFEEDFACE;
  mp->input_queue = pointer_to_uword (tm->vl_input_queue);
  strncpy ((char *) mp->name, "tcp_tester", sizeof (mp->name) - 1);

  vl_api_memclnt_create_t_handler (mp);

  /* Wait for reply */
  tm->node_index = vlib_get_current_process (vm)->node_runtime.node_index;
  vlib_process_wait_for_event_or_clock (vm, 1.0);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case 1:
      resolved = 1;
      break;
    case ~0:
      /* timed out */
      break;
    default:
      clib_warning ("unknown event_type %d", event_type);
    }
  if (!resolved)
    return -1;
  return 0;
}

#define foreach_tclient_static_api_msg       	\
_(MEMCLNT_CREATE_REPLY, memclnt_create_reply)   \
_(CONNECT_URI_REPLY, connect_uri_reply)

static clib_error_t *
tclient_api_hookup (vlib_main_t * vm)
{
  vl_msg_api_msg_config_t _c, *c = &_c;

  /* Hook up client-side static APIs to our handlers */
#define _(N,n) do {                                             \
    c->id = VL_API_##N;                                         \
    c->name = #n;                                               \
    c->handler = vl_api_##n##_t_handler;                        \
    c->cleanup = vl_noop_handler;                               \
    c->endian = vl_api_##n##_t_endian;                          \
    c->print = vl_api_##n##_t_print;                            \
    c->size = sizeof(vl_api_##n##_t);                           \
    c->traced = 1; /* trace, so these msgs print */             \
    c->replay = 0; /* don't replay client create/delete msgs */ \
    c->message_bounce = 0; /* don't bounce this message */	\
    vl_msg_api_config(c);} while (0);

  foreach_tclient_static_api_msg;
#undef _

  return 0;
}

static int
tcp_test_clients_init (vlib_main_t * vm)
{
  tclient_main_t *tm = &tclient_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  int i;

  tclient_api_hookup (vm);
  if (create_api_loopback (tm))
    return -1;

  /* Init test data */
  vec_validate (tm->connect_test_data, 64 * 1024 - 1);
  for (i = 0; i < vec_len (tm->connect_test_data); i++)
    tm->connect_test_data[i] = i & 0xff;

  tm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  vec_validate (tm->rx_buf, vec_len (tm->connect_test_data) - 1);

  tm->is_init = 1;
  tm->vlib_main = vm;

  vec_validate (tm->connection_index_by_thread, thread_main->n_vlib_mains);
  return 0;
}

static int
builtin_session_connected_callback (u32 app_index, u32 api_context,
				    stream_session_t * s, u8 is_fail)
{
  vl_api_connect_uri_reply_t _m, *mp = &_m;
  unix_shared_memory_queue_t *q;
  application_t *app;
  unix_shared_memory_queue_t *vpp_queue;

  app = application_get (app_index);
  q = vl_api_client_index_to_input_queue (app->api_client_index);

  if (!q)
    return -1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_CONNECT_URI_REPLY);
  mp->context = api_context;
  if (!is_fail)
    {
      vpp_queue = session_manager_get_vpp_event_queue (s->thread_index);
      mp->server_rx_fifo = pointer_to_uword (s->server_rx_fifo);
      mp->server_tx_fifo = pointer_to_uword (s->server_tx_fifo);
      mp->handle = stream_session_handle (s);
      mp->vpp_event_queue_address = pointer_to_uword (vpp_queue);
      mp->retval = 0;
      s->session_state = SESSION_STATE_READY;
    }
  else
    {
      mp->retval = clib_host_to_net_u32 (VNET_API_ERROR_SESSION_CONNECT_FAIL);
    }

  vl_api_connect_uri_reply_t_handler (mp);

  return 0;
}

static void
builtin_session_reset_callback (stream_session_t * s)
{
  return;
}

static int
builtin_session_create_callback (stream_session_t * s)
{
  return 0;
}

static void
builtin_session_disconnect_callback (stream_session_t * s)
{
  return;
}

static int
builtin_server_rx_callback (stream_session_t * s)
{
  return 0;
}

/* *INDENT-OFF* */
static session_cb_vft_t builtin_clients =
  {
    .session_reset_callback = builtin_session_reset_callback,
    .session_connected_callback = builtin_session_connected_callback,
    .session_accept_callback = builtin_session_create_callback,
    .session_disconnect_callback = builtin_session_disconnect_callback,
    .builtin_server_rx_callback = builtin_server_rx_callback
  };
/* *INDENT-ON* */

static int
attach_builtin_test_clients ()
{
  tclient_main_t *tm = &tclient_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u8 segment_name[128];
  u32 segment_name_length;
  u64 options[16];

  segment_name_length = ARRAY_LEN (segment_name);

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->api_client_index = tm->my_client_index;
  a->segment_name = segment_name;
  a->segment_name_length = segment_name_length;
  a->session_cb_vft = &builtin_clients;

  options[SESSION_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  options[SESSION_OPTIONS_SEGMENT_SIZE] = (2 << 30);	/*$$$$ config / arg */
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_BUILTIN_APP;

  a->options = options;

  return vnet_application_attach (a);
}

static clib_error_t *
test_tcp_clients_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  tclient_main_t *tm = &tclient_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  uword *event_data = 0;
  uword event_type;
  u8 *connect_uri = (u8 *) "tcp://6.0.1.1/1234";
  u8 *uri;
  u32 n_clients = 1;
  int i;
  u64 tmp;
  f64 cli_timeout = 20.0;
  f64 delta;

  tm->bytes_to_send = 8192;
  vec_free (tm->connect_uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "nclients %d", &n_clients))
	;
      else if (unformat (input, "mbytes %lld", &tmp))
	tm->bytes_to_send = tmp << 20;
      else if (unformat (input, "gbytes %lld", &tmp))
	tm->bytes_to_send = tmp << 30;
      else if (unformat (input, "bytes %lld", &tm->bytes_to_send))
	;
      else if (unformat (input, "uri %s", &tm->connect_uri))
	;
      else if (unformat (input, "cli-timeout %f", &cli_timeout))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (tm->is_init == 0)
    {
      if (tcp_test_clients_init (vm))
	return clib_error_return (0, "failed init");
    }

  tm->ready_connections = 0;
  tm->expected_connections = n_clients;
  tm->rx_total = 0;

  uri = connect_uri;
  if (tm->connect_uri)
    uri = tm->connect_uri;

#if TCP_BUILTIN_CLIENT_PTHREAD
  /* Start a transmit thread */
  if (tm->client_thread_handle == 0)
    {
      int rv = pthread_create (&tm->client_thread_handle,
			       NULL /*attr */ ,
			       tclient_thread_fn, 0);
      if (rv)
	{
	  tm->client_thread_handle = 0;
	  return clib_error_return (0, "pthread_create returned %d", rv);
	}
    }
#endif
  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );
  if (tm->test_client_attached == 0)
    attach_builtin_test_clients ();
  tm->test_client_attached = 1;

  /* Turn on the builtin client input nodes */
  for (i = 0; i < thread_main->n_vlib_mains; i++)
    vlib_node_set_state (vlib_mains[i], builtin_client_node.index,
			 VLIB_NODE_STATE_POLLING);

  tm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;

  /* Fire off connect requests */
  for (i = 0; i < n_clients; i++)
    {
      vl_api_connect_uri_t _cmp, *cmp = &_cmp;
      void vl_api_connect_uri_t_handler (vl_api_connect_uri_t * cmp);

      memset (cmp, 0, sizeof (*cmp));

      cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
      cmp->client_index = tm->my_client_index;
      cmp->context = ntohl (0xfeedface);
      memcpy (cmp->uri, uri, strlen ((char *) uri) + 1);

      vl_api_connect_uri_t_handler (cmp);
      /* Crude pacing for call setups, 100k/sec  */
      vlib_process_suspend (vm, 10e-6);
    }

  /* Park until the sessions come up, or ten seconds elapse... */
  vlib_process_wait_for_event_or_clock (vm, 10.0 /* timeout, seconds */ );
  event_type = vlib_process_get_events (vm, &event_data);

  switch (event_type)
    {
    case ~0:
      vlib_cli_output (vm, "Timeout with only %d sessions active...",
		       tm->ready_connections);
      goto cleanup;

    case 1:
      vlib_cli_output (vm, "Test started at %.6f", tm->test_start_time);
      break;

    default:
      vlib_cli_output (vm, "unexpected event(1): %d", event_type);
      goto cleanup;
    }

  /* Now wait for the sessions to finish... */
  vlib_process_wait_for_event_or_clock (vm, cli_timeout);
  event_type = vlib_process_get_events (vm, &event_data);

  switch (event_type)
    {
    case ~0:
      vlib_cli_output (vm, "Timeout with %d sessions still active...",
		       tm->ready_connections);
      goto cleanup;

    case 2:
      vlib_cli_output (vm, "Test finished at %.6f", tm->test_end_time);
      break;

    default:
      vlib_cli_output (vm, "unexpected event(2): %d", event_type);
      goto cleanup;
    }

  delta = tm->test_end_time - tm->test_start_time;

  if (delta != 0.0)
    {
      vlib_cli_output (vm,
		       "%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds",
		       tm->rx_total, tm->rx_total / (1ULL << 20),
		       tm->rx_total / (1ULL << 30), delta);
      vlib_cli_output (vm, "%.2f bytes/second full-duplex",
		       ((f64) tm->rx_total) / (delta));
      vlib_cli_output (vm, "%.4f gbit/second full-duplex",
		       (((f64) tm->rx_total * 8.0) / delta / 1e9));
    }
  else
    vlib_cli_output (vm, "zero delta-t?");

cleanup:
  pool_free (tm->sessions);
  for (i = 0; i < vec_len (tm->connection_index_by_thread); i++)
    vec_reset_length (tm->connection_index_by_thread[i]);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_clients_command, static) =
{
  .path = "test tcp clients",
  .short_help = "test tcp clients [nclients %d]"
  "[iterations %d] [bytes %d] [uri tcp://6.0.1.1/1234]",
  .function = test_tcp_clients_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
tcp_test_clients_main_init (vlib_main_t * vm)
{
  tclient_main_t *tm = &tclient_main;
  tm->is_init = 0;
  return 0;
}

VLIB_INIT_FUNCTION (tcp_test_clients_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
