/*
* Copyright (c) 2015-2017 Cisco and/or its affiliates.
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

typedef struct
{
  u8 *rx_buf;
  unix_shared_memory_queue_t **vpp_queue;
  u64 byte_index;

  uword *handler_by_get_request;

  /* Sever's event queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  u32 app_index;

  /* process node index for evnt scheduling */
  u32 node_index;
  vlib_main_t *vlib_main;
} http_server_main_t;

http_server_main_t http_server_main;

static int
builtin_session_accept_callback (stream_session_t * s)
{
  http_server_main_t *bsm = &http_server_main;

  bsm->vpp_queue[s->thread_index] =
    session_manager_get_vpp_event_queue (s->thread_index);
  s->session_state = SESSION_STATE_READY;
  bsm->byte_index = 0;
  return 0;
}

static void
builtin_session_disconnect_callback (stream_session_t * s)
{
  http_server_main_t *bsm = &http_server_main;
  vnet_disconnect_args_t _a, *a = &_a;

  a->handle = stream_session_handle (s);
  a->app_index = bsm->app_index;
  vnet_disconnect_session (a);
}

static void
builtin_session_reset_callback (stream_session_t * s)
{
  clib_warning ("called.. ");

  stream_session_cleanup (s);
}


static int
builtin_session_connected_callback (u32 app_index, u32 api_context,
				    stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

static int
builtin_add_segment_callback (u32 client_index,
			      const u8 * seg_name, u32 seg_size)
{
  clib_warning ("called...");
  return -1;
}

static int
builtin_redirect_connect_callback (u32 client_index, void *mp)
{
  clib_warning ("called...");
  return -1;
}

static const char
  *http_response = "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/html\r\n"
  "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
  "Connection: close\r\n"
  "Pragma: no-cache\r\n" "Content-Length: %d\r\n\r\n%s";

static const char
  *http_error_template = "HTTP/1.1 %s\r\n"
  "Content-Type: text/html\r\n"
  "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
  "Connection: close\r\n" "Pragma: no-cache\r\n" "Content-Length: 0\r\n\r\n";

static const char
  *html_header_template = "<html><head><title>%s</title></head><body><pre>";

static const char *html_footer = "</pre></body></html>\r\n";

static inline void
send_data (u8 * bytes, stream_session_t * s)
{
  u8 *remaining_output = (u8 *) s->opaque[0];

  vec_append (remaining_output, bytes);
  vec_free (bytes);
  s->opaque[0] = (u64) remaining_output;
}


static void
get_index_handler (stream_session_t * s)
{
  u8 *index_contents;
  u8 *index_page;
  u8 *header;
  u8 *remaining_output = (void *) s->opaque[0];

  header = format (0, html_header_template, "Index");

  index_contents =
    format (0, "This is the Index Page. Eventually make it real.\r\n");

  index_page = format (0, "%s\r\n%v\r\n%s\r\n",
		       header, index_contents, html_footer);

  remaining_output = format (remaining_output, http_response,
			     vec_len (index_page), index_page);

  send_data (remaining_output, s);
  vec_free (header);
  vec_free (index_contents);
  vec_free (index_page);
  vec_free (remaining_output);
}

typedef struct
{
  char *name;
  void *handler;
} get_handler_t;

static const get_handler_t get_request_handlers[] = {
  {"/", get_index_handler},
  {"/index.html", get_index_handler},
  {"/index.htm", get_index_handler},
};


static void
send_more_output (stream_session_t * s)
{
  u8 *remaining_output = (u8 *) s->opaque[0];
  u32 actual_transfer;

  actual_transfer = svm_fifo_enqueue_nowait
    (s->server_tx_fifo, vec_len (remaining_output), remaining_output);

  if (actual_transfer == vec_len (remaining_output))
    {
      vec_free (remaining_output);
      s->opaque[0] = 0;
      return;
    }

  vec_delete (remaining_output, actual_transfer, 0);
  s->opaque[0] = (u64) remaining_output;
}

static void
send_error (char *str, stream_session_t * s)
{
  u8 *remaining_output = (u8 *) s->opaque[0];

  remaining_output = format (remaining_output, http_error_template, str);
  s->opaque[0] = (u64) remaining_output;
}

static int
http_server_rx_callback (stream_session_t * s)
{
  u32 max_dequeue;
  int actual_transfer;
  svm_fifo_t *tx_fifo, *rx_fifo;
  http_server_main_t *bsm = &http_server_main;
  session_fifo_event_t evt;
  static int serial_number = 0;
  u8 *resource;
  u8 *remaining_output;
  u8 *terminator;
  uword *p;
  int i;

  max_dequeue = svm_fifo_max_dequeue (s->server_rx_fifo);

  tx_fifo = s->server_tx_fifo;
  rx_fifo = s->server_rx_fifo;

  /* Not enough space in tx fifo to say "GO AWAY!"? */
  if (PREDICT_FALSE (max_dequeue < 128))
    {
      /* XXX timeout for session that are stuck */

    requeue_rx_event:
      /* Program self-tap to retry */
      if (svm_fifo_set_event (rx_fifo))
	{
	  evt.fifo = rx_fifo;
	  evt.event_type = FIFO_EVENT_BUILTIN_RX;
	  evt.event_id = 0;
	  unix_shared_memory_queue_add (bsm->vpp_queue[s->thread_index],
					(u8 *) & evt,
					0 /* do wait for mutex */ );
	}

      return 0;
    }

  /* See if we're here to continue stuffing the tx fifo */
  remaining_output = (u8 *) s->opaque[0];

  if (remaining_output)
    goto send_output;

  svm_fifo_unset_event (rx_fifo);

  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;

  vec_validate (bsm->rx_buf, max_dequeue - 1);
  _vec_len (bsm->rx_buf) = max_dequeue;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, max_dequeue,
					     bsm->rx_buf);
  ASSERT (actual_transfer > 0);

  _vec_len (bsm->rx_buf) = actual_transfer;

  /*
   * Dig desired resource out of bsm->rx_buf, which should contain
   * "GET /index.html HTTP/1.1" or similar from browser, curl, etc.
   */

  if (vec_len (bsm->rx_buf) < 7)
    {
      send_error ("400 Bad Request", s);
      goto send_output;
    }

  for (i = 0; i < vec_len (bsm->rx_buf) - 4; i++)
    {
      if (bsm->rx_buf[i] == 'G' &&
	  bsm->rx_buf[i + 1] == 'E' &&
	  bsm->rx_buf[i + 2] == 'T' && bsm->rx_buf[i + 3] == ' ')
	{
	  resource = bsm->rx_buf + 4;
	  goto found;
	}
    }
  send_error ("400 Bad Request", s);
  goto send_output;

found:
  for (terminator = resource + 1;
       terminator < bsm->rx_buf + vec_len (bsm->rx_buf); terminator++)
    {
      void (*fp) (stream_session_t * s);

      if (*terminator == ' ')
	{
	  *terminator = 0;
	  p = hash_get_mem (bsm->handler_by_get_request, resource);
	  if (p == 0)
	    {
	      send_error ("404 Not Found", s);
	      goto send_output;
	    }
	  fp = (void *) p[0];
	  (*fp) (s);
	  goto send_output;
	}
    }

  send_error ("400 Bad Request", s);

send_output:
  send_more_output (s);

  if (svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;
      evt.event_id = serial_number++;

      unix_shared_memory_queue_add (bsm->vpp_queue[s->thread_index],
				    (u8 *) & evt, 0 /* do wait for mutex */ );
    }

  remaining_output = (u8 *) s->opaque[0];
  if (remaining_output)
    goto requeue_rx_event;

  return 0;
}

static session_cb_vft_t builtin_session_cb_vft = {
  .session_accept_callback = builtin_session_accept_callback,
  .session_disconnect_callback = builtin_session_disconnect_callback,
  .session_connected_callback = builtin_session_connected_callback,
  .add_segment_callback = builtin_add_segment_callback,
  .redirect_connect_callback = builtin_redirect_connect_callback,
  .builtin_server_rx_callback = http_server_rx_callback,
  .session_reset_callback = builtin_session_reset_callback
};

/* Abuse VPP's input queue */
static int
create_api_loopback (vlib_main_t * vm)
{
  http_server_main_t *bsm = &http_server_main;
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
  bsm->vl_input_queue = shmem_hdr->vl_input_queue;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = VL_API_MEMCLNT_CREATE;
  mp->context = 0xFEEDFACE;
  mp->input_queue = (u64) bsm->vl_input_queue;
  strncpy ((char *) mp->name, "tcp_http_server", sizeof (mp->name) - 1);

  vl_api_memclnt_create_t_handler (mp);

  /* Wait for reply */
  bsm->node_index = vlib_get_current_process (vm)->node_runtime.node_index;
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

static int
server_attach ()
{
  http_server_main_t *bsm = &http_server_main;
  u8 segment_name[128];
  u64 options[SESSION_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->api_client_index = bsm->my_client_index;
  a->session_cb_vft = &builtin_session_cb_vft;
  a->options = options;
  a->options[SESSION_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[SESSION_OPTIONS_RX_FIFO_SIZE] = 8 << 10;
  a->options[SESSION_OPTIONS_TX_FIFO_SIZE] = 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_BUILTIN_APP;
  a->segment_name = segment_name;
  a->segment_name_length = ARRAY_LEN (segment_name);

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  bsm->app_index = a->app_index;
  return 0;
}

static int
server_listen ()
{
  http_server_main_t *bsm = &http_server_main;
  vnet_bind_args_t _a, *a = &_a;
  memset (a, 0, sizeof (*a));
  a->app_index = bsm->app_index;
  a->uri = "tcp://0.0.0.0/80";
  return vnet_bind_uri (a);
}

static int
server_create (vlib_main_t * vm)
{
  http_server_main_t *bsm = &http_server_main;
  u32 num_threads;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();

  if (bsm->my_client_index == (u32) ~ 0)
    {
      if (create_api_loopback (vm))
	return -1;
    }

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (http_server_main.vpp_queue, num_threads - 1);

  if (server_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (server_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }
  return 0;
}

/* Get our api client index */
static void
vl_api_memclnt_create_reply_t_handler (vl_api_memclnt_create_reply_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  http_server_main_t *bsm = &http_server_main;
  bsm->my_client_index = mp->index;
  vlib_process_signal_event (vm, bsm->node_index, 1 /* evt */ ,
			     0 /* data */ );
}

#define foreach_tcp_http_server_api_msg      		\
_(MEMCLNT_CREATE_REPLY, memclnt_create_reply)   		\

static clib_error_t *
tcp_http_server_api_hookup (vlib_main_t * vm)
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

  foreach_tcp_http_server_api_msg;
#undef _

  return 0;
}

static clib_error_t *
server_create_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;

  tcp_http_server_api_hookup (vm);
  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );
  rv = server_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "server_create returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (server_create_command, static) =
{
  .path = "test http server",
  .short_help = "test http server",
  .function = server_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
builtin_http_server_main_init (vlib_main_t * vm)
{
  http_server_main_t *bsm = &http_server_main;
  bsm->my_client_index = ~0;
  int i;

  bsm->handler_by_get_request = hash_create_string (0, sizeof (uword));

  for (i = 0; i < ARRAY_LEN (get_request_handlers); i++)
    {
      hash_set_mem (bsm->handler_by_get_request, get_request_handlers[i].name,
		    get_request_handlers[i].handler);
    }

  return 0;
}

VLIB_INIT_FUNCTION (builtin_http_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
