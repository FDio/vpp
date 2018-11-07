/*
* Copyright (c) 2018 Travelping GmbH
*
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

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <vnet/vnet.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

#include "upf.h"
#include "upf_pfcp.h"
#include "upf_pfcp_api.h"
#include "upf_http_redirect_server.h"

typedef enum
{
  EVENT_WAKEUP = 1,
} http_process_event_t;

http_redirect_server_main_t http_redirect_server_main;

static const char *http_redirect_template =
  "HTTP/1.1 302 OK\r\n"
  "Location: %s\r\n"
  "Content-Type: text/html\r\n"
  "Cache-Control: private, no-cache, must-revalidate\r\n"
  "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
  "Connection: close\r\n"
  "Pragma: no-cache\r\n"
  "Content-Length: %d\r\n\r\n%s";

static const char *http_error_template =
  "HTTP/1.1 %s\r\n"
  "Content-Type: text/html\r\n"
  "Cache-Control: private, no-cache, must-revalidate\r\n"
  "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
  "Connection: close\r\n"
  "Pragma: no-cache\r\n"
  "Content-Length: 0\r\n\r\n";

static const char *wispr_proxy_template =
  "<!--\n"
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
  "<WISPAccessGatewayParam"
  " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
  " xsi:noNamespaceSchemaLocation=\"http://www.acmewisp.com/WISPAccessGatewayParam.xsd\">"
  "<Proxy>"
  "<MessageType>110</MessageType>"
  "<ResponseCode>200</ResponseCode>"
  "<NextURL>%s</NextURL>"
  "</Proxy>"
  "</WISPAccessGatewayParam>\n"
  "-->\n";

static const char *html_redirect_template =
  "<!DOCTYPE html>\n"
  "<html>\n"
  "%s"
  "   <head>\n"
  "      <title>Redirection</title>\n"
  "      <meta http-equiv=\"refresh\" content=\"0; URL=%s\">\n"
  "   </head>\n"
  "   <body>\n"
  "      Please <a href='%s'>click here</a> to continue\n"
  "   </body>\n"
  "</html>\n";


static void
http_redir_send_data (stream_session_t * s, u8 * data)
{
  u32 offset, bytes_to_send;
  f64 delay = 10e-3;
  http_redirect_server_main_t *hsm = &http_redirect_server_main;
  vlib_main_t *vm = hsm->vlib_main;
  f64 last_sent_timer = vlib_time_now (vm);

  bytes_to_send = vec_len (data);
  offset = 0;

  while (bytes_to_send > 0)
    {
      int actual_transfer;

      actual_transfer = svm_fifo_enqueue_nowait
	(s->server_tx_fifo, bytes_to_send, data + offset);

      /* Made any progress? */
      if (actual_transfer <= 0)
	{
	  vlib_process_suspend (vm, delay);
	  /* 10s deadman timer */
	  if (vlib_time_now (vm) > last_sent_timer + 10.0)
	    {
	      /* $$$$ FC: reset transport session here? */
	      break;
	    }
	  /* Exponential backoff, within reason */
	  if (delay < 1.0)
	    delay = delay * 2.0;
	}
      else
	{
	  last_sent_timer = vlib_time_now (vm);
	  offset += actual_transfer;
	  bytes_to_send -= actual_transfer;

	  if (svm_fifo_set_event (s->server_tx_fifo))
	    session_send_io_evt_to_thread (s->server_tx_fifo,
					   FIFO_EVENT_APP_TX);
	  delay = 10e-3;
	}
    }
}

static void
send_error (stream_session_t * s, char *str)
{
  u8 *data;

  data = format (0, http_error_template, str);
  http_redir_send_data (s, data);
  vec_free (data);
}

static int
session_rx_request (stream_session_t * s)
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;
  svm_fifo_t *rx_fifo;
  u32 max_dequeue;
  int actual_transfer;

  rx_fifo = s->server_rx_fifo;
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  svm_fifo_unset_event (rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return -1;

  vec_validate (hsm->rx_buf[s->thread_index], max_dequeue - 1);
  _vec_len (hsm->rx_buf[s->thread_index]) = max_dequeue;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, max_dequeue,
					     hsm->rx_buf[s->thread_index]);
  ASSERT (actual_transfer > 0);
  _vec_len (hsm->rx_buf[s->thread_index]) = actual_transfer;
  return 0;
}

static int
http_redirect_server_rx_callback_static (stream_session_t * s)
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;
  vnet_disconnect_args_t _a, *a = &_a;
  upf_main_t * gtm = &upf_main;
  transport_connection_t *tc;
  upf_session_t * sess;
  struct rules *active;
  upf_far_t * far;
  u8 *request = 0;
  u8 *wispr, *html, *http, *url;
  int i;
  int rv;

  rv = session_rx_request (s);
  if (rv)
    return rv;

  request = hsm->rx_buf[s->thread_index];
  if (vec_len (request) < 7)
    {
      send_error (s, "400 Bad Request");
      goto out;
    }

  for (i = 0; i < vec_len (request) - 4; i++)
    {
      if (request[i] == 'G' &&
	  request[i + 1] == 'E' &&
	  request[i + 2] == 'T' && request[i + 3] == ' ')
	goto found;
    }
  send_error (s, "400 Bad Request");
  goto out;

found:

  tc = session_get_transport (s);
  if (!(tc->b2.gtpu.far_index & 0x80000000))
    {
      send_error (s, "500 Gateway Error");
      goto out;
    }

  sess = pool_elt_at_index (gtm->sessions, tc->b2.gtpu.session_index);
  active = sx_get_rules(sess, SX_ACTIVE);
  far = vec_elt_at_index (active->far, tc->b2.gtpu.far_index & ~0x80000000);

  /* Send it */
  url = far->forward.redirect_information.uri;
  wispr = format(0, wispr_proxy_template, url);
  html = format(0, html_redirect_template, wispr, url, url);
  http = format (0, http_redirect_template, url, vec_len (html), html);

  http_redir_send_data (s, http);

  vec_free(http);
  vec_free(html);
  vec_free(wispr);

out:
  /* Cleanup */
  vec_free (request);
  hsm->rx_buf[s->thread_index] = request;

  a->handle = session_handle (s);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
  return 0;
}

static int
http_redirect_server_session_accept_callback (stream_session_t * s)
{
  http_redirect_server_main_t *bsm = &http_redirect_server_main;

  bsm->vpp_queue[s->thread_index] =
    session_manager_get_vpp_event_queue (s->thread_index);
  s->session_state = SESSION_STATE_READY;
  bsm->byte_index = 0;
  return 0;
}

static void
http_redirect_server_session_disconnect_callback (stream_session_t * s)
{
  http_redirect_server_main_t *bsm = &http_redirect_server_main;
  vnet_disconnect_args_t _a, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = bsm->app_index;
  vnet_disconnect_session (a);
}

static void
http_redirect_server_session_reset_callback (stream_session_t * s)
{
  clib_warning ("called.. ");
  stream_session_cleanup (s);
}

static int
http_redirect_server_session_connected_callback (u32 app_index, u32 api_context,
					stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

static int
http_redirect_server_add_segment_callback (u32 client_index, const ssvm_private_t * sp)
{
  clib_warning ("called...");
  return -1;
}

static session_cb_vft_t http_redirect_server_session_cb_vft = {
  .session_accept_callback = http_redirect_server_session_accept_callback,
  .session_disconnect_callback = http_redirect_server_session_disconnect_callback,
  .session_connected_callback = http_redirect_server_session_connected_callback,
  .add_segment_callback = http_redirect_server_add_segment_callback,
  .builtin_app_rx_callback = http_redirect_server_rx_callback_static,
  .session_reset_callback = http_redirect_server_session_reset_callback
};

/* Abuse VPP's input queue */
static int
create_api_loopback (vlib_main_t * vm)
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  hsm->vl_input_queue = shmem_hdr->vl_input_queue;
  hsm->my_client_index =
    vl_api_memclnt_create_internal ("http_redirect_server", hsm->vl_input_queue);
  return 0;
}

static int
server_attach ()
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = hsm->my_client_index;
  a->session_cb_vft = &http_redirect_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hsm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  hsm->app_index = a->app_index;

  return 0;
}

static int
http_redirect_server_listen (u32 fib_index, int is_ip4)
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;
  session_endpoint_cfg_t cfg = SESSION_ENDPOINT_CFG_NULL;
  session_handle_t handle;
  stream_session_t *tl;
  application_t *app;
  int rv;

  cfg.is_ip4 = is_ip4;
  cfg.transport_proto = TRANSPORT_PROTO_TCP;
  cfg.fib_index = fib_index;

  app = application_get_if_valid (hsm->app_index);

  rv = application_start_listen(app, &cfg, &handle);
  if (rv)
    {
      clib_warning ("failed to start listen");
      return rv;
    }

  tl = listen_session_get_from_handle (handle);

  if (is_ip4)
    {
      vec_validate_init_empty(hsm->ip4_listen_session_by_fib_index, fib_index, 0);
      hsm->ip4_listen_session_by_fib_index[fib_index] = 0x80000000 | tl->session_index;
    }
  else
    {
      vec_validate_init_empty(hsm->ip6_listen_session_by_fib_index, fib_index, 0);
      hsm->ip6_listen_session_by_fib_index[fib_index] = 0x80000000 | tl->session_index;
    }

  return 0;
}

static int
http_redirect_server_create (vlib_main_t * vm, u32 fib_index, int is_ip4)
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;

  if (PREDICT_FALSE (hsm->my_client_index == (u32) ~ 0))
    {
      if (create_api_loopback (vm))
	return -1;

      vec_validate (hsm->vpp_queue, hsm->num_threads - 1);

      if (server_attach ())
	{
	  clib_warning ("failed to attach server");
	  return -1;
	}
    }

  if (http_redirect_server_listen (fib_index, is_ip4))
    {
      clib_warning ("failed to start listening");
      return -1;
    }
  return 0;
}

u32 upf_http_redirect_server_create(u32 fib_index, int is_ip4)
{
  vlib_main_t *vm = &vlib_global_main;
  int rv;

  if (http_redirect_server_main.my_client_index == (u32) ~ 0)
    vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  rv = http_redirect_server_create(vm, fib_index, is_ip4);
  if (rv != 0)
    {
      clib_error ("UPF http redirect server create returned %d", rv);
      return 0;
    }

  return is_ip4 ? http_redirect_server_main.ip4_listen_session_by_fib_index[fib_index] :
    http_redirect_server_main.ip6_listen_session_by_fib_index[fib_index];
}

clib_error_t *
upf_http_redirect_server_main_init (vlib_main_t * vm)
{
  http_redirect_server_main_t *hsm = &http_redirect_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();

  memset(hsm, 0, sizeof(*hsm));

  hsm->my_client_index = ~0;
  hsm->vlib_main = vm;

  hsm->num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hsm->rx_buf, hsm->num_threads - 1);
  return 0;
}

VLIB_INIT_FUNCTION (upf_http_redirect_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
