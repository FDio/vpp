/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <http_static/http_static.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct hss_fh_cfg_
{
  /** root path to be served */
  u8 *www_root;

  /** file cache */
  hss_cache_t cache;

  u8 debug_level;
} hss_fh_cfg_t;

static u8
file_path_is_valid (u8 *path)
{
  struct stat _sb, *sb = &_sb;

  if (stat ((char *) path, sb) < 0 /* can't stat the file */
      || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */)
    return 0;

  return 1;
}

static u32
try_index_file (hss_main_t *hsm, hss_session_t *hs, u8 *path)
{
  u8 *port_str = 0, *redirect;
  transport_endpoint_t endpt;
  transport_proto_t proto;
  int print_port = 0;
  u16 local_port;
  session_t *ts;
  u32 plen;

  /* Remove the trailing space */
  _vec_len (path) -= 1;
  plen = vec_len (path);

  /* Append "index.html" */
  if (path[plen - 1] != '/')
    path = format (path, "/index.html%c", 0);
  else
    path = format (path, "index.html%c", 0);

  if (hsm->debug_level > 0)
    clib_warning ("trying to find index: %s", path);

  if (!file_path_is_valid (path))
    return HTTP_STATUS_NOT_FOUND;

  /*
   * We found an index.html file, build a redirect
   */
  vec_delete (path, vec_len (hsm->www_root) - 1, 0);

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  session_get_endpoint (ts, &endpt, 1 /* is_local */);

  local_port = clib_net_to_host_u16 (endpt.port);
  proto = session_type_transport_proto (ts->session_type);

  if ((proto == TRANSPORT_PROTO_TCP && local_port != 80) ||
      (proto == TRANSPORT_PROTO_TLS && local_port != 443))
    {
      print_port = 1;
      port_str = format (0, ":%u", (u32) local_port);
    }

  redirect =
    format (0,
	    "HTTP/1.1 301 Moved Permanently\r\n"
	    "Location: http%s://%U%s%s\r\n\r\n",
	    proto == TRANSPORT_PROTO_TLS ? "s" : "", format_ip46_address,
	    &endpt.ip, endpt.is_ip4, print_port ? port_str : (u8 *) "", path);

  if (hsm->debug_level > 0)
    clib_warning ("redirect: %s", redirect);

  vec_free (port_str);

  hs->data = redirect;
  hs->data_len = vec_len (redirect);
  hs->free_data = 1;

  return HTTP_STATUS_OK;
}

static int
fh_try_handle_req (hss_session_t *hs, http_req_method_t rt, u8 *request)
{
  http_status_code_t sc = HTTP_STATUS_OK;
  u8 *path;
  u32 ce_index;

  /* Feature not enabled */
  if (!hsm->www_root)
    return -1;

  /*
   * Construct the file to open
   * Browsers are capable of sporadically including a leading '/'
   */
  if (!request)
    path = format (0, "%s%c", hsm->www_root, 0);
  else if (request[0] == '/')
    path = format (0, "%s%s%c", hsm->www_root, request, 0);
  else
    path = format (0, "%s/%s%c", hsm->www_root, request, 0);

  if (hsm->debug_level > 0)
    clib_warning ("%s '%s'", (rt == HTTP_REQ_GET) ? "GET" : "POST", path);

  if (hs->data && hs->free_data)
    vec_free (hs->data);

  hs->path = path;
  hs->data_offset = 0;

  ce_index =
    hss_cache_lookup_and_attach (&hsm->cache, path, &hs->data, &hs->data_len);
  if (ce_index == ~0)
    {
      if (!file_path_is_valid (path))
	{
	  sc = try_index_file (hsm, hs, path);
	  goto done;
	}
      ce_index =
	hss_cache_add_and_attach (&hsm->cache, path, &hs->data, &hs->data_len);
      if (ce_index == ~0)
	{
	  sc = HTTP_STATUS_INTERNAL_ERROR;
	  goto done;
	}
    }

  hs->cache_pool_index = ce_index;

done:

  start_send_data (hs, sc);
  if (!hs->data)
    hss_session_disconnect_transport (hs);

  return 0;
}

static int
fh_tx_callback (hss_session_t *hs, session_t *ts)
{
  u32 to_send;
  int rv;

  if (!hs->data)
    return 0;

  to_send = hs->data_len - hs->data_offset;
  rv = svm_fifo_enqueue (ts->tx_fifo, to_send, hs->data + hs->data_offset);

  if (rv <= 0)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv < to_send)
    {
      hs->data_offset += rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

  return 0;
}

static const hss_module_vft_t hss_file_handler = {
  .try_handle_req = fh_try_handle_req,
  .tx_callback = fh_tx_callback,
};

clib_error_t *
hss_file_handler_init (vlib_main_t *vm)
{
  clib_error_t *error = 0;

  hss_register_module (HSS_MODULE_FILE_HANDLER, &hss_file_handler);

  return error;
}

VLIB_INIT_FUNCTION (hss_file_handler_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
