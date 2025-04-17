.. _http_plugin:

.. toctree::

HTTP Plugin
===========

Overview
--------

This plugin adds the HTTP protocol to VPP's Host Stack.
As a result parsing and serializing of HTTP/1 requests or responses are available for internal VPP applications.

Usage
-----

The plugin exposes following inline functions: ``http_validate_abs_path_syntax``, ``http_validate_query_syntax``,
``http_percent_decode``, ``http_path_sanitize``, ``http_build_header_table``, ``http_get_header``,
``http_reset_header_table``, ``http_free_header_table``, ``http_init_headers_ctx``, ``http_add_header``,
``http_add_custom_header``, ``http_validate_target_syntax``, ``http_parse_authority``, ``http_serialize_authority``,
``http_parse_masque_host_port``, ``http_decap_udp_payload_datagram``, ``http_encap_udp_payload_datagram``,
``http_token_is``, ``http_token_is_case``, ``http_token_contains``

It relies on the hoststack constructs and uses ``http_msg_data_t`` data structure for passing metadata to/from applications.

Server application
^^^^^^^^^^^^^^^^^^

Server application sets ``TRANSPORT_PROTO_HTTP`` as ``transport_proto`` in session endpoint configuration when registering to listen.

Receiving data
""""""""""""""

HTTP plugin sends message header with metadata for parsing, in form of offset and length, followed by all data bytes as received from transport.

Application will get pre-parsed following items:

* HTTP method
* scheme (HTTP/HTTPS)
* target authority offset and length
* target path offset and length
* target query offset and length
* header section offset and length
* body offset and length

The example below reads HTTP message header in ``builtin_app_rx_callback``, which is first step application should do:

.. code-block:: C

  #include <http/http.h>
  http_msg_t msg;
  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

As next step application might validate message and method type, for example application only expects to receive GET requests:

.. code-block:: C

  if (msg.type != HTTP_MSG_REQUEST || msg.method_type != HTTP_REQ_GET)
    {
      /* your error handling */
    }

Now application can start reading HTTP data. First let's read the target path:

.. code-block:: C

  u8 *target_path;
  if (msg.data.target_path_len == 0)
    {
      /* your error handling */
    }
  vec_validate (target_path, msg.data.target_path_len - 1);
  rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_path_offset, msg.data.target_path_len, target_path);
  ASSERT (rv == msg.data.target_path_len);

Target path might be in some cases empty (e.g. CONNECT method), you can read more about target forms in RFC9112 section 3.2.
In case of origin and absolute form HTTP plugin always sets ``target_path_offset`` after leading slash character.

Example bellow validates "absolute-path" rule, as described in RFC9110 section 4.1, additionally application can get information if percent encoding is used and decode path:

.. code-block:: C

  int is_encoded = 0;
  if (http_validate_abs_path_syntax (target_path, &is_encoded))
    {
      /* your error handling */
    }
  if (is_encoded)
    {
      u8 *decoded = http_percent_decode (target_path, vec_len (target_path));
      vec_free (target_path);
      target_path = decoded;
    }

More on topic when to decode in RFC3986 section 2.4.

When application serves static files, it is highly recommended to sanitize target path by removing dot segments (you don't want to risk path traversal attack):

.. code-block:: C

  u8 *sanitized_path;
  sanitized_path = http_path_remove_dot_segments (target_path);

Let's move to target query which is optional. Percent encoding might be used too, but we skip it for brevity:

.. code-block:: C

  u8 *target_query = 0;
  if (msg.data.target_query_len)
    {
      vec_validate (target_query, msg.data.target_query_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_query_offset,
			  msg.data.target_query_len, target_query);
      ASSERT (rv == msg.data.target_query_len);
      if (http_validate_query_syntax (target_query, 0))
        {
          /* your error handling */
        }
    }

And now for something completely different, headers.
Headers are parsed using a generic algorithm, independent of the individual header names.
When header is repeated, its combined value consists of all values separated by comma, concatenated in order as received.
Following example shows how to parse headers:

.. code-block:: C

  #include <http/http_header_names.h>
  if (msg.data.headers_len)
    {
      http_header_table_t ht = HTTP_HEADER_TABLE_NULL;
      /* initialize header table buffer */
      http_init_header_table_buf (&ht, msg);
      /* read raw headers into buffer */
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.headers_offset,
			  msg.data.headers_len, ht.buf);
      ASSERT (rv == msg.data.headers_len);
      /* build header table */
      http_build_header_table (&ht, msg);
      /* get Accept header */
      const http_token_t *accept_value = http_get_header (&ht,
        http_header_name_token (HTTP_HEADER_ACCEPT));
      if (accept_value)
        {
          if (http_token_contains (accept_value->base, accept_value->len, http_token_lit ("text/plain")))
            {
              /* do something interesting */
            }
        }
      /* free header table */
      http_free_header_table (&ht);
    }

Allocated header table memory can be reused, you just need to reset it using ``http_reset_header_table`` before reuse.
We will add following member to our session context structure:

.. code-block:: C

  typedef struct
  {
    /* ... */
    http_header_table_t ht;
  } session_ctx_t;

Don't forget to zero allocated session context.

And in ``session_cleanup_callback`` we free header table memory:

.. code-block:: C

  http_free_header_table (&ctx->ht);

Modified example above:

.. code-block:: C

  #include <http/http_header_names.h>
  /* reset header table before reuse */
  http_reset_header_table (&ctx->ht);
  /* ... */
  if (msg.data.headers_len)
    {
      /* initialize header table buffer */
      http_init_header_table_buf (&ctx->ht, msg);
      /* read raw headers into buffer */
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.headers_offset,
			  msg.data.headers_len, ctx->ht.buf);
      ASSERT (rv == msg.data.headers_len);
      /* build header table */
      http_build_header_table (&ctx->ht, msg);
      /* get Accept header */
      const http_token_t *accept_value = http_get_header (&ctx->ht,
        http_header_name_token (HTTP_HEADER_ACCEPT));
      if (accept_value)
        {
          /* do something interesting */
        }
    }

Finally application reads body  (if any), which might be received in multiple pieces (depends on size), so we might need some state machine in ``builtin_app_rx_callback``.
We will add following members to our session context structure:

.. code-block:: C

  typedef struct
  {
    /* ... */
    u64 to_recv;
    u8 *resp_body;
  } session_ctx_t;

First we prepare vector for response body, do it only once when you are reading metadata:

.. code-block:: C

  /* drop everything up to body */
  svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.body_offset);
  ctx->to_recv = msg.data.body_len;
  /* prepare vector for response body */
  vec_validate (ctx->resp_body, msg.data.body_len - 1);
  vec_reset_length (ctx->resp_body);

Now we can start reading body content, following block of code could be executed multiple times:

.. code-block:: C

  /* dequeue */
  u32 n_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  /* current offset */
  u64 curr = vec_len (ctx->resp_body);
  rv = svm_fifo_dequeue (ts->rx_fifo, n_deq, ctx->resp_body + curr);
  ASSERT (rv == n_deq);
  /* notify http transport that we read data if requested */
  if (svm_fifo_needs_deq_ntf (ts->rx_fifo, n_deq))
    {
      svm_fifo_clear_deq_ntf (ts->rx_fifo);
      session_program_transport_io_evt (ts->handle, SESSION_IO_EVT_RX);
    }
  /* update length of the vector */
  vec_set_len (ctx->resp_body, curr + n_deq);
  /* update number of remaining bytes to receive */
  ctx->to_recv -= rv;
  /* check if all data received */
  if (ctx->to_recv == 0)
    {
      /* we are done */
      /* send 200 OK response */
    }

.. note::
    When body content is read from the ``rx_fifo`` app need to send notification to HTTP layer if requested, it is required for HTTP/2 flow control.

Sending data
""""""""""""""

When server application sends response back to HTTP layer it starts with message metadata, followed by optional serialized headers and finally body (if any).

Application should set following items:

* Status code
* header section offset and length
* body offset and length

Application could pass headers back to HTTP layer. Header list is created dynamically using ``http_headers_ctx_t``, which must be initialized with preallocated buffer.
Well known header names are predefined and are added using ``http_add_header``, for headers with custom names use ``http_add_custom_header``.
Header list buffer is sent buffer to HTTP layer in raw, current length is stored ``tail_offset`` member of ``http_headers_ctx_t``.

.. note::
    Following headers are added at protocol layer and **MUST NOT** be set by application: Date, Server, Content-Length, Connection, Upgrade

Following example shows how to create headers section:

.. code-block:: C

  #include <http/http.h>
  #include <http/http_header_names.h>
  #include <http/http_content_types.h>
  http_headers_ctx_t resp_headers;
  u8 *headers_buf = 0;
  /* allocate buffer for response header list */
  vec_validate (headers_buf, 1023);
  /* initialize header list context */
  http_init_headers_ctx (&resp_headers, headers_buf, vec_len (headers_buf));
  /* add headers to the list */
  http_add_header (&resp_headers, HTTP_HEADER_CONTENT_TYPE,
		   http_content_type_token (HTTP_CONTENT_TEXT_HTML));
  http_add_header (&resp_headers, HTTP_HEADER_CACHE_CONTROL,
		   http_token_lit ("max-age=600"));
  http_add_custom_header (&resp_headers,
		   http_token_lit ("X-Frame-Options"),
		   (const char *) x_frame_opt, vec_len (x_frame_opt));

The example below show how to create and send response HTTP message metadata:

.. code-block:: C

  http_msg_t msg;
  msg.type = HTTP_MSG_REPLY;
  msg.code = HTTP_STATUS_MOVED
  msg.data.headers_offset = 0;
  msg.data.headers_len = resp_headers.tail_offset;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.body_len = vec_len (tx_buf);
  msg.data.body_offset = msg.data.headers_len;
  msg.data.len = msg.data.body_len + msg.data.headers_len;
  ts = session_get (hs->vpp_session_index, hs->thread_index);
  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

Next you will send your headers:

.. code-block:: C

  rv = svm_fifo_enqueue (ts->tx_fifo, msg.data.headers_len, headers_buf);
  ASSERT (rv == msg.data.headers_len);
  vec_free (headers_buf);

Finally application sends response body:

.. code-block:: C

  rv = svm_fifo_enqueue (ts->tx_fifo, vec_len (tx_buf), tx_buf);
  if (rv != vec_len (hs->tx_buf))
    {
      hs->tx_offset = rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }
  else
    {
      vec_free (tx_buf);
    }
  if (svm_fifo_set_event (ts->tx_fifo))
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);

Examples above shows how to send body and headers by copy, alternatively you could pass them as pointer:

.. code-block:: C

  msg.data.type = HTTP_MSG_DATA_PTR;
  /* code omitted for brevity */
  if (msg.data.headers_len)
    {
      uword headers = pointer_to_uword (headers_buf);
      rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (headers), (u8 *) &headers);
      ASSERT (rv == sizeof (headers));
    }
  uword data = pointer_to_uword (tx_buf);
  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (data), (u8 *) &data);
  ASSERT (rv == sizeof (data));

In this case you need to free data when you receive next request or when session is closed.


Client application
^^^^^^^^^^^^^^^^^^

Client application opens connection with vnet URI where transport protocol is set to ``http``.

Sending data
""""""""""""""

HTTP request is sent when connection is successfully established in ``session_connected_callback``.

When client application sends message to HTTP layer it starts with message metadata, followed by request target, optional headers and body (if any) buffers.

Application should set following items:

* HTTP method
* target offset and length
* header section offset and length
* body offset and length

Application could pass headers to HTTP layer. Header list is created dynamically as vector of ``http_header_t``,
where we store only pointers to buffers (zero copy).
Well known header names are predefined.
The list is serialized just before you send buffer to HTTP layer.

.. note::
    Following headers are added at protocol layer and **MUST NOT** be set by application: Host, User-Agent


The example below shows how to create headers section:

.. code-block:: C

  #include <http/http.h>
  #include <http/http_header_names.h>
  #include <http/http_content_types.h>
  http_headers_ctx_t *req_headers;
  u8 *headers_buf = 0;
  vec_validate (headers_buf, 63);
  http_init_headers_ctx (&eq_headers, headers_buf, vec_len (headers_buf));
  http_add_header (req_headers, HTTP_HEADER_ACCEPT,
		   http_content_type_token (HTTP_CONTENT_TEXT_HTML));

Following example shows how to set message metadata:

.. code-block:: C

  http_msg_t msg;
  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_GET;
  msg.data.headers_offset = 0;
  /* request target */
  msg.data.target_path_offset = 0;
  msg.data.target_path_len = vec_len (target);
  /* custom headers */
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.headers_len = headers.tail_offset;
  /* no request body because we are doing GET request */
  msg.data.body_len = 0;
  /* data type and total length */
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = msg.data.target_path_len + msg.data.headers_len + msg.data.body_len;

Finally application sends everything to HTTP layer:

.. code-block:: C

  svm_fifo_seg_t segs[3] = { { (u8 *) &msg, sizeof (msg) }, /* message metadata */
			     { target, vec_len (target) }, /* request target */
			     { headers_buf, msg.data.headers_len } }; /* headers */
  rv = svm_fifo_enqueue_segments (as->tx_fifo, segs, 3, 0 /* allow partial */);
  vec_free (headers_buf);
  if (rv < 0 || rv != sizeof (msg) + msg.data.len)
    {
      clib_warning ("failed app enqueue");
      return -1;
    }
  if (svm_fifo_set_event (as->tx_fifo))
    session_program_tx_io_evt (as->handle, SESSION_IO_EVT_TX);

Examples above shows how to send buffers by copy, alternatively you could pass them as pointer:

.. code-block:: C

  msg.data.type = HTTP_MSG_DATA_PTR;
  msg.method_type = HTTP_REQ_POST;
  msg.data.body_len = vec_len (data);
  /* code omitted for brevity */
  uword target = pointer_to_uword (target);
  uword headers = pointer_to_uword (headers_buf);
  uword body = pointer_to_uword (data);
  svm_fifo_seg_t segs[4] = {
    { (u8 *) &msg, sizeof (msg) },
    { (u8 *) &target, sizeof (target) },
    { (u8 *) &headers, sizeof (headers) },
    { (u8 *) &body, sizeof (body) },
  };
  rv = svm_fifo_enqueue_segments (s->tx_fifo, segs, 4, 0 /* allow partial */);
  ASSERT (rv == (sizeof (msg) + sizeof (target) + sizeof (headers) + sizeof (body)));

In this case you need to free data when you receive response or when session is closed.

Receiving data
""""""""""""""

HTTP plugin sends message header with metadata for parsing, in form of offset and length, followed by all data bytes as received from transport.

Application will get pre-parsed following items:

* status code
* header section offset and length
* body offset and length

The example below reads HTTP message header in ``builtin_app_rx_callback``, which is first step application should do:

.. code-block:: C

  #include <http/http.h>
  http_msg_t msg;
  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

As next step application might validate message type and status code:

.. code-block:: C

  if (msg.type != HTTP_MSG_REPLY)
    {
      /* your error handling */
    }
  if (msg.code != HTTP_STATUS_OK)
    {
      /* your error handling */
      /* of course you can continue with steps bellow */
      /* you might be interested in some headers or body content (if any) */
    }

Headers are parsed using a generic algorithm, independent of the individual header names.
When header is repeated, its combined value consists of all values separated by comma, concatenated in order as received.
Following example shows how to parse headers:

.. code-block:: C

  #include <http/http_header_names.h>
  if (msg.data.headers_len)
    {
      http_header_table_t ht = HTTP_HEADER_TABLE_NULL;
      /* initialize header table buffer */
      http_init_header_table_buf (&ht, msg);
      /* read raw headers into buffer */
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.headers_offset,
			  msg.data.headers_len, ht.buf);
      ASSERT (rv == msg.data.headers_len);
      /* build header table */
      http_build_header_table (&ht, msg);
      /* get Content-Type header */
      const http_token_t *content_type = http_get_header (&ht,
        http_header_name_token (HTTP_HEADER_CONTENT_TYPE));
      if (content_type)
        {
          /* do something interesting */
        }
      /* free header table */
      http_free_header_table (&ht);
    }

Finally application reads body, which might be received in multiple pieces (depends on size), so we might need some state machine in ``builtin_app_rx_callback``.
We will add following members to our session context structure:

.. code-block:: C

  typedef struct
  {
    /* ... */
    u64 to_recv;
    u8 *resp_body;
  } session_ctx_t;

First we prepare vector for response body, do it only once when you are reading metadata:

.. code-block:: C

  /* drop everything up to body */
  svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.body_offset);
  ctx->to_recv = msg.data.body_len;
  /* prepare vector for response body */
  vec_validate (ctx->resp_body, msg.data.body_len - 1);
  vec_reset_length (ctx->resp_body);

Now we can start reading body content, following block of code could be executed multiple times:

.. code-block:: C

  /* dequeue */
  u32 max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  u32 n_deq = clib_min (to_recv, max_deq);
  /* current offset */
  u64 curr = vec_len (ctx->resp_body);
  rv = svm_fifo_dequeue (ts->rx_fifo, n_deq, ctx->resp_body + curr);
  if (rv < 0 || rv != n_deq)
    {
      /* your error handling */
    }
  /* update length of the vector */
  vec_set_len (ctx->resp_body, curr + n_deq);
  /* update number of remaining bytes to receive */
  ASSERT (to_recv >= rv);
  ctx->to_recv -= rv;
  /* check if all data received */
  if (ctx->to_recv == 0)
    {
      /* we are done */
      /* close the session if you don't want to send another request */
      /* and update state machine... */
    }

HTTP timeout
^^^^^^^^^^^^

HTTP plugin sets session inactivity timeout by default to 60 seconds.
Client and server applications can pass custom timeout value (in seconds) using extended configuration when doing connect or start listening respectively.
You just need to add extended configuration to session endpoint configuration which is part of ``vnet_connect_args_t`` and ``vnet_listen_args_t``.
HTTP plugin use ``timeout`` member of ``transport_endpt_cfg_http_t``, unsigned 32bit integer seems to be sufficient (allowing the timeout to be set up to 136 years).

The example below sets HTTP session timeout to 30 seconds (server application):

.. code-block:: C

    vnet_listen_args_t _a, *a = &_a;
    transport_endpt_ext_cfg_t *ext_cfg;
    int rv;
    clib_memset (a, 0, sizeof (*a));
    clib_memcpy (&a->sep_ext, &sep, sizeof (sep));
    /* your custom timeout value in seconds, unused parameters are set to zero */
    transport_endpt_cfg_http_t http_cfg = { 30, 0 };
    /* add new extended config entry */
    ext_cfg = session_endpoint_add_ext_cfg (
        &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
    clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));
    /* rest of the settings omitted for brevity */
    rv = vnet_listen (a);
    /* don't forget to free extended config */
    session_endpoint_free_ext_cfgs (&a->sep_ext);
    /* ... */
