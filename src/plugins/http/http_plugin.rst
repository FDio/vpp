.. _http_plugin:

.. toctree::

HTTP Plugin
===========

Overview
--------

This plugin adds the HTTP protocol to VPP's Host Stack.
As a result parsing of HTTP/1 request or response is available for internal VPP applications.

Usage
-----

The plugin exposes following inline functions: ``http_validate_abs_path_syntax``, ``http_validate_query_syntax``,
``http_percent_decode``, ``http_path_remove_dot_segments``, ``http_parse_headers``, ``http_get_header``,
``http_free_header_table``.

It relies on the hoststack constructs and uses ``http_msg_data_t`` data structure for passing metadata to/from applications.

Server application
^^^^^^^^^^^^^^^^^^

Server application sets ``TRANSPORT_PROTO_HTTP`` as ``transport_proto`` in session endpoint configuration when registering to listen.

Receiving data
""""""""""""""

HTTP plugin sends message header with metadata for parsing, in form of offset and length, followed by all data bytes as received from transport.

Application will get pre-parsed following items:

* HTTP method
* target form
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
  vec_validate (target_path, msg.data.target_path_len - 1);
  rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_path_offset, msg.data.target_path_len, target_path);
  ASSERT (rv == msg.data.target_path_len);

Application might also want to know target form which is stored in ``msg.data.target_form``, you can read more about target forms in RFC9112 section 3.2.
In case of origin form HTTP plugin always sets ``target_path_offset`` after leading slash character.

Example bellow validates "absolute-path" rule, as described in RFC9110 section 4.1, in case of target in origin form, additionally application can get information if percent encoding is used and decode path:

.. code-block:: C

  int is_encoded = 0;
  if (msg.data.target_form == HTTP_TARGET_ORIGIN_FORM)
    {
      if (http_validate_abs_path_syntax (target_path, &is_encoded))
        {
          /* your error handling */
        }
      if (is_encoded)
        {
          u8 *decoded = http_percent_decode (target_path);
          vec_free (target_path);
          target_path = decoded;
        }
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
      u8 *headers = 0;
      http_header_table_t *ht;
      vec_validate (headers, msg.data.headers_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.headers_offset,
			  msg.data.headers_len, headers);
      ASSERT (rv == msg.data.headers_len);
      if (http_parse_headers (headers, &ht))
        {
          /* your error handling */
        }
      /* get Accept header */
      const char *accept_value = http_get_header (ht, http_header_name_str (HTTP_HEADER_ACCEPT));
      if (accept_value)
        {
          /* do something interesting */
        }
      http_free_header_table (ht);
      vec_free (headers);
    }

Finally application reads body:

.. code-block:: C

  u8 *body = 0;
  if (msg.data.body_len)
    {
      vec_validate (body, msg.data.body_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.body_offset, msg.data.body_len, body);
      ASSERT (rv == msg.data.body_len);
    }

Sending data
""""""""""""""

When server application sends response back to HTTP layer it starts with message metadata, followed by optional serialized headers and finally body (if any).

Application should set following items:

* Status code
* target form
* header section offset and length
* body offset and length

Application could pass headers back to HTTP layer. Header list is created dynamically as vector of ``http_header_t``,
where we store only pointers to buffers (zero copy).
Well known header names are predefined.
The list is serialized just before you send buffer to HTTP layer.

.. note::
    Following headers are added at protocol layer and **MUST NOT** be set by application: Date, Server, Content-Length

Following example shows how to create headers section:

.. code-block:: C

  #include <http/http.h>
  #include <http/http_header_names.h>
  #include <http/http_content_types.h>
  http_header_t *resp_headers = 0;
  u8 *headers_buf = 0;
  http_add_header (resp_headers,
		   http_header_name_token (HTTP_HEADER_CONTENT_TYPE),
		   http_content_type_token (HTTP_CONTENT_TEXT_HTML));
  http_add_header (resp_headers,
		   http_header_name_token (HTTP_HEADER_CACHE_CONTROL),
		   http_token_lit ("max-age=600"));
  http_add_header (resp_headers,
		   http_header_name_token (HTTP_HEADER_LOCATION),
		   (const char *) redirect, vec_len (redirect));
  headers_buf = http_serialize_headers (resp_headers);

The example below show how to create and send response HTTP message metadata:

.. code-block:: C

  http_msg_t msg;
  msg.type = HTTP_MSG_REPLY;
  msg.code = HTTP_STATUS_MOVED
  msg.data.headers_offset = 0;
  msg.data.headers_len = vec_len (headers_buf);
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.body_len = vec_len (tx_buf);
  msg.data.body_offset = msg.data.headers_len;
  msg.data.len = msg.data.body_len + msg.data.headers_len;
  ts = session_get (hs->vpp_session_index, hs->thread_index);
  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

Next you will send your serialized headers:

.. code-block:: C

  rv = svm_fifo_enqueue (ts->tx_fifo, vec_len (headers_buf), headers_buf);
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
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

Example above shows how to send body data by copy, alternatively you could pass it as pointer:

.. code-block:: C

  msg.data.type = HTTP_MSG_DATA_PTR;
  /* code omitted for brevity */
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
* target form, offset and length
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
  http_header_t *req_headers = 0;
  u8 *headers_buf = 0;
  http_add_header (req_headers,
		   http_header_name_token (HTTP_HEADER_ACCEPT),
		   http_content_type_token (HTTP_CONTENT_TEXT_HTML));
  headers_buf = http_serialize_headers (req_headers);
  vec_free (hs->req_headers);

Following example shows how to set message metadata:

.. code-block:: C

  http_msg_t msg;
  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_GET;
  msg.data.headers_offset = 0;
  /* request target */
  msg.data.target_form = HTTP_TARGET_ORIGIN_FORM;
  msg.data.target_path_offset = 0;
  msg.data.target_path_len = vec_len (target);
  /* custom headers */
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.headers_len = vec_len (headers_buf);
  /* no request body because we are doing GET request */
  msg.data.body_len = 0;
  /* data type and total length */
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = msg.data.target_path_len + msg.data.headers_len + msg.data.body_len;

Finally application sends everything to HTTP layer:

.. code-block:: C

  svm_fifo_seg_t segs[3] = { { (u8 *) &msg, sizeof (msg) }, /* message metadata */
			     { target, vec_len (target) }, /* request target */
			     { headers_buf, vec_len (headers_buf) } }; /* serialized headers */
  rv = svm_fifo_enqueue_segments (as->tx_fifo, segs, 3, 0 /* allow partial */);
  vec_free (headers_buf);
  if (rv < 0 || rv != sizeof (msg) + msg.data.len)
    {
      clib_warning ("failed app enqueue");
      return -1;
    }
  if (svm_fifo_set_event (as->tx_fifo))
    session_send_io_evt_to_thread (as->tx_fifo, SESSION_IO_EVT_TX);

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
      u8 *headers = 0;
      http_header_table_t *ht;
      vec_validate (headers, msg.data.headers_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.headers_offset,
			  msg.data.headers_len, headers);
      ASSERT (rv == msg.data.headers_len);
      if (http_parse_headers (headers, &ht))
        {
          /* your error handling */
        }
      /* get Content-Type header */
      const char *content_type = http_get_header (ht, http_header_name_str (HTTP_HEADER_CONTENT_TYPE));
      if (content_type)
        {
          /* do something interesting */
        }
      http_free_header_table (ht);
      vec_free (headers);
    }

Finally application reads body, which might be received in multiple pieces (depends on size), so we might need some state machine in ``builtin_app_rx_callback``.
We will add following members to our session context structure:

.. code-block:: C

  typedef struct
  {
    /* ... */
    u32 to_recv;
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
  u32 curr = vec_len (ctx->resp_body);
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
      hcc_session_disconnect (ts);
      /* we are done, update state machine... */
    }
