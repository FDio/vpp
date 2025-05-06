/*
 * HTTP streaming output implementation for Generic PCAPng capture
 * Streams captured packets via HTTP POST to a remote server
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>

#include "gpcapng.h"
#include "destination.h"

typedef struct
{
  gpcapng_worker_context_common_t common;
  /* HTTP client state */
  u32 app_index;
  session_t *session;
  u32 worker_index;

  /* Streaming buffer management */
  u8 *send_buffer;
  u32 buffer_size;
  u32 bytes_pending;

  /* HTTP request state */
  http_msg_t msg;
  u8 *headers_buf;
  http_headers_ctx_t req_headers;
  u8 *target_uri;

  /* Connection state */
  u8 connected;
  u8 headers_sent;
  session_endpoint_cfg_t connect_sep;

  /* Statistics */
  u64 total_bytes_sent;
  u64 chunks_sent;

  /* Retry logic */
  u8 retry_pending;
  u32 retry_count;
  f64 next_retry_time;
  f64 current_timeout;
  f64 initial_timeout; /* 0.5 seconds */
  f64 max_timeout;     /* 30 seconds */
} http_pcapng_ctx_t;

static void
print_http_context (vlib_main_t *vm, void *ctx)
{
  http_pcapng_ctx_t *hc = ctx;
  vlib_cli_output (vm, "app index: %d", hc->app_index);
  vlib_cli_output (vm, "connected: %d", hc->connected);
  vlib_cli_output (vm, "bytes sent: %d", hc->total_bytes_sent);
  vlib_cli_output (vm, "chunks sent: %d", hc->chunks_sent);
}

/* Forward declarations for HTTP client callbacks */
static int http_pcapng_session_connected_callback (u32 app_index,
						   u32 session_index,
						   session_t *s,
						   session_error_t err);
static int http_pcapng_rx_callback (session_t *s);
static int http_pcapng_tx_callback (session_t *s);
static void http_pcapng_session_disconnect_callback (session_t *s);
static void http_pcapng_session_reset_callback (session_t *s);

static int
http_pcapng_accept_callback (session_t *s)
{
  return 0;
}

static int
http_pcapng_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
http_pcapng_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
http_pcapng_ts_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;
  /*
    hs = http_pcapng_session_get (s->thread_index, s->opaque);
    if (!hs)
      return;
  */
}

static session_cb_vft_t http_pcapng_session_cb_vft = {
  .session_accept_callback = http_pcapng_accept_callback,
  .session_connected_callback = http_pcapng_session_connected_callback,
  .session_disconnect_callback = http_pcapng_session_disconnect_callback,
  .add_segment_callback = http_pcapng_add_segment_callback,
  .del_segment_callback = http_pcapng_del_segment_callback,
  .session_reset_callback = http_pcapng_session_reset_callback,
  .session_cleanup_callback = http_pcapng_ts_cleanup_callback,
  .builtin_app_rx_callback = http_pcapng_rx_callback,
  .builtin_app_tx_callback = http_pcapng_tx_callback,
};
/*
static int
pcapng_http_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv)
    clib_warning (0, "connect returned: %U", format_session_error, rv);

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);
  return rv;
}

static void
pcapng_program_connect (vnet_connect_args_t *a)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
pcapng_http_connect_rpc, a);
}
*/

void
enable_session_manager (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);
  vlib_worker_thread_barrier_release (vm);
}

static int
retry_entry_compare (void *a, void *b)
{
  retry_entry_t *ra = (retry_entry_t *) a;
  retry_entry_t *rb = (retry_entry_t *) b;
  return (ra->expiry_time < rb->expiry_time) ? -1 :
	 (ra->expiry_time > rb->expiry_time) ? 1 :
					       0;
}

static void
schedule_retry (worker_dest_index_t wdi, http_pcapng_ctx_t *ctx)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();
  u16 worker_index = wdi_to_worker_index (wdi);

  if (ctx->retry_count >= 10)
    { /* Max 10 retries */
      clib_warning ("Max retries exceeded for HTTP destination");
      return;
    }

  ctx->retry_pending = 1;
  ctx->retry_count++;
  ctx->next_retry_time =
    vlib_time_now (vlib_get_main ()) + ctx->current_timeout;

  /* Exponential backoff, but cap at max_timeout */
  ctx->current_timeout =
    clib_min (ctx->current_timeout * 2.0, ctx->max_timeout);

  /* Add to worker's retry queue */
  retry_entry_t entry = { .wdi = wdi, .expiry_time = ctx->next_retry_time };
  vec_add1 (gpm->worker_retry_queue[worker_index], entry);

  /* Keep queue sorted by expiry time */
  vec_sort_with_function (gpm->worker_retry_queue[worker_index],
			  retry_entry_compare);
}

/* RPC function that runs on transport thread to make HTTP connection */
static int
pcapng_http_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv)
    {
      clib_warning ("HTTP PCAPng connect returned: %U", format_session_error,
		    rv);
    }

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);
  return rv;
}

static void
attempt_reconnect (worker_dest_index_t wdi, http_pcapng_ctx_t *ctx)
{
  vnet_connect_args_t *connect_args = 0;
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_endpt_cfg_http_t http_cfg = { 3600, 0 };

  /* Allocate connect args on heap for RPC */
  vec_validate (connect_args, 0);
  clib_memset (connect_args, 0, sizeof (connect_args[0]));

  /* Setup HTTP configuration */
  ext_cfg = session_endpoint_add_ext_cfg (
    &connect_args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  /* Copy connection endpoint configuration */
  clib_memcpy (&connect_args->sep_ext, &ctx->connect_sep,
	       sizeof (ctx->connect_sep));
  connect_args->app_index = ctx->app_index;
  connect_args->api_context = wdi;

  /* Send RPC to transport client thread to make connection */
  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
					pcapng_http_connect_rpc, connect_args);

  ctx->retry_pending = 0; /* Will be reset in callback if connection fails */
}

void
process_http_gpcapng_retries (u16 worker_index)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();
  f64 now = vlib_time_now (vlib_get_main ());
  int processed = 0;

  if (worker_index >= vec_len (gpm->worker_retry_queue) ||
      !gpm->worker_retry_queue[worker_index])
    return;

  /* Process up to 5 expired entries */
  while (vec_len (gpm->worker_retry_queue[worker_index]) > 0 && processed < 5)
    {
      if (gpm->worker_retry_queue[worker_index][0].expiry_time > now)
	break; /* Queue is sorted, so we can stop here */

      worker_dest_index_t wdi = gpm->worker_retry_queue[worker_index][0].wdi;

      /* Check if WDI has been poisoned (destination deleted) */
      if (wdi == WDI_POISON_VALUE)
	{
	  clib_warning (
	    "Skipping poisoned retry entry (destination was deleted)");
	  vec_delete (gpm->worker_retry_queue[worker_index], 1, 0);
	  processed++;
	  continue;
	}

      http_pcapng_ctx_t *ctx = wdi_to_worker_context (wdi);

      if (ctx && ctx->retry_pending)
	{
	  attempt_reconnect (wdi, ctx);
	}

      /* Remove processed entry */
      vec_delete (gpm->worker_retry_queue[worker_index], 1, 0);
      processed++;
    }
}

/* RPC function to process retries on current worker thread */
static int
http_retry_rpc (void *arg)
{
  process_http_gpcapng_retries (vlib_get_thread_index ());
  return 0;
}

/* Process node that sends RPC calls to all workers for HTTP retry processing
 */
static uword
http_retry_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 0.1); /* 100ms interval */

      /* Only process if HTTP destinations are configured */
      if (!gpm->http_destinations_configured)
	{
	  continue;
	}

      /* Send RPC to each worker thread */
      u16 worker_index;
      for (worker_index = 0; worker_index <= vlib_num_workers ();
	   worker_index++)
	{
	  if (worker_index == 0)
	    {
	      /* Main thread - call directly */
	      process_http_gpcapng_retries (0);
	    }
	  else
	    {
	      /* Send RPC to worker thread */
	      session_send_rpc_evt_to_thread_force (
		vlib_get_thread_index () + worker_index, http_retry_rpc, 0);
	    }
	}
    }
  return 0;
}

/* Register the HTTP retry process node */
VLIB_REGISTER_NODE (http_retry_process_node) = {
  .function = http_retry_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "gpcapng-http-retry-process",
  .process_log2_n_stack_bytes = 16,
};

/* Start the HTTP retry process if not already started */
static void
ensure_http_retry_process_started (void)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();

  /* Mark that we have HTTP destinations configured */
  gpm->http_destinations_configured = 1;

  return;

  if (gpm->http_retry_process_node_index == 0)
    {
      vlib_main_t *vm = vlib_get_main ();
      vlib_node_t *n;

      /* Get the node and start the process */
      n = vlib_get_node (vm, http_retry_process_node.index);
      gpm->http_retry_process_node_index = n->index;
      vlib_start_process (vm, n->index);

      clib_warning ("Started HTTP retry process (node index: %u)",
		    gpm->http_retry_process_node_index);
    }
}

#define HTTP_INITIAL_TIMEOUT_S 0.5
#define HTTP_MAX_TIMEOUT_S     30.0

/**
 * Initialize HTTP streaming context for PCAPng capture
 * @param worker_index Worker thread index
 * @return Initialized context or NULL on error
 */
void *
http_pcapng_init (gpcapng_dest_t *output, u16 worker_index,
		  u16 destination_index)
{
  http_pcapng_ctx_t *ctx;
  vnet_app_attach_args_t attach_args;
  u64 options[18];
  int rv;
  u8 *worker_uri = format (0, "%s-%d.pcapng", output->arg, worker_index);
  clib_warning ("worker uri: %v", worker_uri);

  /* Allocate and initialize context */
  ctx =
    clib_mem_alloc_aligned (sizeof (http_pcapng_ctx_t), CLIB_CACHE_LINE_BYTES);
  if (!ctx)
    {
      clib_warning ("Failed to allocate HTTP PCAPng context");
      return NULL;
    }
  memset (ctx, 0, sizeof (*ctx));
  worker_context_init_common (ctx, PCAPNG_DEST_HTTP);

  ctx->worker_index = worker_index;
  ctx->buffer_size = 64 * 1024; /* 64KB buffer */
  ctx->send_buffer = clib_mem_alloc (ctx->buffer_size);
  if (!ctx->send_buffer)
    {
      clib_warning ("Failed to allocate send buffer");
      clib_mem_free (ctx);
      return NULL;
    }

  ctx->retry_pending = 0;
  ctx->retry_count = 0;
  ctx->initial_timeout = HTTP_INITIAL_TIMEOUT_S;
  ctx->max_timeout = HTTP_MAX_TIMEOUT_S;
  ctx->current_timeout = ctx->initial_timeout;

  /* Initialize HTTP headers buffer */
  vec_validate (ctx->headers_buf, 4095); /* 4KB for headers */
  http_init_headers_ctx (&ctx->req_headers, ctx->headers_buf,
			 vec_len (ctx->headers_buf));

  /* Set target URI */
  parse_target ((char **) &worker_uri, (char **) &ctx->target_uri);
  while (vec_len (ctx->target_uri) &&
	 vec_elt (ctx->target_uri, vec_len (ctx->target_uri) - 1) == 0)
    {
      vec_dec_len (ctx->target_uri, 1);
    }
  clib_warning ("Worker uri: %v, target_uri: %v, len: %d", worker_uri,
		ctx->target_uri, vec_len (ctx->target_uri));

  /* Setup HTTP application attachment */
  clib_memset (&attach_args, 0, sizeof (attach_args));
  clib_memset (options, 0, sizeof (options));

  attach_args.api_client_index = APP_INVALID_INDEX;
  attach_args.name = format (0, "http_pcapng_worker_%u", worker_index);
  attach_args.session_cb_vft = &http_pcapng_session_cb_vft;
  attach_args.options = options;
  attach_args.options[APP_OPTIONS_SEGMENT_SIZE] = 32 << 20;	/* 32MB */
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20; /* 32MB */
  attach_args.options[APP_OPTIONS_RX_FIFO_SIZE] = 8 << 10;	/* 8KB */
  attach_args.options[APP_OPTIONS_TX_FIFO_SIZE] =
    16384 << 10; /* 16MB for streaming */
  attach_args.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  rv = vnet_application_attach (&attach_args);
  if (rv)
    {
      clib_warning ("HTTP PCAPng app attach failed: %U", format_session_error,
		    rv);
      vec_free (ctx->headers_buf);
      vec_free (ctx->target_uri);
      vec_free (attach_args.name);
      clib_mem_free (ctx->send_buffer);
      clib_mem_free (ctx);
      return NULL;
    }

  ctx->app_index = attach_args.app_index;
  vec_free (attach_args.name);

  clib_memset (&ctx->connect_sep, 0, sizeof (ctx->connect_sep));
  rv = parse_uri ((char *) worker_uri, &ctx->connect_sep);
  if (rv)
    {
      clib_warning ("Failed to parse target URI: %U", format_session_error,
		    rv);
      /* Cleanup and return NULL */
      vnet_app_detach_args_t detach = { .app_index = ctx->app_index };
      vnet_application_detach (&detach);
      vec_free (ctx->headers_buf);
      vec_free (ctx->target_uri);
      clib_mem_free (ctx->send_buffer);
      clib_mem_free (ctx);
      return NULL;
    }

  /* Initiate connection */
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_endpt_cfg_http_t http_cfg = {
    (u32) 3600, 0
  }; /* 1 hour timeout for streaming */

  vnet_connect_args_t connect_args;
  clib_memset (&connect_args, 0, sizeof (connect_args));
  ext_cfg = session_endpoint_add_ext_cfg (
    &connect_args.sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  clib_memcpy (&connect_args.sep_ext, &ctx->connect_sep,
	       sizeof (ctx->connect_sep));
  connect_args.app_index = ctx->app_index;

  connect_args.api_context = make_wdi (worker_index, destination_index);

  /* Don't connect immediately, let the retry mechanism handle it */
  schedule_retry (make_wdi (worker_index, destination_index), ctx);
  return ctx;
}

/**
 * Write a chunk of PCAPng data to HTTP stream
 * @param context HTTP PCAPng context
 * @param chunk Data chunk to write
 * @param chunk_size Size of data chunk
 * @return 0 on success, -1 on error
 */
int
http_pcapng_chunk_write (void *context, const void *chunk, size_t chunk_size)
{
  http_pcapng_ctx_t *ctx = (http_pcapng_ctx_t *) context;

  if (!ctx)
    {
      return -1;
    }
  if (!ctx->connected)
    {
      ALWAYS_ASSERT (0);
      return 0;
    }

  /* For streaming PUT, we just enqueue the raw data */
  /* The HTTP layer will handle chunked encoding */
  u32 max_enq = svm_fifo_max_enqueue (ctx->session->tx_fifo);
  if (max_enq < chunk_size)
    {
      /* Not enough space, would need to buffer */
      return -1;
    }

  int rv = svm_fifo_enqueue (ctx->session->tx_fifo, chunk_size, (u8 *) chunk);
  if (rv < 0)
    {
      return -1;
    }

  ctx->total_bytes_sent += rv;
  ctx->chunks_sent++;

  /* Trigger TX event */
  if (svm_fifo_set_event (ctx->session->tx_fifo))
    {
      session_program_tx_io_evt (ctx->session->handle, SESSION_IO_EVT_TX);
    }

  return 0;
}

/**
 * Flush any pending data in HTTP stream
 * @param context HTTP PCAPng context
 */
void
http_pcapng_flush (void *context)
{
  http_pcapng_ctx_t *ctx = (http_pcapng_ctx_t *) context;

  if (!ctx || !ctx->connected || !ctx->session)
    {
      return;
    }

  /* For streaming PUT, we need to close the connection to signal end of data
   */
  /* The HTTP layer will send the final 0-sized chunk */

  /* Log statistics */
  clib_warning ("HTTP PCAPng worker %u: sent %lu bytes in %lu chunks",
		ctx->worker_index, ctx->total_bytes_sent, ctx->chunks_sent);

  /* Disconnect the session to signal end of streaming */
  vnet_disconnect_args_t disconnect_args = { .handle =
					       session_handle (ctx->session),
					     .app_index = ctx->app_index };
  vnet_disconnect_session (&disconnect_args);

  ctx->connected = 0;
}

/**
 * Cleanup HTTP PCAPng context and close connection
 * @param context HTTP PCAPng context to cleanup
 */
void
http_pcapng_cleanup (void *context)
{
  http_pcapng_ctx_t *ctx = (http_pcapng_ctx_t *) context;

  if (!ctx)
    {
      return;
    }

  /* Disconnect session if connected */
  if (ctx->session && ctx->connected)
    {
      vnet_disconnect_args_t disconnect_args = {
	.handle = session_handle (ctx->session), .app_index = ctx->app_index
      };
      vnet_disconnect_session (&disconnect_args);
    }

  /* Detach application */
  if (ctx->app_index != APP_INVALID_INDEX)
    {
      vnet_app_detach_args_t detach_args = { .app_index = ctx->app_index,
					     .api_client_index =
					       APP_INVALID_INDEX };
      vnet_application_detach (&detach_args);
    }

  /* Free allocated memory */
  if (ctx->send_buffer)
    {
      clib_mem_free (ctx->send_buffer);
    }

  vec_free (ctx->headers_buf);
  vec_free (ctx->target_uri);

  /* Free context */
  clib_mem_free (ctx);
}

/* HTTP Client Session Callbacks */

static int
http_pcapng_session_connected_callback (u32 app_index, u32 session_index,
					session_t *s, session_error_t err)
{
  if (err)
    {
      clib_warning ("HTTP PCAPng connection failed: %U, retrying...",
		    format_session_error, err);
      // session_index here is actually api_context when err != 0
      worker_dest_index_t wdi = (worker_dest_index_t) session_index;
      http_pcapng_ctx_t *ctx = wdi_to_worker_context (wdi);

      if (ctx)
	{
	  schedule_retry (wdi, ctx);
	}
      return -1;
    }

  http_pcapng_ctx_t *ctx = wdi_to_worker_context (s->opaque);

  if (!ctx)
    {
      clib_warning ("No context found for HTTP PCAPng session");
      return -1;
    }

  /* Reset retry state on successful connection */
  ctx->retry_pending = 0;
  ctx->retry_count = 0;
  ctx->current_timeout = ctx->initial_timeout;

  /* Reset HTTP state for new connection */
  ctx->headers_sent = 0;
  ctx->session = s;
  ctx->connected = 1;

  /* Check if we need to send headers first */
  if (!ctx->headers_sent)
    {
      clib_warning ("sending streaming PUT request");

      if (svm_fifo_max_dequeue (s->tx_fifo) > 0)
	{
	  clib_warning ("Draining %u bytes of old data from FIFO",
			svm_fifo_max_dequeue (s->tx_fifo));
	  svm_fifo_dequeue_drop_all (s->tx_fifo);
	}

      /* Setup HTTP PUT headers for streaming */
      ctx->msg.method_type = HTTP_REQ_PUT;
      ctx->msg.type = HTTP_MSG_REQUEST;
      ctx->msg.data.type = HTTP_MSG_DATA_STREAMING;

      /* Set message lengths */
      ctx->msg.data.target_path_len = vec_len (ctx->target_uri);
      ctx->msg.data.headers_len = ctx->req_headers.tail_offset;
      ctx->msg.data.body_len = ~0ULL; /* Unknown length for streaming */
      clib_warning ("Send PUT: %v len: %d", ctx->target_uri,
		    vec_len (ctx->target_uri));

      ctx->msg.data.target_path_offset = 0;
      ctx->msg.data.headers_offset = ctx->msg.data.target_path_len;
      ctx->msg.data.body_offset =
	ctx->msg.data.headers_offset + ctx->msg.data.headers_len;
      ctx->msg.data.len =
	ctx->msg.data.target_path_len + ctx->msg.data.headers_len;

      /* Send HTTP headers */
      int rv = svm_fifo_enqueue (ctx->session->tx_fifo, sizeof (ctx->msg),
				 (u8 *) &ctx->msg);
      if (rv != sizeof (ctx->msg))
	{
	  clib_warning ("Failed to enqueue HTTP message header");
	  return -1;
	}

      /* Send target path */
      rv = svm_fifo_enqueue (ctx->session->tx_fifo,
			     ctx->msg.data.target_path_len, ctx->target_uri);
      if (rv != ctx->msg.data.target_path_len)
	{
	  clib_warning ("Failed to enqueue target path");
	  return -1;
	}

      /* Send headers */
      rv = svm_fifo_enqueue (ctx->session->tx_fifo,
			     ctx->req_headers.tail_offset, ctx->headers_buf);
      if (rv != ctx->req_headers.tail_offset)
	{
	  clib_warning ("Failed to enqueue headers");
	  return -1;
	}

      ctx->headers_sent = 1;
      u8 *start_data = get_pcapng_preamble_vec ();
      http_pcapng_chunk_write (ctx, start_data, vec_len (start_data));
      vec_free (start_data);

      /* Trigger TX event */
      if (svm_fifo_set_event (ctx->session->tx_fifo))
	{
	  session_program_tx_io_evt (ctx->session->handle, SESSION_IO_EVT_TX);
	}
    }

  wdi_set_ready_flag (s->opaque, 1);

  return 0;
}

static void
http_pcapng_session_disconnect_callback (session_t *s)
{
  http_pcapng_ctx_t *ctx = wdi_to_worker_context (s->opaque);

  if (ctx)
    {
      wdi_set_ready_flag (s->opaque, 0);

      ctx->connected = 0;
      ctx->session = NULL;

      /* Schedule retry with shorter timeout for disconnects */
      ctx->current_timeout = 0.1; /* 100ms for disconnect retries */
      schedule_retry (s->opaque, ctx);
    }
}

static void
http_pcapng_session_reset_callback (session_t *s)
{
  http_pcapng_session_disconnect_callback (s);
}

static int
http_pcapng_rx_callback (session_t *s)
{
  /* For uploads, we typically don't expect much response data
   * Just consume and log any response */
  u32 max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (max_deq > 0)
    {
      u8 *response_data = clib_mem_alloc (max_deq);
      if (response_data)
	{
	  svm_fifo_dequeue (s->rx_fifo, max_deq, response_data);
	  clib_warning ("HTTP PCAPng received %u bytes response", max_deq);
	  clib_mem_free (response_data);
	}
    }
  return 0;
}

static int
http_pcapng_tx_callback (session_t *s)
{
  /* Handle any pending transmission if needed */
  return 0;
}

static int session_manager_enabled = 0;
void
gpcapng_ensure_session_manager ()
{
  if (!session_manager_enabled)
    {
      vlib_main_t *vm = vlib_get_main ();
      enable_session_manager (vm);
      session_manager_enabled = 1;
    }
}

void
set_pcapng_output_http (gpcapng_dest_t *output)
{
  // FIXME: ensure enable_session_manager (vm) is called elsewhere !

  output->init = http_pcapng_init;
  output->flush = http_pcapng_flush;
  output->chunk_write = http_pcapng_chunk_write;
  output->cleanup = http_pcapng_cleanup;
  output->print_worker_context = print_http_context;

  /* Start HTTP retry process when first HTTP destination is configured */
  ensure_http_retry_process_started ();
}

int
pcapng_http_destination_add (char *url)
{
  gpcapng_ensure_session_manager ();
  clib_warning ("Adding HTTP destination to %s", url);
  return 0;
}
