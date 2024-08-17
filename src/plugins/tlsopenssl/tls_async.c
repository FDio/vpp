/*
 * Copyright (c) 2018 Intel and/or its affiliates.
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
#include <vnet/api_errno.h>
#include <vlib/node_funcs.h>
#include <openssl/engine.h>
#include <tlsopenssl/tls_openssl.h>
#include <dlfcn.h>

#define MAX_VECTOR_ASYNC    256

#define SSL_WANT_NAMES                                                        \
  {                                                                           \
    [0] = "N/A", [SSL_NOTHING] = "SSL_NOTHING",                               \
    [SSL_WRITING] = "SSL_WRITING", [SSL_READING] = "SSL_READING",             \
    [SSL_X509_LOOKUP] = "SSL_X509_LOOKUP",                                    \
    [SSL_ASYNC_PAUSED] = "SSL_ASYNC_PAUSED",                                  \
    [SSL_ASYNC_NO_JOBS] = "SSL_ASYNC_NO_JOBS",                                \
    [SSL_CLIENT_HELLO_CB] = "SSL_CLIENT_HELLO_CB",                            \
  }

static const char *ssl_want[] = SSL_WANT_NAMES;

#define foreach_ssl_evt_status_type_                                          \
  _ (INVALID_STATUS, "Async event invalid status")                            \
  _ (INFLIGHT, "Async event inflight")                                        \
  _ (READY, "Async event ready")                                              \
  _ (REENTER, "Async event reenter")                                          \
  _ (MAX_STATUS, "Async event max status")

typedef enum ssl_evt_status_type_
{
#define _(sym, str) SSL_ASYNC_##sym,
  foreach_ssl_evt_status_type_
#undef _
} ssl_evt_status_type_t;

typedef struct openssl_tls_callback_arg_
{
  int thread_index;
  int event_index;
} openssl_tls_callback_arg_t;

typedef struct openssl_event_
{
  u32 ctx_index;
  int session_index;
  ssl_evt_status_type_t status;
  ssl_async_evt_type_t type;

  openssl_resume_handler *handler;
  openssl_tls_callback_arg_t cb_args;
#define thread_idx cb_args.thread_index
#define event_idx cb_args.event_index
  int next;
} openssl_evt_t;

typedef struct openssl_async_queue_
{
  int evt_run_head;
  int evt_run_tail;
  int depth;
  int max_depth;
} openssl_async_queue_t;

typedef struct openssl_async_
{
  openssl_evt_t ***evt_pool;
  openssl_async_queue_t *queue;
  openssl_async_queue_t *queue_in_init;
  void (*polling) (void);
  u8 start_polling;
  ENGINE *engine;

} openssl_async_t;

void qat_polling ();
void qat_pre_init ();
void qat_polling_config ();
void dasync_polling ();

struct engine_polling
{
  char *engine;
  void (*polling) (void);
  void (*pre_init) (void);
  void (*thread_init) (void *);
};

void qat_init_thread (void *arg);

struct engine_polling engine_list[] = {
  { "qat", qat_polling, qat_pre_init, qat_init_thread },
  { "dasync", dasync_polling, NULL, NULL }
};

openssl_async_t openssl_async_main;
static vlib_node_registration_t tls_async_process_node;

/* to avoid build warning */
void session_send_rpc_evt_to_thread (u32 thread_index, void *fp,
				     void *rpc_args);

void
evt_pool_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  openssl_async_t *om = &openssl_async_main;
  int i, num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  TLS_DBG (2, "Totally there is %d thread\n", num_threads);

  vec_validate (om->evt_pool, num_threads - 1);
  vec_validate (om->queue, num_threads - 1);
  vec_validate (om->queue_in_init, num_threads - 1);

  om->start_polling = 0;
  om->engine = 0;

  for (i = 0; i < num_threads; i++)
    {
      om->queue[i].evt_run_head = -1;
      om->queue[i].evt_run_tail = -1;
      om->queue[i].depth = 0;
      om->queue[i].max_depth = 0;

      om->queue_in_init[i].evt_run_head = -1;
      om->queue_in_init[i].evt_run_tail = -1;
      om->queue_in_init[i].depth = 0;
      om->queue_in_init[i].max_depth = 0;
    }
  om->polling = NULL;

  return;
}

int
openssl_engine_register (char *engine_name, char *algorithm, int async)
{
  int i, registered = -1;
  openssl_async_t *om = &openssl_async_main;
  void (*p) (void);
  ENGINE *engine;

  for (i = 0; i < ARRAY_LEN (engine_list); i++)
    {
      if (!strcmp (engine_list[i].engine, engine_name))
	{
	  om->polling = engine_list[i].polling;
	  registered = i;
	}
    }
  if (registered < 0)
    {
      clib_error ("engine %s is not regisered in VPP", engine_name);
      return -1;
    }

  ENGINE_load_builtin_engines ();
  ENGINE_load_dynamic ();
  engine = ENGINE_by_id (engine_name);

  if (engine == NULL)
    {
      clib_warning ("Failed to find engine ENGINE_by_id %s", engine_name);
      return -1;
    }

  om->engine = engine;
  /* call pre-init */
  p = engine_list[registered].pre_init;
  if (p)
    (*p) ();

  if (algorithm)
    {
      if (!ENGINE_set_default_string (engine, algorithm))
	{
	  clib_warning ("Failed to set engine %s algorithm %s\n",
			engine_name, algorithm);
	  return -1;
	}
    }
  else
    {
      if (!ENGINE_set_default (engine, ENGINE_METHOD_ALL))
	{
	  clib_warning ("Failed to set engine %s to all algorithm",
			engine_name);
	  return -1;
	}
    }

  if (async)
    {
      openssl_async_node_enable_disable (1);
    }

  for (i = 0; i < vlib_num_workers (); i++)
    {
      if (engine_list[registered].thread_init)
	session_send_rpc_evt_to_thread (i + 1,
					engine_list[registered].thread_init,
					uword_to_pointer (i, void *));
    }

  om->start_polling = 1;

  return 0;

}

static openssl_evt_t *
openssl_evt_get (u32 evt_index)
{
  openssl_evt_t **evt;
  evt =
    pool_elt_at_index (openssl_async_main.evt_pool[vlib_get_thread_index ()],
		       evt_index);
  return *evt;
}

static openssl_evt_t *
openssl_evt_get_w_thread (int evt_index, u8 thread_index)
{
  openssl_evt_t **evt;

  evt =
    pool_elt_at_index (openssl_async_main.evt_pool[thread_index], evt_index);
  return *evt;
}

int
openssl_evt_free (int event_index, u8 thread_index)
{
  openssl_async_t *om = &openssl_async_main;

  /*pool operation */
  pool_put_index (om->evt_pool[thread_index], event_index);

  return 1;
}

static u32
openssl_evt_alloc (void)
{
  u8 thread_index = vlib_get_thread_index ();
  openssl_async_t *tm = &openssl_async_main;
  openssl_evt_t **evt;

  pool_get (tm->evt_pool[thread_index], evt);
  if (!(*evt))
    *evt = clib_mem_alloc (sizeof (openssl_evt_t));

  clib_memset (*evt, 0, sizeof (openssl_evt_t));
  (*evt)->event_idx = evt - tm->evt_pool[thread_index];
  return ((*evt)->event_idx);
}


/* In most cases, tls_async_openssl_callback is called by HW to make event active
 * When EAGAIN received, VPP will call this callback to retry
 */
int
tls_async_openssl_callback (SSL * s, void *cb_arg)
{
  openssl_evt_t *event, *event_tail;
  openssl_async_t *om = &openssl_async_main;
  openssl_tls_callback_arg_t *args = (openssl_tls_callback_arg_t *) cb_arg;
  int thread_index = args->thread_index;
  int event_index = args->event_index;
  int *evt_run_tail = &om->queue[thread_index].evt_run_tail;
  int *evt_run_head = &om->queue[thread_index].evt_run_head;

  TLS_DBG (2, "Set event %d to run\n", event_index);
  event = openssl_evt_get_w_thread (event_index, thread_index);

  /* Happend when a recursive case, especially in SW simulation */
  if (PREDICT_FALSE (event->status == SSL_ASYNC_READY))
    {
      event->status = SSL_ASYNC_REENTER;
      return 0;
    }
  event->status = SSL_ASYNC_READY;
  event->next = -1;

  if (*evt_run_tail >= 0)
    {
      event_tail = openssl_evt_get_w_thread (*evt_run_tail, thread_index);
      event_tail->next = event_index;
    }
  *evt_run_tail = event_index;
  if (*evt_run_head < 0)
    {
      *evt_run_head = event_index;
    }

  return 1;
}

/*
 * Continue an async SSL_write() call.
 * This function is _only_ called when continuing an SSL_write() call
 * that returned WANT_ASYNC.
 * Since it continues the handling of an existing, paused SSL job
 * (ASYNC_JOB*), the 'buf' and 'num' params to SSL_write() have
 * already been set in the initial call, and are meaningless here.
 * Therefore setting buf=null,num=0, to emphasize the point.
 * On successful write, TLS context total_write bytes are updated.
 */
static int
openssl_async_write_from_fifo_into_ssl (svm_fifo_t *f, SSL *ssl,
					tls_ctx_t *ctx)
{
  int wrote = 0;

  wrote = SSL_write (ssl, NULL, 0);
  ossl_check_err_is_fatal (ssl, wrote);

  ctx->total_write -= wrote;
  svm_fifo_dequeue_drop (f, wrote);

  return wrote;
}

/*
 * Perform SSL_write from TX FIFO head.
 * On successful write, TLS context total_write bytes are updated.
 */
static_always_inline int
openssl_write_from_fifo_head_into_ssl (svm_fifo_t *f, SSL *ssl, tls_ctx_t *ctx,
				       u32 max_len)
{
  int wrote = 0, rv, i = 0, len;
  u32 n_segs = 2;
  svm_fifo_seg_t fs[n_segs];

  max_len = clib_min (ctx->total_write, max_len);

  len = svm_fifo_segments (f, 0, fs, &n_segs, max_len);
  if (len <= 0)
    return 0;

  while (wrote < len && i < n_segs)
    {
      rv = SSL_write (ssl, fs[i].data, fs[i].len);
      wrote += (rv > 0) ? rv : 0;
      if (rv < (int) fs[i].len)
	break;
      i++;
    }

  if (wrote)
    {
      ctx->total_write -= wrote;
      svm_fifo_dequeue_drop (f, wrote);
    }

  return wrote;
}

static int
openssl_async_read_from_ssl_into_fifo (svm_fifo_t *f, SSL *ssl)
{
  int read;

  read = SSL_read (ssl, NULL, 0);
  if (read <= 0)
    return read;

  svm_fifo_enqueue_nocopy (f, read);

  return read;
}

/*
 * Pop the current event from queue and update tail if needed
 */
static void
tls_async_dequeue_update (openssl_evt_t *event, int *evt_run_head,
			  int *evt_run_tail, int *queue_depth)
{
  /* remove the event from queue head */
  *evt_run_head = event->next;
  event->status = SSL_ASYNC_INVALID_STATUS;
  event->next = -1;

  (*queue_depth)--;

  if (*evt_run_head < 0)
    {
      *evt_run_tail = -1;
      if (*queue_depth)
	clib_warning ("queue empty but depth:%d\n", *queue_depth);
    }
}

static int
tls_async_dequeue_event (int thread_index)
{
  openssl_evt_t *event;
  openssl_async_t *om = &openssl_async_main;
  openssl_async_queue_t *queue = om->queue;
  int *evt_run_tail = &queue[thread_index].evt_run_tail;
  int *evt_run_head = &queue[thread_index].evt_run_head;
  int dequeue_cnt = clib_min (queue[thread_index].depth, MAX_VECTOR_ASYNC);
  const u32 max_len = 128 << 10;

  /* dequeue all pending events, events enqueued during this routine call,
   * will be handled next time tls_async_dequeue_event is invoked */
  while (*evt_run_head >= 0 && dequeue_cnt--)
    {
      session_t *app_session, *tls_session;
      openssl_ctx_t *oc;
      tls_ctx_t *ctx;
      SSL *ssl;

      event = openssl_evt_get_w_thread (*evt_run_head, thread_index);
      ctx = openssl_ctx_get_w_thread (event->ctx_index, thread_index);
      oc = (openssl_ctx_t *) ctx;
      ssl = oc->ssl;

      if (event->type == SSL_ASYNC_EVT_RD)
	{
	  /* read event */
	  svm_fifo_t *app_rx_fifo, *tls_rx_fifo;
	  int read;

	  app_session = session_get_from_handle (ctx->app_session_handle);
	  app_rx_fifo = app_session->rx_fifo;

	  tls_session = session_get_from_handle (ctx->tls_session_handle);
	  tls_rx_fifo = tls_session->rx_fifo;

	  /* continue the paused job */
	  read = openssl_async_read_from_ssl_into_fifo (app_rx_fifo, ssl);
	  if (read < 0)
	    {
	      if (SSL_want_async (ssl))
		goto handle_later;

	      tls_async_dequeue_update (event, evt_run_head, evt_run_tail,
					&queue[thread_index].depth);
	      goto ev_rd_done;
	    }

	  /* read finished or in error, remove the event from queue */
	  tls_async_dequeue_update (event, evt_run_head, evt_run_tail,
				    &queue[thread_index].depth);

	  /* Unrecoverable protocol error. Reset connection */
	  if (PREDICT_FALSE ((read < 0) &&
			     (SSL_get_error (ssl, read) == SSL_ERROR_SSL)))
	    {
	      tls_notify_app_io_error (ctx);
	      goto ev_rd_done;
	    }

	  /*
	   * Managed to read some data. If handshake just completed, session
	   * may still be in accepting state.
	   */
	  if (app_session->session_state >= SESSION_STATE_READY)
	    tls_notify_app_enqueue (ctx, app_session);

	  /* managed to read, try to read more */
	  while (read > 0)
	    {
	      read =
		openssl_read_from_ssl_into_fifo (app_rx_fifo, ssl, max_len);
	      if (read < 0)
		{
		  if (SSL_want_async (ssl))
		    {
		      vpp_tls_async_enqueue_event (ctx, SSL_ASYNC_EVT_RD, NULL,
						   0);
		      goto ev_rd_queued;
		    }
		}

	      /* Unrecoverable protocol error. Reset connection */
	      if (PREDICT_FALSE ((read < 0) &&
				 (SSL_get_error (ssl, read) == SSL_ERROR_SSL)))
		{
		  tls_notify_app_io_error (ctx);
		  goto ev_rd_done;
		}

	      /* If handshake just completed, session may still be in accepting
	       * state */
	      if (read >= 0 &&
		  app_session->session_state >= SESSION_STATE_READY)
		tls_notify_app_enqueue (ctx, app_session);
	    }

	ev_rd_done:
	  /* read done */
	  ctx->in_async_read = false;

	  if ((SSL_pending (ssl) > 0) ||
	      svm_fifo_max_dequeue_cons (tls_rx_fifo))
	    {
	      tls_add_vpp_q_builtin_rx_evt (tls_session);
	    }

	ev_rd_queued:
	  continue;
	}
      else if (event->type == SSL_ASYNC_EVT_WR)
	{
	  /* write event */
	  int wrote, wrote_sum = 0;
	  u32 space, enq_buf;
	  svm_fifo_t *app_tx_fifo, *tls_tx_fifo;
	  transport_send_params_t *sp =
	    (transport_send_params_t *) event->handler;

	  app_session = session_get_from_handle (ctx->app_session_handle);
	  app_tx_fifo = app_session->tx_fifo;

	  /* continue the paused job */
	  wrote =
	    openssl_async_write_from_fifo_into_ssl (app_tx_fifo, ssl, ctx);
	  if (wrote < 0)
	    {
	      if (SSL_want_async (ssl))
		/* paused job not ready, wait */
		goto handle_later;
	      clib_warning ("[wrote:%d want:%s ctx:%d]\n", wrote,
			    ssl_want[SSL_want (ssl)], oc->openssl_ctx_index);
	    }
	  wrote_sum += wrote;

	  /* paused job done, remove event, update queue */
	  tls_async_dequeue_update (event, evt_run_head, evt_run_tail,
				    &queue[thread_index].depth);

	  /* Unrecoverable protocol error. Reset connection */
	  if (PREDICT_FALSE (wrote < 0))
	    {
	      tls_notify_app_io_error (ctx);
	      clib_warning (
		"Unrecoverable protocol error. Reset connection\n");
	      goto ev_in_queue;
	    }

	  tls_session = session_get_from_handle (ctx->tls_session_handle);
	  tls_tx_fifo = tls_session->tx_fifo;

	  /* prepare for remaining write(s) */
	  space = svm_fifo_max_enqueue_prod (tls_tx_fifo);
	  /* Leave a bit of extra space for tls ctrl data, if any needed */
	  space = clib_max ((int) space - TLSO_CTRL_BYTES, 0);

	  /* continue remaining openssl_ctx_write request */
	  while (ctx->total_write)
	    {
	      int rv;
	      u32 deq_max = svm_fifo_max_dequeue_cons (app_tx_fifo);

	      deq_max = clib_min (deq_max, space);
	      deq_max = clib_min (deq_max, sp->max_burst_size);
	      if (!deq_max)
		goto check_tls_fifo;

	      /* Make sure tcp's tx fifo can actually buffer all bytes to
	       * be dequeued. If under memory pressure, tls's fifo segment
	       * might not be able to allocate the chunks needed. This also
	       * avoids errors from the underlying custom bio to the ssl
	       * infra which at times can get stuck. */
	      if (svm_fifo_provision_chunks (tls_tx_fifo, 0, 0,
					     deq_max + TLSO_CTRL_BYTES))
		goto check_tls_fifo;

	      rv = openssl_write_from_fifo_head_into_ssl (app_tx_fifo, ssl,
							  ctx, deq_max);

	      /* Unrecoverable protocol error. Reset connection */
	      if (PREDICT_FALSE (rv < 0))
		{
		  tls_notify_app_io_error (ctx);
		  clib_warning (
		    "Unrecoverable protocol error. Reset connection\n");
		  goto ev_in_queue;
		}

	      if (!rv)
		{
		  if (SSL_want_async (ssl))
		    {
		      /* new paused job, add queue event and wait */
		      vpp_tls_async_enqueue_event (ctx, SSL_ASYNC_EVT_WR, sp,
						   0);
		      goto ev_in_queue;
		    }
		  clib_warning ("[rv:%d want:%s ctx:%d]\n", rv,
				ssl_want[SSL_want (ssl)],
				oc->openssl_ctx_index);
		  break;
		}
	      wrote_sum += rv;
	    }

	  if (svm_fifo_needs_deq_ntf (app_tx_fifo, wrote))
	    session_dequeue_notify (app_session);

	check_tls_fifo:
	  /* we got here, async write is done or not possible */
	  ctx->total_write = 0;

	  if (PREDICT_FALSE (BIO_ctrl_pending (oc->rbio) <= 0))
	    openssl_confirm_app_close (ctx);

	  /* Deschedule and wait for deq notification if fifo is almost full */
	  enq_buf =
	    clib_min (svm_fifo_size (tls_tx_fifo) / 2, TLSO_MIN_ENQ_SPACE);
	  if (space < wrote_sum + enq_buf)
	    {
	      svm_fifo_add_want_deq_ntf (tls_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	      transport_connection_deschedule (&ctx->connection);
	      sp->flags |= TRANSPORT_SND_F_DESCHED;
	    }
	  else
	    {
	      /* Request tx reschedule of the app session */
	      app_session->flags |= SESSION_F_CUSTOM_TX;
	      transport_connection_reschedule (&ctx->connection);
	    }

	ev_in_queue:
	  /* job removed, openssl_ctx_write will resume */
	  continue;
	}
      else
	{
	  /* wrong event type */
	  clib_warning ("goto remove_event [event->type:%d]\n", event->type);
	  tls_async_dequeue_update (event, evt_run_head, evt_run_tail,
				    &queue[thread_index].depth);
	}
    }

handle_later:
  return 1;
}

static int
tls_async_dequeue_event_in_init (int thread_index)
{
  openssl_evt_t *event;
  openssl_async_t *om = &openssl_async_main;
  openssl_async_queue_t *queue = om->queue_in_init;
  int *evt_run_tail = &queue[thread_index].evt_run_tail;
  int *evt_run_head = &queue[thread_index].evt_run_head;

  /* dequeue events if exists */
  while (*evt_run_head >= 0)
    {
      openssl_ctx_t *oc;
      tls_ctx_t *ctx;
      int rv, err;

      event = openssl_evt_get_w_thread (*evt_run_head, thread_index);
      ctx = openssl_ctx_get_w_thread (event->ctx_index, thread_index);
      oc = (openssl_ctx_t *) ctx;

      if (event->type != SSL_ASYNC_EVT_INIT)
	{
	  /* wrong event type */
	  clib_warning ("goto remove_event [event->type:%d]\n", event->type);
	  goto remove_event;
	}

      if (!SSL_in_init (oc->ssl))
	{
	  clib_warning ("[!SSL_in_init() != ev->type:%d] th:%d ev:%d\n",
			event->type, event->cb_args.thread_index,
			event->cb_args.event_index);
	  goto remove_event;
	}

      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);

      /* Do not remove session from tail */
      if (err == SSL_ERROR_WANT_ASYNC)
	goto handle_later;

      if (err == SSL_ERROR_SSL)
	{
	  char buf[512];
	  ERR_error_string (ERR_get_error (), buf);
	  clib_warning ("Err: %s\n", buf);
	  openssl_handle_handshake_failure (ctx);
	  goto remove_event;
	}

      if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
	goto handle_later;

      /* client not supported */
      if (!SSL_is_server (oc->ssl))
	{
	  clib_warning ("goto remove_event [!SSL_is_server]\n");
	  goto remove_event;
	}

      if (tls_notify_app_accept (ctx))
	{
	  ctx->c_s_index = SESSION_INVALID_INDEX;
	  tls_disconnect_transport (ctx);
	}

      TLS_DBG (1, "Handshake for %u complete. TLS cipher is %s",
	       oc->openssl_ctx_index, SSL_get_cipher (oc->ssl));

    remove_event:
      *evt_run_head = event->next;
      queue[thread_index].depth--;

      if (*evt_run_head < 0)
	{
	  /* queue empty, bail out */
	  *evt_run_tail = -1;
	  if (queue[thread_index].depth)
	    clib_warning ("queue empty but depth:%d\n",
			  queue[thread_index].depth);
	  break;
	}
    }

handle_later:
  return 1;
}

int
vpp_tls_async_enqueue_event (tls_ctx_t *ctx, int evt_type,
			     transport_send_params_t *sp, int size)
{
  openssl_evt_t *event;
  openssl_async_t *om = &openssl_async_main;
  openssl_async_queue_t *queue;
  openssl_ctx_t *oc;
  int thread_index;
  int event_index;
  int *evt_run_tail;
  int *evt_run_head;

  event = openssl_evt_get (ctx->evt_index[evt_type]);

  thread_index = event->thread_idx;
  event_index = event->event_idx;

  oc = (openssl_ctx_t *) ctx;

  /* set queue to be used */
  if (SSL_in_init (oc->ssl))
    queue = om->queue_in_init;
  else
    queue = om->queue;

  evt_run_tail = &queue[thread_index].evt_run_tail;
  evt_run_head = &queue[thread_index].evt_run_head;

  event->type = SSL_ASYNC_EVT_INIT;
  event->handler = (openssl_resume_handler *) sp;
  event->next = -1;

  /* first we enqueue the request */
  if (*evt_run_tail >= 0)
    {
      openssl_evt_t *event_tail;

      /* queue not empty, append to tail event */
      event_tail = openssl_evt_get_w_thread (*evt_run_tail, thread_index);
      event_tail->next = event_index;
    }

  /* set tail to use new event index */
  *evt_run_tail = event_index;

  if (*evt_run_head < 0)
    /* queue is empty, update head */
    *evt_run_head = event_index;

  queue[thread_index].depth++;
  if (queue[thread_index].depth > queue[thread_index].max_depth)
    queue[thread_index].max_depth = queue[thread_index].depth;

  return 1;
}

static int
vpp_tls_async_init_event (tls_ctx_t *ctx, openssl_resume_handler *handler,
			  session_t *session, ssl_async_evt_type_t evt_type)
{
  u32 eidx;
  openssl_evt_t *event;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 thread_id = ctx->c_thread_index;

  eidx = openssl_evt_alloc ();
  event = openssl_evt_get (eidx);
  event->ctx_index = oc->openssl_ctx_index;
  event->event_idx = eidx;
  event->thread_idx = thread_id;
  event->handler = NULL;
  event->session_index = session->session_index;
  event->type = evt_type;
  event->status = SSL_ASYNC_INVALID_STATUS;
  ctx->evt_index[evt_type] = eidx;

  return 1;
}

int
vpp_tls_async_init_events (tls_ctx_t *ctx, openssl_resume_handler *handler,
			   session_t *session)
{
  vpp_tls_async_init_event (ctx, handler, session, SSL_ASYNC_EVT_INIT);
  vpp_tls_async_init_event (ctx, handler, session, SSL_ASYNC_EVT_RD);
  vpp_tls_async_init_event (ctx, handler, session, SSL_ASYNC_EVT_WR);

  return 1;
}

int
vpp_openssl_is_inflight (tls_ctx_t *ctx)
{
  u32 eidx;
  openssl_evt_t *event;
  int i;

  for (i = SSL_ASYNC_EVT_INIT; i < SSL_ASYNC_EVT_MAX; i++)
    {
      eidx = ctx->evt_index[i];
      event = openssl_evt_get (eidx);

      if (event->status == SSL_ASYNC_INFLIGHT)
	return 1;
    }

  return 0;
}

int
vpp_tls_async_update_event (tls_ctx_t *ctx, int eagain,
			    ssl_async_evt_type_t type)
{
  u32 eidx;
  openssl_evt_t *event;

  eidx = ctx->evt_index[type];
  event = openssl_evt_get (eidx);
  event->status = SSL_ASYNC_INFLIGHT;
  if (eagain)
    return tls_async_openssl_callback (0, &event->cb_args);

  return 1;
}

void
event_handler (void *tls_async)
{
  openssl_resume_handler *handler;
  openssl_evt_t *event;
  session_t *session;
  int thread_index;
  tls_ctx_t *ctx;

  event = (openssl_evt_t *) tls_async;
  thread_index = event->thread_idx;
  ctx = openssl_ctx_get_w_thread (event->ctx_index, thread_index);
  handler = event->handler;
  session = session_get (event->session_index, thread_index);

  if (handler)
    {
      (*handler) (ctx, session);
    }

  return;
}

 /* engine specific code to polling the response ring */
void
dasync_polling ()
{
/* dasync is a fake async device, and could not be polled.
 * We have added code in the dasync engine to triggered the callback already,
 * so nothing can be done here
 */
}

void
qat_pre_init ()
{
  openssl_async_t *om = &openssl_async_main;

  ENGINE_ctrl_cmd (om->engine, "ENABLE_EXTERNAL_POLLING", 0, NULL, NULL, 0);
}

/* Below code is spefic to QAT engine, and other vendors can refer to this code to enable a new engine */
void
qat_init_thread (void *arg)
{
  openssl_async_t *om = &openssl_async_main;
  int thread_index = pointer_to_uword (arg);

  ENGINE_ctrl_cmd (om->engine, "SET_INSTANCE_FOR_THREAD", thread_index,
		   NULL, NULL, 0);

  TLS_DBG (2, "set thread %d and instance %d mapping\n", thread_index,
	   thread_index);

}

void
qat_polling ()
{
  openssl_async_t *om = &openssl_async_main;
  int poll_status = 0;

  if (om->start_polling)
    {
      ENGINE_ctrl_cmd (om->engine, "POLL", 0, &poll_status, NULL, 0);
    }
}

void
openssl_async_polling ()
{
  openssl_async_t *om = &openssl_async_main;
  if (om->polling)
    {
      (*om->polling) ();
    }
}

void
openssl_async_node_enable_disable (u8 is_en)
{
  u8 state = is_en ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u8 have_workers = vtm->n_threads != 0;

  foreach_vlib_main ()
    {
      if (have_workers && this_vlib_main->thread_index)
	{
	  vlib_node_set_state (this_vlib_main, tls_async_process_node.index,
			       state);
	}
    }
}

int
tls_async_do_job (int eidx, u32 thread_index)
{
  tls_ctx_t *ctx;
  openssl_evt_t *event;

  /* do the real job */
  event = openssl_evt_get_w_thread (eidx, thread_index);
  ctx = openssl_ctx_get_w_thread (event->ctx_index, thread_index);

  if (ctx)
    {
      ctx->flags |= TLS_CONN_F_RESUME;
      session_send_rpc_evt_to_thread (thread_index, event_handler, event);
    }
  return 1;
}

int
tls_resume_from_crypto (int thread_index)
{
  int i;

  openssl_async_t *om = &openssl_async_main;
  openssl_evt_t *event;
  int *evt_run_head = &om->queue[thread_index].evt_run_head;
  int *evt_run_tail = &om->queue[thread_index].evt_run_tail;

  if (*evt_run_head < 0)
    return 0;

  for (i = 0; i < MAX_VECTOR_ASYNC; i++)
    {
      if (*evt_run_head >= 0)
	{
	  event = openssl_evt_get_w_thread (*evt_run_head, thread_index);
	  tls_async_do_job (*evt_run_head, thread_index);
	  if (PREDICT_FALSE (event->status == SSL_ASYNC_REENTER))
	    {
	      /* recusive event triggered */
	      event->status = SSL_ASYNC_READY;
	      continue;
	    }

	  event->status = SSL_ASYNC_INVALID_STATUS;
	  *evt_run_head = event->next;

	  if (event->next < 0)
	    {
	      *evt_run_tail = -1;
	      break;
	    }
	}
    }

  return 0;

}

static clib_error_t *
tls_async_init (vlib_main_t * vm)
{
  evt_pool_init (vm);
  return 0;
}

static uword
tls_async_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		   vlib_frame_t * f)
{
  u8 thread_index;
  openssl_async_t *om = &openssl_async_main;

  thread_index = vlib_get_thread_index ();
  if (pool_elts (om->evt_pool[thread_index]) > 0)
    {
      tls_async_dequeue_event_in_init (thread_index);
      tls_async_dequeue_event (thread_index);
    }

  return 0;
}

VLIB_INIT_FUNCTION (tls_async_init);

VLIB_REGISTER_NODE (tls_async_process_node,static) = {
    .function = tls_async_process,
    .type = VLIB_NODE_TYPE_INPUT,
    .name = "tls-async-process",
    .state = VLIB_NODE_STATE_DISABLED,
};


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
