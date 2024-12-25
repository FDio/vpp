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

const char *ssl_want[] = SSL_WANT_NAMES;

#define foreach_ssl_evt_status_type_                                          \
  _ (INVALID_STATUS, "Async event invalid status")                            \
  _ (INFLIGHT, "Async event inflight")                                        \
  _ (READY, "Async event ready")                                              \
  _ (REENTER, "Async event reenter")                                          \
  _ (DEQ_DONE, "Async event dequeued")                                        \
  _ (CB_EXECUTED, "Async callback executed")                                  \
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
  ssl_async_evt_type_t async_evt_type;
  openssl_resume_handler *evt_handler;
} openssl_tls_callback_arg_t;

typedef struct openssl_event_
{
  u32 ctx_index;
  int session_index;
  ssl_evt_status_type_t status;

  transport_send_params_t *tran_sp;
  openssl_tls_callback_arg_t cb_args;
#define thread_idx cb_args.thread_index
#define event_idx cb_args.event_index
#define async_event_type  cb_args.async_evt_type
#define async_evt_handelr cb_args.evt_handler
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
void dpdk_engine_init_thread (void *arg);

struct engine_polling engine_list[] = {
  { "qat", qat_polling, qat_pre_init, qat_init_thread },
  { "dpdk_engine", qat_polling, NULL, dpdk_engine_init_thread },
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
  ssl_async_evt_type_t evt_type = args->async_evt_type;
  openssl_async_queue_t *queue;
  int *evt_run_tail, *evt_run_head;

  TLS_DBG (2, "Set event %d to run\n", event_index);
  event = openssl_evt_get_w_thread (event_index, thread_index);

  if (evt_type == SSL_ASYNC_EVT_INIT)
    queue = om->queue_in_init;
  else
    queue = om->queue;

  evt_run_tail = &queue[thread_index].evt_run_tail;
  evt_run_head = &queue[thread_index].evt_run_head;

  /* Happend when a recursive case, especially in SW simulation */
  if (PREDICT_FALSE (event->status == SSL_ASYNC_READY))
    {
      TLS_DBG (2, "EVT: %p ASYNC_ALREADY Set", event);
      event->status = SSL_ASYNC_REENTER;
      return 0;
    }
  event->status = SSL_ASYNC_READY;
  event->next = -1;

  if (*evt_run_head < 0)
    *evt_run_head = event_index;
  else if (*evt_run_tail >= 0)
    {
      event_tail = openssl_evt_get_w_thread (*evt_run_tail, thread_index);
      event_tail->next = event_index;
    }

  queue[thread_index].depth++;
  if (queue[thread_index].depth > queue[thread_index].max_depth)
    queue[thread_index].max_depth = queue[thread_index].depth;

  *evt_run_tail = event_index;

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
 * On successful write, TLS context total_async_write bytes are updated.
 */
int
openssl_async_write_from_fifo_into_ssl (svm_fifo_t *f, SSL *ssl,
					openssl_ctx_t *ctx)
{
  int wrote = 0;

  wrote = SSL_write (ssl, NULL, 0);
  ossl_check_err_is_fatal (ssl, wrote);

  ctx->total_async_write -= wrote;
  TLS_DBG (2, "ASYNC_WROTE_DONE: %d", wrote);
  TLS_DBG (2, "CTX_TOTAL_ASYNC_WRITE: %d, wrote: %d", ctx->total_async_write,
	   wrote);
  svm_fifo_dequeue_drop (f, wrote);

  return wrote;
}

/*
 * Perform SSL_write from TX FIFO head.
 * On successful write, TLS context total_async_write bytes are updated.
 */
int
openssl_write_from_fifo_head_into_ssl (svm_fifo_t *f, SSL *ssl,
				       openssl_ctx_t *ctx, u32 max_len)
{
  int wrote = 0, rv, i = 0, len;
  u32 n_segs = 2;
  svm_fifo_seg_t fs[n_segs];

  max_len = clib_min (ctx->total_async_write, max_len);
  TLS_DBG (2, "MAX_FIFO_SEG_LEN: %d", max_len);

  len = svm_fifo_segments (f, 0, fs, &n_segs, max_len);
  if (len <= 0)
    {
      TLS_DBG (2, "CTX_TOTAL_WRITE: %d Wrote: %d", ctx->total_async_write,
	       wrote);
      return 0;
    }

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
      ctx->total_async_write -= wrote;
      svm_fifo_dequeue_drop (f, wrote);
    }
  TLS_DBG (2, "CTX_TOTAL_WRITE: %d Wrote: %d", ctx->total_async_write, wrote);

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

int
vpp_tls_async_enqueue_event (openssl_ctx_t *ctx, int evt_type,
			     transport_send_params_t *sp, int size)
{
  openssl_evt_t *event;
  openssl_async_t *om = &openssl_async_main;
  openssl_async_queue_t *queue;
  int thread_index;
  int event_index;
  int *evt_run_tail;
  int *evt_run_head;

  event = openssl_evt_get (ctx->evt_index[evt_type]);
  TLS_DBG (2, "GOT_EVT: %p for TYPE: %d status: %d", event, evt_type,
	   event->status);

  if (event->status == SSL_ASYNC_INFLIGHT)
    {
      clib_warning ("EVT_TYPE: %d already inflight", event->async_event_type);
      return 0;
    }

  thread_index = event->thread_idx;
  event_index = event->event_idx;

  TLS_DBG (2, "RETRIEVED EVT_TYPE: %d", event->async_event_type);

  /* set queue to be used */
  if (evt_type == SSL_ASYNC_EVT_INIT)
    queue = om->queue_in_init;
  else
    queue = om->queue;

  evt_run_tail = &queue[thread_index].evt_run_tail;
  evt_run_head = &queue[thread_index].evt_run_head;

  event->tran_sp = sp;
  event->next = -1;
  event->status = SSL_ASYNC_INFLIGHT;

  TLS_DBG (2, "CURRENT_QUEUE_DEPTH_FOR_TYPE_%d: %d", evt_type,
	   queue[thread_index].depth);
  /* first we enqueue the request */
  if (*evt_run_head < 0)
    {
      TLS_DBG (2, "EVENT_TYPE_%d_ADDED_TO_HEAD", evt_type);
      /* queue is empty, update head */
      *evt_run_head = event_index;
    }
  else if (*evt_run_tail >= 0)
    {
      TLS_DBG (2, "EVENT_TYPE_%d_ADDED_TO_TAIL", evt_type);
      openssl_evt_t *event_tail;
      /* queue not empty, append to tail event */
      event_tail = openssl_evt_get_w_thread (*evt_run_tail, thread_index);
      event_tail->next = event_index;
      /* set tail to use new event index */
      *evt_run_tail = event_index;
    }
  else
    TLS_DBG (2, "HEAD_NOT_EMPTY_TAIL_GT_0_TYPE_%d", evt_type);

  queue[thread_index].depth++;
  if (queue[thread_index].depth > queue[thread_index].max_depth)
    queue[thread_index].max_depth = queue[thread_index].depth;

  TLS_DBG (2, "UPDATED_QUEUE_DEPTH: %d", queue[thread_index].depth);

  return 1;
}

int
vpp_tls_async_init_event (tls_ctx_t *ctx, openssl_resume_handler *handler,
			  transport_send_params_t *sp, session_t *session,
			  ssl_async_evt_type_t evt_type, int wr_size)
{
  u32 eidx;
  openssl_evt_t *event = NULL;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 thread_id = ctx->c_thread_index;

  if (oc->evt_alloc_flag[evt_type])
    {
      eidx = oc->evt_index[evt_type];
      TLS_DBG (2, "EVENT_ALREADY_ALLOTED: %d", eidx);
      if (evt_type == SSL_ASYNC_EVT_WR)
	{
	  event = openssl_evt_get (eidx);
	  goto update_wr_evnt;
	}
      return 1;
    }
  else
    {
      eidx = openssl_evt_alloc ();
      oc->evt_alloc_flag[evt_type] = true;
      TLS_DBG (2, "NEW_EVENT_ALLOTED: %d", eidx);
    }

  event = openssl_evt_get (eidx);
  event->ctx_index = oc->openssl_ctx_index;
  /* async call back args */
  event->event_idx = eidx;
  event->thread_idx = thread_id;
  event->async_event_type = evt_type;
  event->async_evt_handelr = handler;
  event->session_index = session->session_index;
  event->status = SSL_ASYNC_INVALID_STATUS;
  oc->evt_index[evt_type] = eidx;
  TLS_DBG (2, "EVT: %p ALLOTED_FOR_TYPE_%d: EIDX: %d TID: %d", event, evt_type,
	   event->event_idx, event->thread_idx);
#ifdef HAVE_OPENSSL_ASYNC
  SSL_set_async_callback_arg (oc->ssl, &event->cb_args);
#endif
update_wr_evnt:
  if (evt_type == SSL_ASYNC_EVT_WR)
    {
      transport_connection_deschedule (&ctx->connection);
      sp->flags |= TRANSPORT_SND_F_DESCHED;
      TLS_DBG (2, "BEFORE_TOTAL_ASYNC_WRITE_UPDATED: %d",
	       oc->total_async_write);
      oc->total_async_write = wr_size;
      TLS_DBG (2, "TOTAL_ASYNC_WRITE_UPDATED: %d", oc->total_async_write);
    }
  event->tran_sp = sp;
  return 1;
}

int
vpp_openssl_is_inflight (tls_ctx_t *ctx)
{
  u32 eidx;
  openssl_evt_t *event;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int i;

  for (i = SSL_ASYNC_EVT_INIT; i < SSL_ASYNC_EVT_MAX; i++)
    {
      eidx = oc->evt_index[i];
      event = openssl_evt_get (eidx);

      if (event->status == SSL_ASYNC_INFLIGHT)
	return 1;
    }

  return 0;
}

void
event_handler (void *tls_async)
{
  openssl_resume_handler *handler;
  openssl_evt_t *event;
  session_t *session;
  int thread_index;

  event = (openssl_evt_t *) tls_async;
  thread_index = event->thread_idx;
  handler = event->async_evt_handelr;
  session = session_get (event->session_index, thread_index);

  if (handler)
    {
      TLS_DBG (2, "GOT_EVT: %p for TYPE: %d status: %d", event,
	       event->async_event_type, event->status);
      (*handler) (event, session);
      event->status = SSL_ASYNC_CB_EXECUTED;
      TLS_DBG (2, "AFTER_CB_EXECUTION_FOR_EVT: %p for TYPE: %d status: %d",
	       event, event->async_event_type, event->status);
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
dpdk_engine_init_thread (void *arg)
{
  vlib_main_t *vm = vlib_get_main ();
  tls_main_t *tm = vnet_tls_get_main ();
  void *handle = NULL;

  if (tm && tm->engine_path)
    handle = dlopen ((char *) tm->engine_path, RTLD_LAZY);

  if (!handle)
    {
      clib_warning ("dpdk engline library not found");
      return;
    }

  u64 *(*fn) () = dlsym (handle, "dpdk_rte_thread_register");

  if (fn)
    {
      if (fn () < 0)
        clib_warning ("dpdk: cannot register thread %u", vm->thread_index);
    }
  else
    clib_warning ("dpdk_rte_thread_register symbol not found");
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
handle_async_cb_events (openssl_async_queue_t *queue, int thread_index)
{
  int i;
  openssl_evt_t *event;

  int *evt_run_head = &queue[thread_index].evt_run_head;
  int *evt_run_tail = &queue[thread_index].evt_run_tail;

  if (*evt_run_head < 0)
    return 0;

  for (i = 0; i < MAX_VECTOR_ASYNC; i++)
    {
      if (*evt_run_head >= 0 && queue[thread_index].depth)
	{
	  TLS_DBG (8, "HEAD_EVT_INDEX: %d CUR_DEPTH: %d", *evt_run_head,
		   queue[thread_index].depth);
	  event = openssl_evt_get_w_thread (*evt_run_head, thread_index);
	  if (PREDICT_FALSE (event->status == SSL_ASYNC_REENTER))
	    {
	      TLS_DBG (2, "REENTER_TRIGGERED");
	      /* recusive event triggered */
	      goto deq_event;
	    }
	  tls_async_do_job (*evt_run_head, thread_index);

	deq_event:
	  *evt_run_head = event->next;
	  event->status = SSL_ASYNC_DEQ_DONE;
	  queue[thread_index].depth--;
	  TLS_DBG (8, "AFTER_ASYNC_JOB_CUR_DEPTH: %d",
		   queue[thread_index].depth);

	  if (*evt_run_head < 0)
	    {
	      *evt_run_tail = -1;
	      TLS_DBG (8, "EVTS_DEQ_DONE");
	      break;
	    }
	}
    }

  return 0;
}

void
resume_handshake_events (int thread_index)
{
  openssl_async_t *om = &openssl_async_main;

  openssl_async_queue_t *queue = om->queue_in_init;
  handle_async_cb_events (queue, thread_index);
}

void
resume_read_write_events (int thread_index)
{
  openssl_async_t *om = &openssl_async_main;

  openssl_async_queue_t *queue = om->queue;
  handle_async_cb_events (queue, thread_index);
}

int
tls_resume_from_crypto (int thread_index)
{
  resume_read_write_events (thread_index);
  resume_handshake_events (thread_index);
  return 0;
}

static clib_error_t *
tls_async_init (vlib_main_t * vm)
{
  evt_pool_init (vm);
  return 0;
}

int
tls_async_handshake_event_handler (void *async_evt, void *unused)
{
  openssl_evt_t *event = (openssl_evt_t *) async_evt;
  int thread_index = event->thread_idx;
  openssl_ctx_t *oc;
  tls_ctx_t *ctx;
  int rv, err;

  ctx = openssl_ctx_get_w_thread (event->ctx_index, thread_index);
  oc = (openssl_ctx_t *) ctx;
  session_t *tls_session = session_get_from_handle (ctx->tls_session_handle);

  if (!SSL_in_init (oc->ssl))
    {
      TLS_DBG (8, "[!SSL_in_init]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       event->event_idx);
      return 0;
    }

  if (ctx->flags & TLS_CONN_F_RESUME)
    {
      ctx->flags &= ~TLS_CONN_F_RESUME;
    }
  else if (!svm_fifo_max_dequeue_cons (tls_session->rx_fifo))
    {
      TLS_DBG (8, "FIFO_DEQ_CONS_BREAK:==>CTX: %p EVT: %p EIDX: %d", ctx,
	       event, event->event_idx);
      return 0;
    }

  rv = SSL_do_handshake (oc->ssl);
  err = SSL_get_error (oc->ssl, rv);

  /* Do not remove session from tail */
  if (err == SSL_ERROR_WANT_ASYNC)
    {
      TLS_DBG (2, "[STILL_WANT_ASYNC]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       event->event_idx);
      return 0;
    }

  if (err == SSL_ERROR_SSL)
    {
      char buf[512];
      ERR_error_string (ERR_get_error (), buf);
      TLS_DBG (2, "[SSL_ERROR_SSL]==>CTX: %p EVT: %p EIDX: %d Buf: %s", ctx,
	       event, event->event_idx, buf);
      return 0;
    }

  if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
    {
      TLS_DBG (2, "[SSL_ERR_WANT_WR_OR_RD]==>CTX: %p EVT: %p EIDX: %d", ctx,
	       event, event->event_idx);
      return 0;
    }

  /* client not supported */
  if (!SSL_is_server (oc->ssl))
    {
      TLS_DBG (2, "[SSL_is_server]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       event->event_idx);
      return 0;
    }

  /* Need to check transport status */
  if (ctx->flags & TLS_CONN_F_PASSIVE_CLOSE)
    {
      openssl_handle_handshake_failure (ctx);
      TLS_DBG (2, "[PASSIVE_CLOSE]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       thread_index);
      return 0;
    }

  if (tls_notify_app_accept (ctx))
    {
      TLS_DBG (2, "[APP_ACCEPT]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       event->event_idx);
      ctx->c_s_index = SESSION_INVALID_INDEX;
      tls_disconnect_transport (ctx);
    }

  TLS_DBG (1,
	   "<=====Handshake for %u complete. TLS cipher is %s EVT: %p =====>",
	   oc->openssl_ctx_index, SSL_get_cipher (oc->ssl), event);

  return 1;
}

int
tls_async_read_event_handler (void *async_evt, void *unused)
{
  openssl_evt_t *event = (openssl_evt_t *) async_evt;
  int thread_index = event->thread_idx;
  session_t *app_session, *tls_session;
  openssl_ctx_t *oc;
  tls_ctx_t *ctx;
  SSL *ssl;

  ctx = openssl_ctx_get_w_thread (event->ctx_index, thread_index);
  oc = (openssl_ctx_t *) ctx;
  ssl = oc->ssl;

  ctx->flags |= TLS_CONN_F_ASYNC_RD;
  /* read event */
  svm_fifo_t *app_rx_fifo, *tls_rx_fifo;
  int read, err;

  app_session = session_get_from_handle (ctx->app_session_handle);
  app_rx_fifo = app_session->rx_fifo;

  tls_session = session_get_from_handle (ctx->tls_session_handle);
  tls_rx_fifo = tls_session->rx_fifo;

  /* continue the paused job */
  read = openssl_async_read_from_ssl_into_fifo (app_rx_fifo, ssl);
  err = SSL_get_error (oc->ssl, read);
  if (err == SSL_ERROR_WANT_ASYNC)
    {
      TLS_DBG (2, "[STILL_WANT_ASYNC]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       thread_index);
      return 0;
    }

  if (read <= 0)
    {
      if (SSL_want_async (ssl))
	{
	  TLS_DBG (2, "[READ_STILL_WANT_ASYNC]==>CTX: %p EVT: %p EIDX: %d",
		   ctx, event, thread_index);
	  return 0;
	}
      goto ev_rd_done;
    }

  /* Unrecoverable protocol error. Reset connection */
  if (PREDICT_FALSE ((read <= 0) &&
		     (SSL_get_error (ssl, read) == SSL_ERROR_SSL)))
    {
      TLS_DBG (2, "[SSL_ERROR]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       thread_index);
      tls_notify_app_io_error (ctx);
      goto ev_rd_done;
    }

  /*
   * Managed to read some data. If handshake just completed, session
   * may still be in accepting state.
   */
  if (app_session->session_state >= SESSION_STATE_READY)
    {
      TLS_DBG (2, "READ_DONE_AND_ENQ: %d EVT: %p", read, event);
      tls_notify_app_enqueue (ctx, app_session);
    }

ev_rd_done:
  /* read done */
  ctx->flags &= ~TLS_CONN_F_ASYNC_RD;

  if ((SSL_pending (ssl) > 0) || svm_fifo_max_dequeue_cons (tls_rx_fifo))
    {
      TLS_DBG (2, "[READ_DONE]==>CTX: %p EVT: %p EIDX: %d READ: %d", ctx,
	       event, thread_index, read);
      tls_add_vpp_q_builtin_rx_evt (tls_session);
    }

  return 1;
}

int
tls_async_write_event_handler (void *async_evt, void *unused)
{
  openssl_evt_t *event = (openssl_evt_t *) async_evt;
  int thread_index = event->thread_idx;
  session_t *app_session, *tls_session;
  openssl_ctx_t *oc;
  tls_ctx_t *ctx;
  SSL *ssl;

  ctx = openssl_ctx_get_w_thread (event->ctx_index, thread_index);
  oc = (openssl_ctx_t *) ctx;
  ssl = oc->ssl;

  /* write event */
  int wrote = 0;
  u32 space, enq_buf;
  svm_fifo_t *app_tx_fifo, *tls_tx_fifo;
  transport_send_params_t *sp = event->tran_sp;

  app_session = session_get_from_handle (ctx->app_session_handle);
  app_tx_fifo = app_session->tx_fifo;

  /* continue the paused job */
  wrote = openssl_async_write_from_fifo_into_ssl (app_tx_fifo, ssl, oc);
  if (!wrote)
    {
      /* paused job not ready, wait */
      if (SSL_want_async (ssl))
	{
	  TLS_DBG (2, "[STILL_WANT_ASYNC] EVT: %p EIDX: %d", event,
		   event->event_idx);
	  return 0;
	}
      TLS_DBG (2, "[wrote:%d want:%s ctx:%d]\n", wrote,
	       ssl_want[SSL_want (ssl)], oc->openssl_ctx_index);
    }

  /* Unrecoverable protocol error. Reset connection */
  if (PREDICT_FALSE (wrote < 0))
    {
      tls_notify_app_io_error (ctx);
      TLS_DBG (2, "[PROTOCOL_ERR] EVT: %p EIDX: %d", event, thread_index);
      return 0;
    }

  tls_session = session_get_from_handle (ctx->tls_session_handle);
  tls_tx_fifo = tls_session->tx_fifo;

  /* prepare for remaining write(s) */
  space = svm_fifo_max_enqueue_prod (tls_tx_fifo);
  TLS_DBG (2, "MAX_ENQ_PROD: %d", space);
  /* Leave a bit of extra space for tls ctrl data, if any needed */
  space = clib_max ((int) space - TLSO_CTRL_BYTES, 0);
  TLS_DBG (2, "MAX_ENQ_PROD_CTRL_BYTES: %d", space);

  if (svm_fifo_needs_deq_ntf (app_tx_fifo, wrote))
    {
      TLS_DBG (2, "[DEQ_NOTIFY] EVT: %p EIDX: %d Total_write: %d", event,
	       event->event_idx, oc->total_async_write);
      session_dequeue_notify (app_session);
    }

  /* we got here, async write is done or not possible */
  oc->total_async_write = 0;

  if (PREDICT_FALSE (ctx->flags & TLS_CONN_F_APP_CLOSED &&
		     BIO_ctrl_pending (oc->rbio) <= 0))
    {
      TLS_DBG (2, "[APP_CLOSED]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       event->event_idx);
      openssl_confirm_app_close (ctx);
    }

  /* Deschedule and wait for deq notification if fifo is almost full */
  TLS_DBG (2, "SVM_FIFO_SIZE: %d", svm_fifo_size (tls_tx_fifo));
  enq_buf = clib_min (svm_fifo_size (tls_tx_fifo) / 2, TLSO_MIN_ENQ_SPACE);
  if (space < wrote + enq_buf)
    {
      TLS_DBG (2, "[SPACE_LT]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       thread_index);
      svm_fifo_add_want_deq_ntf (tls_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      transport_connection_deschedule (&ctx->connection);
      sp->flags |= TRANSPORT_SND_F_DESCHED;
    }
  else
    {
      TLS_DBG (2, "[SPACE_NOT_LT]==>CTX: %p EVT: %p EIDX: %d", ctx, event,
	       event->event_idx);
      /* Request tx reschedule of the app session */
      app_session->flags |= SESSION_F_CUSTOM_TX;
      transport_connection_reschedule (&ctx->connection);
    }

  return 1;
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
      openssl_async_polling ();
      tls_resume_from_crypto (thread_index);
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
