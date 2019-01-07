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
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vlib/node_funcs.h>
#include <openssl/engine.h>
#include <tlsopenssl/tls_openssl.h>

#define MAX_SESSION	    4096
#define MAX_VECTOR_ASYNC    256

#define SSL_ASYNC_INFLIGHT  1
#define SSL_ASYNC_PENDING   2
#define SSL_ASYNC_READY     3

#define EMPTY_STRUCT {0}

typedef struct openssl_tls_callback_arg_
{
  int thread_index;
  int event_index;
} openssl_tls_callback_arg_t;

typedef struct openssl_event_
{
  int status;
  u32 event_index;
  u8 thread_index;
  u32 ctx_index;

  openssl_resume_handler *handler;
  openssl_tls_callback_t engine_callback;
  openssl_tls_callback_arg_t cb_args;

  int next;
} openssl_evt_t;

typedef struct openssl_async_status_
{
  int evt_run_head;
  int evt_run_tail;
  int evt_pending_head;
  int poll_config;
} openssl_async_status_t;

typedef struct openssl_async_
{
  openssl_evt_t ***evt_pool;
  openssl_async_status_t *status;
  void (*polling) (void);
  void (*polling_conf) (void);
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
  void (*polling_conf) (void);
};

struct engine_polling engine_list[] = {
  {"qat", qat_polling, qat_pre_init, qat_polling_config},
  {"dasync", dasync_polling, NULL, NULL}
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
  vec_validate (om->status, num_threads - 1);

  om->start_polling = 0;
  om->engine = 0;

  for (i = 0; i < num_threads; i++)
    {
      om->status[i].evt_run_head = -1;
      om->status[i].evt_run_tail = -1;
      om->status[i].evt_pending_head = -1;
    }
  om->polling = NULL;

  openssl_async_node_enable_disable (0);

  return;
}

int
openssl_engine_register (char *engine_name, char *algorithm)
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
	  om->polling_conf = engine_list[i].polling_conf;

	  registered = i;
	}
    }
  if (registered < 0)
    {
      clib_error ("engine %s is not regisered in VPP", engine_name);
      return 0;
    }

  ENGINE_load_builtin_engines ();
  ENGINE_load_dynamic ();
  engine = ENGINE_by_id (engine_name);

  if (engine == NULL)
    {
      clib_warning ("Failed to find engine ENGINE_by_id %s", engine_name);
      return 0;
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
	  return 0;
	}
    }
  else
    {
      if (!ENGINE_set_default (engine, ENGINE_METHOD_ALL))
	{
	  clib_warning ("Failed to set engine %s to all algorithm",
			engine_name);
	  return 0;
	}
    }

  om->start_polling = 1;

  return 1;

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
openssl_evt_free (int event_idx, u8 thread_index)
{
  openssl_evt_t *evt;
  openssl_async_t *om = &openssl_async_main;
  int *evt_run_tail = &om->status[thread_index].evt_run_tail;

  if (event_idx < 0)
    return 0;

  evt = openssl_evt_get_w_thread (event_idx, thread_index);

  evt->status = 0;

  /*pool operation */
  pool_put_index (om->evt_pool[thread_index], event_idx);

  if (*evt_run_tail == event_idx)
    *evt_run_tail = -1;

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
  (*evt)->event_index = evt - tm->evt_pool[thread_index];
  return ((*evt)->event_index);
}

int
tls_async_openssl_callback (SSL * s, void *evt)
{
  openssl_evt_t *event, *event_tail;
  openssl_async_t *om = &openssl_async_main;
  openssl_tls_callback_arg_t *args = (openssl_tls_callback_arg_t *) evt;
  int thread_index = args->thread_index;
  int event_index = args->event_index;
  int *evt_run_tail = &om->status[thread_index].evt_run_tail;
  int *evt_run_head = &om->status[thread_index].evt_run_head;

  TLS_DBG (2, "Set event %d to run\n", event_index);

  event = openssl_evt_get_w_thread (event_index, thread_index);

  if (event->status == SSL_ASYNC_READY)
    return 0;

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

openssl_tls_callback_t *
vpp_add_async_pending_event (tls_ctx_t * ctx,
			     openssl_resume_handler * handler)
{
  u32 eidx;
  openssl_evt_t *event;
  openssl_async_t *om = &openssl_async_main;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int *evt_pending_head;
  u32 thread_id = ctx->c_thread_index;

  eidx = openssl_evt_alloc ();
  event = openssl_evt_get (eidx);

  event->ctx_index = oc->openssl_ctx_index;
  event->status = SSL_ASYNC_PENDING;
  event->handler = handler;
  event->cb_args.event_index = eidx;
  event->cb_args.thread_index = thread_id;
  event->engine_callback.callback = tls_async_openssl_callback;
  event->engine_callback.arg = &event->cb_args;

  /* add to pending list */
  evt_pending_head = &om->status[thread_id].evt_pending_head;
  event->next = *evt_pending_head;
  *evt_pending_head = eidx;

  return &event->engine_callback;
}

int
vpp_add_async_run_event (tls_ctx_t * ctx, openssl_resume_handler * handler)
{
  u32 eidx;
  openssl_evt_t *event;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 thread_id = ctx->c_thread_index;

  eidx = openssl_evt_alloc ();
  event = openssl_evt_get (eidx);

  event->ctx_index = oc->openssl_ctx_index;
  event->status = SSL_ASYNC_PENDING;
  event->handler = handler;
  event->cb_args.event_index = eidx;
  event->cb_args.thread_index = thread_id;
  event->engine_callback.callback = tls_async_openssl_callback;
  event->engine_callback.arg = &event->cb_args;

  /* This is a retry event, and need to put to ring to make it run again */
  return tls_async_openssl_callback (NULL, &event->cb_args);

}

void
event_handler (void *tls_async)
{

  openssl_resume_handler *handler;
  openssl_evt_t *callback;
  stream_session_t *tls_session;
  int thread_index;
  tls_ctx_t *ctx;

  callback = (openssl_evt_t *) tls_async;
  thread_index = callback->cb_args.thread_index;
  ctx = openssl_ctx_get_w_thread (callback->ctx_index, thread_index);
  handler = callback->handler;
  tls_session = session_get_from_handle (ctx->tls_session_handle);

  if (handler)
    {
      (*handler) (ctx, tls_session);
    }

  /* Need to free the event */
  openssl_evt_free (callback->cb_args.event_index, thread_index);

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
qat_polling_config ()
{
  openssl_async_t *om = &openssl_async_main;
  u8 thread_index = vlib_get_thread_index ();
  int *config;

  config = &om->status[thread_index].poll_config;
  if (PREDICT_TRUE (*config))
    return;

  ENGINE_ctrl_cmd (om->engine, "SET_INSTANCE_FOR_THREAD", thread_index,
		   NULL, NULL, 0);
  *config = 1;

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
  /* *INDENT-OFF* */
  foreach_vlib_main (({
    vlib_node_set_state (this_vlib_main, tls_async_process_node.index,
                         state);
  }));
  /* *INDENT-ON* */
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
      ctx->resume = 1;
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
  int *evt_run_head = &om->status[thread_index].evt_run_head;

  if (*evt_run_head < 0)
    return 0;

  for (i = 0; i < MAX_VECTOR_ASYNC; i++)
    {
      if (*evt_run_head >= 0)
	{
	  event = openssl_evt_get_w_thread (*evt_run_head, thread_index);
	  TLS_DBG (2, "event run = %d\n", *evt_run_head);
	  tls_async_do_job (*evt_run_head, thread_index);

	  *evt_run_head = event->next;

	}
      else
	{
	  break;
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

  if (om->polling_conf)
    (*om->polling_conf) ();
  thread_index = vlib_get_thread_index ();
  if (pool_elts (om->evt_pool[thread_index]) > 0)
    {
      openssl_async_polling ();
      tls_resume_from_crypto (thread_index);
    }

  return 0;
}

VLIB_INIT_FUNCTION (tls_async_init);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tls_async_process_node,static) = {
    .function = tls_async_process,
    .type = VLIB_NODE_TYPE_INPUT,
    .name = "tls-async-process",
};


/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
