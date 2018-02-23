/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
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

#ifndef VPP_VCL_EVENT_H
#define VPP_VCL_EVENT_H

#include <vppinfra/types.h>
#include <pthread.h>
#include <vppinfra/fifo.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vnet/api_errno.h>



typedef union event_key_
{
  struct {
    u32 eid; //TODO have to reconcile keeping this generic and enum defined in vppcom.c
    u32 session_index; //only supporting session events for now
  };
  u64 as_u64;
} event_key_t;

//only supporting session events for now
typedef void (*event_callback_t) (u32 session_index, void *reg /*event_handler_reg_t* */);

typedef struct event_handler_reg_
{
  event_callback_t handler_fn;
  pthread_mutex_t handler_lock;
  pthread_cond_t handler_cond;
} event_handler_reg_t;


typedef struct event_thread_
{
  pthread_t thread;
  pthread_mutex_t generator_lock;
  pthread_cond_t generator_cond;
  event_key_t *session_event_fifo;
  event_handler_reg_t *session_event_handlers; //pool
  uword *handlers_index_by_event_key; //hash
} event_thread_t;

int
generate_event (event_key_t *evk, event_thread_t *evt)
{
  int elts, rv = 0;
  pthread_mutex_lock (&(evt->generator_lock));
  elts = clib_fifo_free_elts (evt->session_event_fifo);
  if (PREDICT_TRUE (elts))
    {
      /* Add event to queue */
      clib_fifo_add1 (evt->session_event_fifo, *evk);
      pthread_cond_signal (&(evt->generator_cond));
    }
  else
    {
      rv = VNET_API_ERROR_QUEUE_FULL;
    }
  pthread_mutex_unlock (&(evt->generator_lock));
  return rv;
}

event_handler_reg_t *
register_handler (event_thread_t *evt, event_key_t evk, event_callback_t cb)
{
  event_handler_reg_t *handler;
  uword *p;
  u32 handler_index;
  u64 adj_key = evk.as_u64 | (1LL << 63);


  // If key exists, get handlers from pool
  p = hash_get (evt->handlers_index_by_event_key, adj_key);
  if (p)
    {
      // We already have a handler so add to existing
      handler = pool_elt_at_index (evt->session_event_handlers, p[0]);
    }
  else
    {
      //Set up a new one
      pool_get (evt->session_event_handlers, handler);

      handler_index = handler - evt->session_event_handlers;
      hash_set (evt->handlers_index_by_event_key, adj_key, handler_index);
    }

  /* Allocate handler on heap and init mutex */
  handler->handler_fn = cb;
  pthread_cond_init (&(handler->handler_cond), NULL);
  pthread_mutex_init (&(handler->handler_lock), NULL);

  return handler;
}

int
unregister_handler (event_thread_t *evt, event_key_t evk, event_callback_t fn)
{
  event_handler_reg_t *handler;
  uword *p;
  u64 adj_key = evk.as_u64 | (1LL << 63);

  //unravel everything in register paying special attention to clib_mem_free()
  p = hash_get (evt->handlers_index_by_event_key, adj_key);
  if (!p) return VNET_API_ERROR_NO_SUCH_ENTRY;

  handler = pool_elt_at_index (evt->session_event_handlers, p[0]);
  pthread_mutex_destroy (&(handler->handler_lock));
  pthread_cond_destroy (&(handler->handler_cond));
  pool_put_index (evt->session_event_handlers, p[0]);
  hash_unset (evt->handlers_index_by_event_key, adj_key);

  return 0;
}

static void *
vcl_event_thread_fn (void *arg)
{
  event_thread_t *evt;
  event_key_t evk;
  event_handler_reg_t *handler;
  uword *p;
  u64 adj_key;

  evt = (event_thread_t *) arg;

  printf ("\n*****************   in vcl_event_thread\n");

  do
    {
      pthread_mutex_lock (&(evt->generator_lock));
      while (clib_fifo_elts(evt->session_event_fifo) == 0)
        {
          pthread_cond_wait (&(evt->generator_cond),
                             &(evt->generator_lock));
          printf ("\n*****************   in vcl_event_thread: received cond\n");
        }

      printf ("\n*****************   Got an event\n");
      /* Remove event */
      clib_fifo_sub1 (evt->session_event_fifo, evk);
      adj_key = evk.as_u64 | (1LL << 63);
      p = hash_get (evt->handlers_index_by_event_key, adj_key);
      if (!p) goto unlock; //No handlers

      handler = pool_elt_at_index ( evt->session_event_handlers, p[0]);


      (handler->handler_fn)(evk.session_index, handler);


      unlock:
      pthread_mutex_unlock (&(evt->generator_lock));
    }
  while (1);
  return NULL;
}

int
vcl_start_event_thread (event_thread_t *evt, u8 max_events)
{
  clib_fifo_validate (evt->session_event_fifo, max_events);
  evt->handlers_index_by_event_key = hash_create (0, sizeof (uword));

  pthread_cond_init (&(evt->generator_cond), NULL);
  pthread_mutex_init (&(evt->generator_lock), NULL);

  return pthread_create (&(evt->thread), NULL /* attr */ ,
                         vcl_event_thread_fn, evt);
}

#endif //VPP_VCL_EVENT_H
