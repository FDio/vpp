/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vppinfra/fifo.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vnet/api_errno.h>

#include <vcl/vcl_event.h>
/**
 * @file
 * @brief VPP Communications Library (VCL) event handler.
 *
 * Definitions for generic event handling in VCL.
 */

int
vce_generate_event (vce_event_thread_t *evt, u32 ev_idx)
{
  int elts, rv = 0;
  vce_event_t *p;

  pthread_mutex_lock (&(evt->generator_lock));

  /* Check there is event data for this event */

  clib_spinlock_lock (&(evt->events_lockp));
  p =  pool_elt_at_index (evt->vce_events, ev_idx);
  ASSERT(p);

  elts = (int) clib_fifo_free_elts (evt->event_index_fifo);
  if (PREDICT_TRUE (elts))
    {
      /* Add event to queue */
      clib_fifo_add1 (evt->event_index_fifo, ev_idx);
      pthread_cond_signal (&(evt->generator_cond));
    }
  else
    {
      rv = VNET_API_ERROR_QUEUE_FULL;
    }

  clib_spinlock_unlock (&(evt->events_lockp));
  pthread_mutex_unlock (&(evt->generator_lock));

  return rv;
}

void
vce_clear_event (vce_event_thread_t *evt, u32 ev_idx)
{
  clib_spinlock_lock (&(evt->events_lockp));
  pool_put_index (evt->vce_events, ev_idx);
  clib_spinlock_unlock (&(evt->events_lockp));
}

vce_event_t *
vce_get_event_from_index(vce_event_thread_t *evt, u32 ev_idx)
{
  vce_event_t *ev = 0;
  /* Assumes caller has obtained the spinlock (evt->events_lockp) */

  if ( ! pool_is_free_index (evt->vce_events, ev_idx))
    ev = pool_elt_at_index (evt->vce_events, ev_idx);

  return ev;
}

vce_event_handler_reg_t *
vce_get_event_handler (vce_event_thread_t *evt, vce_event_key_t *evk)
{
  vce_event_handler_reg_t *handler = 0;
  uword *p;

  clib_spinlock_lock (&evt->handlers_lockp);
  p = hash_get (evt->handlers_index_by_event_key, evk->as_u64);
  if (p)
    handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);
  clib_spinlock_unlock (&evt->handlers_lockp);

  return handler;
}

vce_event_handler_reg_t *
vce_register_handler (vce_event_thread_t *evt, vce_event_key_t *evk,
                      vce_event_callback_t cb, void *cb_args)
{
  vce_event_handler_reg_t *handler;
  vce_event_handler_reg_t *old_handler = 0;
  uword *p;
  u32 handler_index;

  /* TODO - multiple handler support. For now we can replace
   * and re-instate, which is useful for event recycling */

  clib_spinlock_lock (&evt->handlers_lockp);

  p = hash_get (evt->handlers_index_by_event_key, evk->as_u64);
  if (p)
    {
      old_handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);
      /* If we are just re-registering, ignore and move on
       * else store the old handler_fn for unregister to re-instate */
      if (old_handler->handler_fn == cb)
        {

          clib_spinlock_unlock (&evt->handlers_lockp);

          /* Signal event thread that a handler exists in case any
           * recycled events requiring this handler are pending */
          pthread_mutex_lock (&(evt->generator_lock));
          pthread_cond_signal (&(evt->generator_cond));
          pthread_mutex_unlock (&(evt->generator_lock));
          return old_handler;
        }
    }

  pool_get (evt->vce_event_handlers, handler);
  handler_index = (u32) (handler - evt->vce_event_handlers);

  handler->handler_fn = cb;
  handler->replaced_handler_idx = (u32) ((p) ? p[0] : ~0);
  handler->ev_idx = (u32) ~0; //This will be set by the event thread if event happens
  handler->evk = evk->as_u64;
  handler->handler_fn_args = cb_args;

  hash_set (evt->handlers_index_by_event_key, evk->as_u64, handler_index);

  pthread_cond_init (&(handler->handler_cond), NULL);
  pthread_mutex_init (&(handler->handler_lock), NULL);

  clib_spinlock_unlock (&evt->handlers_lockp);

  /* Signal event thread that a new handler exists in case any
   * recycled events requiring this handler are pending */
  pthread_mutex_lock (&(evt->generator_lock));
  pthread_cond_signal (&(evt->generator_cond));
  pthread_mutex_unlock (&(evt->generator_lock));

  return handler;
}

int
vce_unregister_handler (vce_event_thread_t *evt,
			vce_event_handler_reg_t *handler)
{
  uword *p;
  u64 evk = handler->evk;
  u8 generate_signal = 0;

  clib_spinlock_lock (&evt->handlers_lockp);

  p = hash_get (evt->handlers_index_by_event_key, evk);
  if (!p)
    {
      clib_spinlock_unlock (&evt->handlers_lockp);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);

  /* If this handler replaced another handler, re-instate it */
  if (handler->replaced_handler_idx != ~0)
    {
      hash_set (evt->handlers_index_by_event_key, evk,
		handler->replaced_handler_idx);
      generate_signal = 1;
    }
  else
    {
      hash_unset (evt->handlers_index_by_event_key, evk);
    }

  pthread_mutex_destroy (&(handler->handler_lock));
  pthread_cond_destroy (&(handler->handler_cond));
  pool_put (evt->vce_event_handlers, handler);

  clib_spinlock_unlock (&evt->handlers_lockp);

  if (generate_signal)
    {
      /* Signal event thread that a new handler exists in case any
       * recycled events requiring this handler are pending */
      pthread_mutex_lock (&(evt->generator_lock));
      pthread_cond_signal (&(evt->generator_cond));
      pthread_mutex_unlock (&(evt->generator_lock));
    }

  return 0;
}

void *
vce_event_thread_fn (void *arg)
{
  vce_event_thread_t *evt = (vce_event_thread_t *) arg;
  vce_event_t *ev;
  u32 ev_idx;
  vce_event_handler_reg_t *handler;
  uword *p;
  u32 recycle_count = 0;

  pthread_mutex_lock (&(evt->generator_lock));
  while (1)
    {
      uword fifo_depth = clib_fifo_elts (evt->event_index_fifo);
      while ((fifo_depth == 0) || (recycle_count == fifo_depth))
        {
          recycle_count = 0;
          pthread_cond_wait (&(evt->generator_cond), &(evt->generator_lock));
          fifo_depth = clib_fifo_elts (evt->event_index_fifo);
        }

      /* Remove event */
      clib_spinlock_lock (&(evt->events_lockp));
      clib_fifo_sub1 (evt->event_index_fifo, ev_idx);
      ev = vce_get_event_from_index (evt, ev_idx);
      ASSERT(ev);
      if (recycle_count && ev->recycle)
        {
          clib_fifo_add1 (evt->event_index_fifo, ev_idx);
          clib_spinlock_unlock (&(evt->events_lockp));
          continue;
        }
      clib_spinlock_lock (&evt->handlers_lockp);

      p = hash_get (evt->handlers_index_by_event_key, ev->evk.as_u64);
      if (!p)
        {
          /* If an event falls in the woods, and there is no handler to hear it,
           * does it make any sound?
           * I don't know either, so lets biff the event */
          pool_put(evt->vce_events, ev);
          clib_spinlock_unlock (&(evt->events_lockp));
          clib_spinlock_unlock (&evt->handlers_lockp);
          pthread_mutex_unlock (&(evt->generator_lock));
        }
      else
        {
          u32 evt_recycle = ev->recycle;
          handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);
          handler->ev_idx = ev_idx;
          ev->recycle = 0;

          clib_spinlock_unlock (&(evt->events_lockp));
          clib_spinlock_unlock (&evt->handlers_lockp);
          pthread_mutex_unlock (&(evt->generator_lock));

          (handler->handler_fn)(handler);

          clib_spinlock_lock (&(evt->events_lockp));
          ev = vce_get_event_from_index (evt, ev_idx);
          recycle_count += (!evt_recycle && ev && ev->recycle) ? 1 : 0;
          clib_spinlock_unlock(&(evt->events_lockp));
        }

      pthread_mutex_lock (&(evt->generator_lock));
    }
  return NULL;
}

int
vce_start_event_thread (vce_event_thread_t *evt, u8 max_events)
{
  clib_fifo_validate (evt->event_index_fifo, max_events);
  evt->handlers_index_by_event_key = hash_create (0, sizeof (uword));

  pthread_cond_init (&(evt->generator_cond), NULL);
  pthread_mutex_init (&(evt->generator_lock), NULL);

  clib_spinlock_init (&(evt->events_lockp));
  clib_spinlock_init (&(evt->handlers_lockp));

  return pthread_create (&(evt->thread), NULL /* attr */ ,
                         vce_event_thread_fn, evt);
}

