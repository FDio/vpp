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

/**
 * @file
 * @brief VPP Communications Library (VCL) event handler.
 *
 * Declarations for generic event handling in VCL.
 */

#include <vppinfra/types.h>
#include <vppinfra/lock.h>
#include <pthread.h>

typedef union vce_event_key_
{
  struct {
    u32 eid;
    u32 session_index; /* TODO supporting session events for now */
  };
  u64 as_u64;
} vce_event_key_t;

typedef struct vce_event_
{
  vce_event_key_t evk;
  u32 refcnt;
  void *data;
} vce_event_t;

typedef void (*vce_event_callback_t) (void *reg /*vce_event_handler_reg_t* */);

typedef struct vce_event_handler_reg_
{
  struct vce_event_handler_reg_ *replaced_handler;
  vce_event_callback_t handler_fn;
  pthread_mutex_t handler_lock;
  pthread_cond_t handler_cond;
  u32 ev_idx;
} vce_event_handler_reg_t;

typedef struct vce_event_thread_
{
  pthread_t thread;
  pthread_mutex_t generator_lock;
  pthread_cond_t generator_cond;
  u32 *event_index_fifo;
  clib_spinlock_t events_lockp;
  vce_event_t *vce_event; //pool
  clib_spinlock_t handlers_lockp;
  vce_event_handler_reg_t *vce_event_handlers; //pool
  uword *handlers_index_by_event_key; //hash
} vce_event_thread_t;

/**
 * @brief vce_generate_event
 * - used to trigger an event in the event thread so that registered
 *   handlers are notified
 *
 * @param ev - vce_event_t - key for event + data glob to be cast
 * @param evt - vce_event_thread_t - event system state
 * @return success/failure rv
 */
int vce_generate_event (u32 ev_idx, vce_event_thread_t *evt);

/**
 *
 * @param evt
 * @param ev_idx
 * @return
 */
vce_event_t *
vce_get_event_from_index(vce_event_thread_t *evt, u32 ev_idx);

/**
 * @brief vce_register_handler
 * - used by functions who need to be notified that an event has occurred
 *   on a vce_event_key_t (i.e. event type (enum) and sessionID)

 * @param evk - vce_event_key_t current an eventID from enum in consumer and
 * 		sessionID
 * @param evt - vce_event_thread_t - event system state
 * @param cb  - vce_event_callback_t function to handle event
 * @return vce_handler_reg_t - the function that needs event notification
 *   needs to block on a condvar mutex to reduce spin. That is in here.
 */
vce_event_handler_reg_t * vce_register_handler (vce_event_thread_t *evt,
						vce_event_key_t *evk,
						vce_event_callback_t cb);

/**
 * @brief vce_unregister_handler
 * - used by functions to remove need to be notified that an event has occurred
 *   on a vce_event_key_t (i.e. event type (enum) and sessionID)
 *
 * @param evk - vce_event_key_t current an eventID from enum in consumer and
 * 		sessionID
 * @param evt - vce_event_thread_t - event system state
 * @return success/failure rv
 */
int vce_unregister_handler (vce_event_thread_t *evt, vce_event_t *ev);

/**
 * @brief vce_event_thread_fn
 * - main event thread that waits on a generic condvar/mutex that a signal
 *   has been generated.
 *   - loops through all registered handlers for that vce_event_key_t
 *   (event enum + sessionID)
 *
 * @param arg
 * @return
 */
extern void * vce_event_thread_fn (void *arg);

/**
 * @brief vce_start_event_thread
 * - as name suggests. What is important is that vce_event_thread_t is allocated
 * on the same heap as "everything else". ie use clib_mem_alloc.
 * @param evt - vce_event_thread_t - event system state
 * @param max_events - depth of event FIFO for max number of outstanding events.
 * @return succes/failure
 */
int vce_start_event_thread (vce_event_thread_t *evt, u8 max_events);

#endif //VPP_VCL_EVENT_H
