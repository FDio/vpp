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

#include <vppinfra/cache.h>
#include <vppinfra/mem.h>

#define VCE_EVENTS_LOCK() clib_spinlock_lock (&(evt->events_lockp))
#define VCE_EVENTS_UNLOCK() clib_spinlock_unlock (&(evt->events_lockp))
#define VCE_HANDLERS_LOCK() clib_spinlock_lock (&(evt->handlers_lockp))
#define VCE_HANDLERS_UNLOCK() clib_spinlock_unlock (&(evt->handlers_lockp))
#define VCE_IO_SESSIONS_LOCK() clib_spinlock_lock (&(evt->io_sessions_lockp))
#define VCE_IO_SESSIONS_UNLOCK() \
  clib_spinlock_unlock (&(evt->io_sessions_lockp))

typedef struct vppcom_ioevent_
{
  uint32_t session_index;
  size_t bytes;
} vppcom_ioevent_t;

/**
 * @file
 * @brief VPP Communications Library (VCL) event handler.
 *
 * Declarations for generic event handling in VCL.
 */

#include <vppinfra/types.h>
#include <vppinfra/lock.h>
#include <pthread.h>

/**
 * User registered callback for when connection arrives on listener created
 * with vppcom_session_register_listener()
 * @param uint32_t - newly accepted session_index
 * @param vppcom_endpt_t* - ip/port information of remote
 * @param void* - user passed arg to pass back
 */
typedef void (*vppcom_session_listener_cb) (uint32_t, vppcom_endpt_t *,
					    void *);

/**
 * User registered callback for IO events (rx/tx)
 * @param vppcom_ioevent_t* -
 * @param void* - user passed arg to pass back
 */
typedef void (*vppcom_session_ioevent_cb) (vppcom_ioevent_t *, void *);

/**
 * User registered ERROR callback for any errors associated with
 * handling vppcom_session_register_listener() and connections
 * @param void* - user passed arg to pass back
 */
typedef void (*vppcom_session_listener_errcb) (void *);


typedef enum vcl_event_id_
{
  VCL_EVENT_INVALID_EVENT,
  VCL_EVENT_CONNECT_REQ_ACCEPTED,
  VCL_EVENT_IOEVENT_RX_FIFO,
  VCL_EVENT_IOEVENT_TX_FIFO,
  VCL_EVENT_N_EVENTS
} vcl_event_id_t;

/* VPPCOM Event typedefs */
typedef struct vppcom_session_listener
{
  vppcom_session_listener_cb user_cb;
  vppcom_session_listener_errcb user_errcb;
  void *user_cb_data;
} vppcom_session_listener_t;

typedef struct vppcom_session_ioevent_
{
  vppcom_session_ioevent_cb user_cb;
  void *user_cb_data;
} vppcom_session_ioevent_t;

typedef struct vppcom_session_io_thread_
{
  pthread_t thread;
  pthread_mutex_t vce_io_lock;
  pthread_cond_t vce_io_cond;
  u32 *active_session_indexes;	//pool
  vppcom_session_ioevent_t *ioevents;	//pool
  clib_spinlock_t io_sessions_lockp;
} vppcom_session_io_thread_t;

typedef struct vce_event_connect_request_
{
  u32 accepted_session_index;
} vce_event_connect_request_t;

typedef union vce_event_key_
{
  struct {
    u32 eid;
    u32 session_index;
  };
  u64 as_u64;
} vce_event_key_t;

typedef struct vce_event_
{
  vce_event_key_t evk;
  u32 recycle;
  u64 data[2]; // Hard code size to avoid allocator thrashing.
} vce_event_t;

typedef void (*vce_event_callback_t) (void *reg /*vce_event_handler_reg_t* */);

typedef struct vce_event_handler_reg_
{
  vce_event_callback_t handler_fn;
  pthread_mutex_t handler_lock;
  pthread_cond_t handler_cond;
  u32 ev_idx;
  u64 evk; //Event key
  u32 replaced_handler_idx;
  void *handler_fn_args;
} vce_event_handler_reg_t;

typedef struct vce_event_thread_
{
  pthread_t thread;
  pthread_mutex_t generator_lock;
  pthread_cond_t generator_cond;
  u32 *event_index_fifo;
  u8 recycle_event;
  clib_spinlock_t events_lockp;
  vce_event_t *vce_events; //pool
  clib_spinlock_t handlers_lockp;
  vce_event_handler_reg_t *vce_event_handlers; //pool
  uword *handlers_index_by_event_key; //hash
} vce_event_thread_t;


/**
 * @brief vppcom_session_register_listener accepts a bound session_index, and
 * listens for connections.
 *
 * On successful connection, calls registered callback (cb) with new
 * session_index.
 *
 * On error, calls registered error callback (errcb).
 *
 * @param session_index - bound session_index to create listener on
 * @param cb  - on new accepted session callback
 * @param errcb  - on failure callback
 * @param flags - placeholder for future use. Must be ZERO
 * @param q_len - max listener connection backlog
 * @param ptr - user data
 * @return
 */
extern int vppcom_session_register_ioevent_cb (uint32_t session_index,
					       vppcom_session_ioevent_cb cb,
					       uint8_t rx, void *ptr);

/**
 * @brief vppcom_session_register_listener accepts a bound session_index, and
 * listens for connections.
 *
 * On successful connection, calls registered callback (cb) with new
 * session_index.
 *
 * On error, calls registered error callback (errcb).
 *
 * @param session_index - bound session_index to create listener on
 * @param cb  - on new accepted session callback
 * @param errcb  - on failure callback
 * @param flags - placeholder for future use. Must be ZERO
 * @param q_len - max listener connection backlog
 * @param ptr - user data
 * @return
 */
extern int vppcom_session_register_listener (uint32_t session_index,
					     vppcom_session_listener_cb cb,
					     vppcom_session_listener_errcb
					     errcb, uint8_t flags, int q_len,
					     void *ptr);

/**
 * @brief vce_generate_event
 * - used to trigger an event in the event thread so that registered
 *   handlers are notified
 *
 * @param evt - vce_event_thread_t - event system state
 * @param ev_idx - index to vce_event_thread_t vce_event pool
 *
 * @return success/failure rv
 */
int vce_generate_event (vce_event_thread_t *evt, u32 ev_idx);

/**
 * @brief vce_clear_event()
 * - removes event from event_pool
 *
 * @param evt - vce_event_thread_t - event system state
 * @param ev_idx  - u32 - index of event to remove
 */
void vce_clear_event (vce_event_thread_t *evt, u32 ev_idx);

/**
 * @brief vce_get_event_from_index()
 *
 * @param evt - vce_event_thread_t - event system state
 * @param ev_idx - index to vce_event_thread_t vce_event pool
 *
 * @return vce_event_t *
 */
vce_event_t * vce_get_event_from_index(vce_event_thread_t *evt, u32 ev_idx);

/**
 * @brief vce_get_event_data()
 *
 * @param ev - vce_event_t * - event
 * @param data_size - u32 - required size of data
 *
 * @return vce_event_t *
 */
always_inline void * vce_get_event_data(vce_event_t *ev, u32 data_size)
{
	ASSERT(sizeof(ev->data) >= data_size);
	return (&ev->data);
}

/**
 * @brief vce_get_event_handler()
 * - returns handler if exists or 0
 * @param evt - vce_event_thread_t - event system state
 * @param evk - event key
 * @return vce_event_handler_reg_t *
 */
vce_event_handler_reg_t * vce_get_event_handler (vce_event_thread_t *evt,
						 vce_event_key_t *evk);

/**
 * @brief vce_register_handler
 * - used by functions who need to be notified that an event has occurred
 *   on a vce_event_key_t (i.e. event type (enum) and sessionID)
 * - if a handler already exists, the index to the old handler is stored
 *   inside the new handler for re-instatement on vce_unregister_handler()

 * @param evt - vce_event_thread_t - event system state
 * @param evk - vce_event_key_t current an eventID from enum in consumer and
 * 		sessionID
 * @param cb  - vce_event_callback_t function to handle event
 * @param cb_args - args that the callback needs passed back to it.
 * @return vce_handler_reg_t - the function that needs event notification
 *   needs to block on a condvar mutex to reduce spin. That is in here.
 */
vce_event_handler_reg_t * vce_register_handler (vce_event_thread_t *evt,
						vce_event_key_t *evk,
						vce_event_callback_t cb,
						void *cb_args);

/**
 * @brief vce_unregister_handler
 * - used by functions to remove need to be notified that an event has occurred
 *   on a vce_event_key_t (i.e. event type (enum) and sessionID)
 * - if this handler replaced an existing one, re-instate it.
 *
 * @param evt - vce_event_thread_t - event system state
 * @param handler - handler to be unregistered
 * @return success/failure rv
 */
int vce_unregister_handler (vce_event_thread_t *evt,
			    vce_event_handler_reg_t *handler);

/**
 * @brief vce_event_thread_fn
 * - main event thread that waits on a generic condvar/mutex that a signal
 *   has been generated.
 *   - loops through all registered handlers for that vce_event_key_t
 *   (event enum + sessionID)
 *
 * @param arg - cast to type of event defined in consuming program.
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

/**
 *  * @brief vce_connect_request_handler_fn
 * - used for listener sessions
 * - when a vl_api_accept_session_t_handler() generates an event
 *   this callback is alerted and sets fields that consumers such as
 *   vppcom_session_accept() expect to see, ie. accepted_client_index
 *
 * @param arg - void* to be cast to vce_event_handler_reg_t*
 */
always_inline void
vce_connect_request_handler_fn (void *arg)
{
  vce_event_handler_reg_t *reg = (vce_event_handler_reg_t *) arg;

  pthread_mutex_lock (&reg->handler_lock);
  pthread_cond_signal (&reg->handler_cond);
  pthread_mutex_unlock (&reg->handler_lock);
}

#endif //VPP_VCL_EVENT_H
