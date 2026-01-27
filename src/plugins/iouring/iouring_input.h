/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Moinak Bhattacharyya
 */


#ifndef __IOURING_INPUT_H__
#define __IOURING_INPUT_H__

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <liburing.h>

#define IOURING_PLUGIN_NAME "iouring_plugin.so"

typedef struct
{
  u32 node_id;
  vlib_frame_t *allocated_frame;
  u32 current_buffer_idx; /* Index within current buffer (not byte offset) */
} iouring_node_registration_t;

typedef struct
{
  u32 n_cqes;
} iouring_frame_scalar_t;

typedef struct
{
  struct io_uring ring;
  f64 last_sqpoll_check; /* Timestamp of last SQPOLL wakeup check */
  u32 buffer_size;
  iouring_node_registration_t *registrations;
  u64 cqe_poll_count; /* Number of times CQEs were polled */
  u64 submit_count;   /* Number of times io_uring_submit was called */
} iouring_worker_t;

typedef struct
{
  iouring_worker_t *workers; /* Array of per-worker data */
  u32 n_workers;
  u32 n_sqpoll_threads; /* Number of SQPOLL kernel threads */
  u32 queue_depth;
  f64 sqpoll_check_interval; /* Check SQPOLL wakeup every N seconds */
  u32 max_cqes_per_iter;     /* Max CQEs to process per input node call */
  u32 sq_thread_idle;	     /* SQ thread idle timeout in ms */
} iouring_main_t;

typedef struct
{
  u8 cqe_data[32];
} iouring_node_cqe_t;

static inline iouring_main_t *
iouring_get_main (void)
{
  return vlib_get_plugin_symbol (IOURING_PLUGIN_NAME, "iouring_main");
}

static inline struct io_uring *
iouring_get_ring (u32 thread_index)
{
  iouring_main_t *im = iouring_get_main ();
  if (PREDICT_FALSE (im == NULL))
    return NULL;
  return &im->workers[thread_index].ring;
}

/* user_data encoding: upper 32 bits = reg_id, lower 32 bits = context */
static inline u64
iouring_make_user_data (u32 reg_id, u32 context)
{
  return ((u64) reg_id << 32) | context;
}

static inline void
iouring_parse_user_data (u64 user_data, u32 *reg_id, u32 *context)
{
  *reg_id = (u32) (user_data >> 32);
  *context = (u32) user_data;
}

static inline void
iouring_sqe_set_user_data (struct io_uring_sqe *sqe, u32 reg_id, u32 context)
{
  sqe->user_data = iouring_make_user_data (reg_id, context);
}

typedef struct
{
  u32 node_id;
  u32 *return_id;
} iouring_register_node_internal_t;

static inline void
iouring_register_node_internal (iouring_register_node_internal_t *cbdata)
{
  iouring_main_t *im = iouring_get_main ();
  if (PREDICT_FALSE (im == NULL))
    {
      *cbdata->return_id = ~0;
      return;
    }

  u32 reg_id = vec_len (im->workers[0].registrations);

  for (u32 i = 0; i < im->n_workers; i++)
    {
      iouring_worker_t *wrk = &im->workers[i];
      vec_validate (wrk->registrations, reg_id);
      wrk->registrations[reg_id].node_id = cbdata->node_id;
      wrk->registrations[reg_id].allocated_frame = NULL;
    }
  *(cbdata->return_id) = reg_id;
  return;
}
static inline u32
iouring_register_node (u32 node_id)
{
  u32 return_id;
  iouring_register_node_internal_t cbdata = {
    .node_id = node_id,
    .return_id = &return_id,
  };
  if (PREDICT_TRUE (vlib_get_thread_index () == 0))
    {
      vlib_main_t *vm = vlib_get_main ();
      vlib_worker_thread_barrier_sync (vm);
      iouring_register_node_internal (&cbdata);
      vlib_worker_thread_barrier_release (vm);
    }

  else
    vlib_rpc_call_main_thread (iouring_register_node_internal, (u8 *) &cbdata, sizeof (cbdata));
  return return_id;
}

#endif /* __IOURING_INPUT_H__ */
