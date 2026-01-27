/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Moinak Bhattacharyya
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <liburing.h>

#include "iouring_input.h"

__clib_export iouring_main_t iouring_main;

#define IOURING_QUEUE_DEPTH	  256
#define IOURING_MAX_CQES_PER_ITER 64
#define IOURING_N_SQPOLL_THREADS  1
#define IOURING_SQ_THREAD_IDLE	  1000 /* SQ thread idle timeout in ms */

static uword
iouring_input_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  iouring_main_t *im = &iouring_main;
  iouring_worker_t *wrk = &im->workers[vm->thread_index];
  struct io_uring *ring = &wrk->ring;
  struct io_uring_cqe *cqe;
  unsigned head;
  u32 n_cqes = 0;

  clib_atomic_fetch_add (&wrk->cqe_poll_count, 1);

  u32 n_ready = io_uring_cq_ready (ring);
  n_ready = clib_min (n_ready, im->max_cqes_per_iter);

  u32 used_regs[n_ready];
  u32 n_used_regs = 0;
  if (n_ready == 0)
    goto done;

  u32 num_per_buffer = wrk->buffer_size / sizeof (iouring_node_cqe_t);

  io_uring_for_each_cqe (ring, head, cqe)
  {
    if (n_cqes == n_ready)
      break;

    u32 reg_index, context;
    iouring_parse_user_data (cqe->user_data, &reg_index, &context);

    if (reg_index == ~0)
      {
	vlib_cli_output (vm, "cqe user_data is ~0, cqe result: %d", cqe->res);
	n_cqes++;
	continue;
      }

    iouring_node_registration_t *reg = &wrk->registrations[reg_index];

    /* Allocate frame if not already allocated (first use this iteration) */
    if (reg->allocated_frame == NULL)
      {
	u32 bi;
	if (PREDICT_FALSE (vlib_buffer_alloc (vm, &bi, 1) == 0))
	  break;
	reg->allocated_frame = vlib_get_frame_to_node (vm, reg->node_id);
	reg->allocated_frame->n_vectors = 1;
	u32 *to_next = vlib_frame_vector_args (reg->allocated_frame);
	to_next[0] = bi;
	vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	b->current_length = 0;
	iouring_frame_scalar_t *sc = vlib_frame_scalar_args (reg->allocated_frame);
	sc->n_cqes = 0;
	reg->current_buffer_idx = 0;
	used_regs[n_used_regs++] = reg_index;
      }

    vlib_frame_t *f = reg->allocated_frame;
    iouring_frame_scalar_t *sc = vlib_frame_scalar_args (f);
    u32 *to_next = vlib_frame_vector_args (f);

    /* Need a new buffer? */
    if (reg->current_buffer_idx >= num_per_buffer)
      {
	u32 bi;
	if (PREDICT_FALSE (vlib_buffer_alloc (vm, &bi, 1) == 0))
	  break;
	to_next[f->n_vectors++] = bi;
	vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	b->current_length = 0;
	reg->current_buffer_idx = 0;
      }

    u32 bi = to_next[f->n_vectors - 1];
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    u32 offset = reg->current_buffer_idx * sizeof (iouring_node_cqe_t);
    clib_memcpy_fast (vlib_buffer_get_current (b) + offset, cqe, sizeof (iouring_node_cqe_t));
    reg->current_buffer_idx++;
    sc->n_cqes++;
    b->current_length += sizeof (iouring_node_cqe_t);

    n_cqes++;
  }

  /* Flush only used registrations */
  for (u32 i = 0; i < n_used_regs; i++)
    {
      iouring_node_registration_t *reg = &wrk->registrations[used_regs[i]];
      vlib_put_frame_to_node (vm, reg->node_id, reg->allocated_frame);
      reg->allocated_frame = NULL;
    }

done:

  io_uring_cq_advance (ring, n_cqes);

  return n_cqes;
}

VLIB_REGISTER_NODE (iouring_input_node) = {
  .function = iouring_input_node_fn,
  .name = "iouring-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
};

static clib_error_t *
iouring_init (vlib_main_t *vm)
{
  iouring_main_t *im = &iouring_main;
  u32 n_threads = vlib_get_n_threads ();
  struct io_uring_params params = { 0 };

  im->queue_depth = IOURING_QUEUE_DEPTH;
  im->sqpoll_check_interval = (((f64) IOURING_SQ_THREAD_IDLE) / 1000.0) / 2.0;
  im->max_cqes_per_iter = IOURING_MAX_CQES_PER_ITER;
  im->n_workers = n_threads;
  im->n_sqpoll_threads = clib_min (IOURING_N_SQPOLL_THREADS, n_threads);
  im->sq_thread_idle = IOURING_SQ_THREAD_IDLE;
  im->workers =
    clib_mem_alloc_aligned (n_threads * sizeof (iouring_worker_t), CLIB_CACHE_LINE_BYTES);
  clib_memset (im->workers, 0, n_threads * sizeof (iouring_worker_t));

  u32 base_flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQE128 | IORING_SETUP_CQE32;

  f64 now = vlib_time_now (vm) - im->sqpoll_check_interval;

  /* Create rings with SQPOLL threads (one per sqpoll thread) */
  for (u32 i = 0; i < im->n_sqpoll_threads; i++)
    {
      iouring_worker_t *wrk = &im->workers[i];
      params.flags = base_flags;
      params.sq_thread_idle = im->sq_thread_idle;

      int rv = io_uring_queue_init_params (im->queue_depth, &wrk->ring, &params);
      if (rv < 0)
	return clib_error_return (0, "io_uring_queue_init failed for sqpoll %u: %s", i,
				  strerror (-rv));

      wrk->buffer_size = vlib_buffer_get_default_data_size (vlib_get_main_by_index (i));
      wrk->last_sqpoll_check = now;
    }

  /* Attach remaining workers to sqpoll threads, divided evenly */
  for (u32 i = im->n_sqpoll_threads; i < n_threads; i++)
    {
      iouring_worker_t *wrk = &im->workers[i];
      u32 sqpoll_idx = i % im->n_sqpoll_threads;

      params.flags = base_flags | IORING_SETUP_ATTACH_WQ;
      params.sq_thread_idle = im->sq_thread_idle;
      params.wq_fd = im->workers[sqpoll_idx].ring.ring_fd;

      int rv = io_uring_queue_init_params (im->queue_depth, &wrk->ring, &params);
      if (rv < 0)
	return clib_error_return (0, "io_uring_queue_init failed for worker %u: %s", i,
				  strerror (-rv));

      wrk->buffer_size = vlib_buffer_get_default_data_size (vlib_get_main_by_index (i));
      wrk->last_sqpoll_check = now;
    }

  return 0;
}

VLIB_INIT_FUNCTION (iouring_init);

static clib_error_t *
iouring_show_stats_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  iouring_main_t *im = &iouring_main;
  u64 total_polls = 0;
  u64 total_submits = 0;

  for (u32 i = 0; i < im->n_workers; i++)
    {
      iouring_worker_t *wrk = &im->workers[i];
      u64 polls = clib_atomic_load_relax_n (&wrk->cqe_poll_count);
      u64 submits = clib_atomic_load_relax_n (&wrk->submit_count);
      vlib_cli_output (vm, "Thread %u: %lu CQE polls, %lu submits", i, polls, submits);
      total_polls += polls;
      total_submits += submits;
    }
  vlib_cli_output (vm, "Total: %lu CQE polls, %lu submits", total_polls, total_submits);

  return 0;
}

VLIB_CLI_COMMAND (iouring_show_stats_command, static) = {
  .path = "show iouring stats",
  .short_help = "show iouring stats",
  .function = iouring_show_stats_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0",
  .description = "io_uring input node",
};
