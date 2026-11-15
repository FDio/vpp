/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Intel and/or its affiliates.
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include "crypto_sw_scheduler.h"

int
crypto_sw_scheduler_set_worker_crypto (u32 worker_idx, u8 enabled)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  crypto_sw_scheduler_per_thread_data_t *ptd = 0;
  u32 count = 0, i;

  if (worker_idx >= vlib_num_workers ())
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      ptd = cm->per_thread_data + i;
      count += ptd->self_crypto_enabled;
    }

  if (enabled || count > 1)
    {
      cm->per_thread_data[vlib_get_worker_thread_index
			  (worker_idx)].self_crypto_enabled = enabled;
    }
  else				/* cannot disable all crypto workers */
    {
      return VNET_API_ERROR_INVALID_VALUE_2;
    }
  return 0;
}

static_always_inline void
cryptodev_sw_scheduler_sgl (vlib_main_t *vm,
			    crypto_sw_scheduler_per_thread_data_t *ptd,
			    vlib_buffer_t *b, vnet_crypto_op_t *op, i16 offset,
			    u32 len)
{
  vnet_crypto_op_chunk_t *ch;
  u32 n_chunks;

  /*
   * offset is relative to current data. Negative offsets stay in head buffer
   * pre_data, positive offsets may skip into later buffers.
   */
  if (offset >= 0)
    {
      while (offset >= b->current_length && b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  offset -= b->current_length;
	  b = vlib_get_buffer (vm, b->next_buffer);
	}

      if (offset == b->current_length)
	{
	  ASSERT (len == 0);
	  op->chunk_index = vec_len (ptd->chunks);
	  op->n_chunks = 0;
	  return;
	}
    }

  ASSERT (offset < b->current_length);

  op->chunk_index = vec_len (ptd->chunks);

  vec_add2 (ptd->chunks, ch, 1);
  ch->src = ch->dst = vlib_buffer_get_current (b) + offset;
  ch->len = clib_min (b->current_length - offset, len);
  len -= ch->len;
  n_chunks = 1;

  while (len && b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      vec_add2 (ptd->chunks, ch, 1);
      ch->src = ch->dst = vlib_buffer_get_current (b);
      ch->len = clib_min (b->current_length, len);
      len -= ch->len;
      n_chunks++;
    }

  if (PREDICT_FALSE (len))
    {
      uword space_left;
      /* Some async crypto users can use buffers in creative ways, let's allow
       * some flexibility here...
       * Current example is ESP decrypt with ESN in async mode: it will stash
       * ESN at the end of the last buffer (if it can) because it must be part
       * of the integrity check but it will not update the buffer length.
       * Fixup the last operation chunk length if we have room.
       */
      space_left = vlib_buffer_space_left_at_end (vm, b);
      ASSERT (space_left >= len);
      if (space_left >= len)
	ch->len += len;
    }

  op->n_chunks = n_chunks;
}

static_always_inline void
crypto_sw_scheduler_convert (vlib_main_t *vm, crypto_sw_scheduler_per_thread_data_t *ptd,
			     vnet_crypto_ctx_t *ctx, u32 index, u32 bi, vnet_crypto_op_type_t type,
			     u8 is_aead)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_crypto_buffer_metadata_t *md = vnet_crypto_buffer_get_metadata (b);
  vnet_crypto_op_t *op = 0;
  vnet_crypto_op_t integ_op;
  u32 cipher_len = md->cipher_data_len;

  if (md->is_chained_buffers)
    {
      vec_add2 (ptd->chained_crypto_ops, op, 1);
      if (!is_aead)
	{
	  cryptodev_sw_scheduler_sgl (vm, ptd, b, &integ_op, md->auth_data_start_off,
				      md->auth_data_len);
	  op->auth_chunk_index = integ_op.chunk_index;
	  op->auth_n_chunks = integ_op.n_chunks;
	}

      cryptodev_sw_scheduler_sgl (vm, ptd, b, op, md->cipher_data_start_off, cipher_len);
    }
  else
    {
      vec_add2 (ptd->crypto_ops, op, 1);
      op->src = op->dst = vlib_buffer_get_current (b) + md->cipher_data_start_off;
      op->len = md->cipher_data_len;
      if (!is_aead)
	{
	  op->auth_src = vlib_buffer_get_current (b) + md->auth_data_start_off;
	  op->auth_src_len = md->auth_data_len;
	}
    }

  op->type = type;
  op->iv = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->iv_off);
  op->ctx = ctx;
  op->flags = 0;
  if (md->is_hmac_check)
    op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
  if (md->is_chained_buffers)
    op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
  op->status = VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS;
  op->user_data = index;

  if (!is_aead)
    {
      op->auth = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);
      op->auth_len = md->icv_len;
    }
  else
    {
      op->auth = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->icv_off);
      op->aad = vnet_crypto_buffer_metadata_get_ptr (vm, b, md->aad_off);
      op->aad_len = md->aad_len;
      op->auth_len = md->icv_len;
    }
}

static_always_inline void
process_ops (vlib_main_t *vm, crypto_sw_scheduler_job_t *job, vnet_crypto_op_t *ops,
	     vnet_crypto_op_chunk_t *chunks, u8 is_chained)
{
  u32 n_ops = vec_len (ops);

  if (n_ops == 0)
    return;

  vnet_crypto_process_ops (vm, ops, is_chained ? chunks : 0, n_ops);

  for (u32 i = 0; i < n_ops; i++)
    job->status[ops[i].user_data] = ops[i].status;
}

#define foreach_crypto_sw_scheduler_error                                                          \
  _ (QUEUE_FULL, "queue-full")                                                                     \
  _ (BAD_HMAC, "bad-hmac")                                                                         \
  _ (ENGINE_ERROR, "engine-error")

typedef enum
{
#define _(f, s) CRYPTO_SW_SCHED_ERROR_##f,
  foreach_crypto_sw_scheduler_error
#undef _
    CRYPTO_SW_SCHED_N_ERROR,
} crypto_sw_scheduler_error_t;

static char *crypto_sw_scheduler_error_strings[] = {
#define _(f, s) s,
  foreach_crypto_sw_scheduler_error
#undef _
};

typedef struct
{
  vnet_crypto_alg_t alg;
  vnet_crypto_op_type_t type;
  vnet_crypto_op_status_t status;
} crypto_sw_scheduler_trace_t;

static u8 *
format_crypto_sw_scheduler_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  crypto_sw_scheduler_trace_t *t = va_arg (*args, crypto_sw_scheduler_trace_t *);

  return format (s, "%U-%U: %U", format_vnet_crypto_op_type, t->type, format_vnet_crypto_alg,
		 t->alg, format_vnet_crypto_op_status, t->status);
}

static_always_inline crypto_sw_scheduler_queue_t *
crypto_sw_scheduler_queue (crypto_sw_scheduler_per_thread_data_t *ptd, vnet_crypto_op_type_t type)
{
  if (type == VNET_CRYPTO_OP_TYPE_ENCRYPT)
    return ptd->queue + CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT;
  return ptd->queue + CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT;
}

VLIB_NODE_FN (crypto_sw_scheduler_enq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  crypto_sw_scheduler_per_thread_data_t *ptd = cm->per_thread_data + vm->thread_index;
  vnet_crypto_deq_scalar_data_t *sd = vlib_frame_scalar_args (frame);
  crypto_sw_scheduler_queue_t *q = crypto_sw_scheduler_queue (ptd, sd->op_type);
  u32 head = q->head, n_vectors = frame->n_vectors;
  crypto_sw_scheduler_job_t *job = q->jobs + (head & cm->crypto_sw_scheduler_queue_mask);

  if (PREDICT_FALSE (job->frame != 0))
    {
      vlib_error_drop_buffers (vm, node, vlib_frame_vector_args (frame), 0, n_vectors, 0,
			       node->node_index, CRYPTO_SW_SCHED_ERROR_QUEUE_FULL);
      vlib_frame_free (vm, frame);
      return n_vectors;
    }

  job->frame = frame;
  job->is_traced = (node->flags & VLIB_NODE_FLAG_TRACE) != 0;
  __atomic_store_n (&job->state, CRYPTO_SW_SCHED_JOB_STATE_PENDING, __ATOMIC_RELEASE);
  __atomic_store_n (&q->head, head + 1, __ATOMIC_RELEASE);

  /* any thread with crypto enabled may process the job */
  for (u32 i = 0; i < vlib_get_n_threads (); i++)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (i), cm->deq_node_index);

  return n_vectors;
}

VLIB_REGISTER_NODE (crypto_sw_scheduler_enq_node) = {
  .name = "crypto-sw-scheduler-enq",
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (vnet_crypto_deq_scalar_data_t),
  .aux_size = sizeof (vnet_crypto_ctx_t *),
  .flags = VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH,
  .n_errors = CRYPTO_SW_SCHED_N_ERROR,
  .error_strings = crypto_sw_scheduler_error_strings,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "error-drop" },
};

static_always_inline crypto_sw_scheduler_job_t *
crypto_sw_scheduler_get_pending_job (crypto_sw_scheduler_main_t *cm,
				     crypto_sw_scheduler_per_thread_data_t *ptd)
{
  u32 mask = cm->crypto_sw_scheduler_queue_mask;
  u32 i = ptd->last_serve_lcore_id + 1;
  crypto_sw_scheduler_job_t *found = 0;

  while (1)
    {
      crypto_sw_scheduler_per_thread_data_t *st;
      crypto_sw_scheduler_queue_t *q;
      u32 tail, head;

      if (i >= vec_len (cm->per_thread_data))
	i = 0;

      st = cm->per_thread_data + i;
      q = st->queue + (ptd->last_serve_encrypt ? CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT :
						 CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT);
      tail = __atomic_load_n (&q->tail, __ATOMIC_ACQUIRE);
      head = __atomic_load_n (&q->head, __ATOMIC_ACQUIRE);

      for (u32 j = tail; j != head; j++)
	{
	  crypto_sw_scheduler_job_t *job = q->jobs + (j & mask);
	  u8 pending = CRYPTO_SW_SCHED_JOB_STATE_PENDING;

	  if (__atomic_compare_exchange_n (&job->state, &pending,
					   CRYPTO_SW_SCHED_JOB_STATE_WORK_IN_PROGRESS, 0,
					   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	    {
	      found = job;
	      break;
	    }
	}

      if (found || i == ptd->last_serve_lcore_id)
	{
	  ptd->last_serve_encrypt = !ptd->last_serve_encrypt;
	  break;
	}

      i++;
    }

  ptd->last_serve_lcore_id = i;
  return found;
}

static_always_inline void
crypto_sw_scheduler_process_job (vlib_main_t *vm, crypto_sw_scheduler_per_thread_data_t *ptd,
				 crypto_sw_scheduler_job_t *job)
{
  vlib_frame_t *f = job->frame;
  vnet_crypto_deq_scalar_data_t *sd = vlib_frame_scalar_args (f);
  vnet_crypto_ctx_t **ctxs = vlib_frame_aux_args (f);
  u32 *bis = vlib_frame_vector_args (f), n = f->n_vectors;
  u8 is_aead = crypto_main.algs[sd->alg].alg_type == VNET_CRYPTO_ALG_T_AEAD;

  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->chained_crypto_ops);
  vec_reset_length (ptd->chunks);

  for (u32 i = 0; i < n; i++)
    {
      if (i + 1 < n)
	clib_prefetch_load (ctxs[i + 1]);
      crypto_sw_scheduler_convert (vm, ptd, ctxs[i], i, bis[i], sd->op_type, is_aead);
    }

  process_ops (vm, job, ptd->crypto_ops, 0, 0);
  process_ops (vm, job, ptd->chained_crypto_ops, ptd->chunks, 1);
  __atomic_store_n (&job->state, CRYPTO_SW_SCHED_JOB_STATE_COMPLETED, __ATOMIC_RELEASE);
}

static_always_inline u32
crypto_sw_scheduler_return_job (vlib_main_t *vm, vlib_node_runtime_t *node,
				crypto_sw_scheduler_job_t *job)
{
  vlib_frame_t *f = job->frame;
  vnet_crypto_deq_scalar_data_t *sd = vlib_frame_scalar_args (f);
  u32 *bis = vlib_frame_vector_args (f), n = f->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];

  vlib_get_buffers (vm, bis, bufs, n);

  for (u32 i = 0; i < n; i++)
    {
      nexts[i] = sd->next_node_index;
      if (PREDICT_FALSE (job->status[i] != VNET_CRYPTO_OP_STATUS_COMPLETED))
	{
	  bufs[i]->error = node->errors[job->status[i] == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC ?
					  CRYPTO_SW_SCHED_ERROR_BAD_HMAC :
					  CRYPTO_SW_SCHED_ERROR_ENGINE_ERROR];
	  nexts[i] = 0;
	}
    }

  if (PREDICT_FALSE (job->is_traced))
    for (u32 i = 0; i < n; i++)
      if (bufs[i]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  crypto_sw_scheduler_trace_t *t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	  t->alg = sd->alg;
	  t->type = sd->op_type;
	  t->status = job->status[i];
	}

  vlib_buffer_enqueue_to_next (vm, node, bis, nexts, n);
  vlib_frame_free (vm, f);
  return n;
}

VLIB_NODE_FN (crypto_sw_scheduler_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  crypto_sw_scheduler_per_thread_data_t *ptd = cm->per_thread_data + vm->thread_index;
  u32 mask = cm->crypto_sw_scheduler_queue_mask, n_returned = 0, n_in_flight = 0;
  u32 n_processed = 0;
  crypto_sw_scheduler_job_t *job;

  /* each lookup checks the encrypt or the decrypt queues, so stop after a miss of both */
  for (u32 n_misses = 0; ptd->self_crypto_enabled && n_misses < CRYPTO_SW_SCHED_QUEUE_N_TYPES;)
    {
      job = crypto_sw_scheduler_get_pending_job (cm, ptd);
      if (job == 0)
	{
	  n_misses++;
	  continue;
	}

      crypto_sw_scheduler_process_job (vm, ptd, job);
      n_processed++;
      n_misses = 0;
    }

  /* jobs are returned in order, by the thread which enqueued them */
  for (u32 i = 0; i < CRYPTO_SW_SCHED_QUEUE_N_TYPES; i++)
    {
      crypto_sw_scheduler_queue_t *q = ptd->queue + i;
      u32 tail = q->tail;

      for (; tail != q->head; tail++)
	{
	  job = q->jobs + (tail & mask);
	  if (__atomic_load_n (&job->state, __ATOMIC_ACQUIRE) !=
	      CRYPTO_SW_SCHED_JOB_STATE_COMPLETED)
	    break;

	  n_returned += crypto_sw_scheduler_return_job (vm, node, job);
	  job->state = 0;
	  job->frame = 0;
	}

      __atomic_store_n (&q->tail, tail, __ATOMIC_RELEASE);
      n_in_flight += q->head - tail;
    }

  if (n_in_flight || n_processed)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return n_returned;
}

VLIB_REGISTER_NODE (crypto_sw_scheduler_deq_node) = {
  .name = "crypto-sw-scheduler-deq",
  .type = VLIB_NODE_TYPE_INPUT,
  .sibling_of = "crypto-deq",
  .state = VLIB_NODE_STATE_INTERRUPT,
  .format_trace = format_crypto_sw_scheduler_trace,
  .n_errors = CRYPTO_SW_SCHED_N_ERROR,
  .error_strings = crypto_sw_scheduler_error_strings,
};

static clib_error_t *
sw_scheduler_set_worker_crypto (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 worker_index;
  u8 crypto_enable;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "worker %u", &worker_index))
	{
	  if (unformat (line_input, "crypto"))
	    {
	      if (unformat (line_input, "on"))
		crypto_enable = 1;
	      else if (unformat (line_input, "off"))
		crypto_enable = 0;
	      else
		return (clib_error_return (0, "unknown input '%U'",
					   format_unformat_error,
					   line_input));
	    }
	  else
	    return (clib_error_return (0, "unknown input '%U'",
				       format_unformat_error, line_input));
	}
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  rv = crypto_sw_scheduler_set_worker_crypto (worker_index, crypto_enable);
  if (rv == VNET_API_ERROR_INVALID_VALUE)
    {
      return (clib_error_return (0, "invalid worker idx: %d", worker_index));
    }
  else if (rv == VNET_API_ERROR_INVALID_VALUE_2)
    {
      return (clib_error_return (0, "cannot disable all crypto workers"));
    }
  return 0;
}

/*?
 * This command sets if worker will do crypto processing.
 *
 * @cliexpar
 * Example of how to set worker crypto processing off:
 * @cliexstart{set sw_scheduler worker 0 crypto off}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (cmd_set_sw_scheduler_worker_crypto, static) = {
  .path = "set sw_scheduler",
  .short_help = "set sw_scheduler worker <idx> crypto <on|off>",
  .function = sw_scheduler_set_worker_crypto,
  .is_mp_safe = 1,
};

static clib_error_t *
sw_scheduler_show_workers (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  u32 i;

  vlib_cli_output (vm, "%-7s%-20s%-8s", "ID", "Name", "Crypto");
  for (i = 1; i < vlib_thread_main.n_vlib_mains; i++)
    {
      vlib_cli_output (vm, "%-7d%-20s%-8s", vlib_get_worker_index (i),
		       (vlib_worker_threads + i)->name,
		       cm->
		       per_thread_data[i].self_crypto_enabled ? "on" : "off");
    }

  return 0;
}

/*?
 * This command displays sw_scheduler workers.
 *
 * @cliexpar
 * Example of how to show workers:
 * @cliexstart{show sw_scheduler workers}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (cmd_show_sw_scheduler_workers, static) = {
  .path = "show sw_scheduler workers",
  .short_help = "show sw_scheduler workers",
  .function = sw_scheduler_show_workers,
  .is_mp_safe = 1,
};

clib_error_t *
sw_scheduler_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (sw_scheduler_cli_init);

crypto_sw_scheduler_main_t crypto_sw_scheduler_main;
clib_error_t *
crypto_sw_scheduler_init (vlib_main_t * vm)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  clib_error_t *error = 0;
  vnet_crypto_alg_t alg;
  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "sw_scheduler", 100, "SW Scheduler Async Engine");

  crypto_sw_scheduler_api_init (vm);

  cm->deq_node_index = crypto_sw_scheduler_deq_node.index;
  vnet_crypto_register_engine_deq_node (vm, cm->crypto_engine_index, cm->deq_node_index);

  for (alg = 1; alg < VNET_CRYPTO_N_ALGS; alg++)
    {
      if (vnet_crypto_alg_has_op_type (alg, VNET_CRYPTO_OP_TYPE_ENCRYPT))
	vnet_crypto_register_async_alg (vm, cm->crypto_engine_index, alg,
					VNET_CRYPTO_OP_TYPE_ENCRYPT,
					crypto_sw_scheduler_enq_node.index);
      if (vnet_crypto_alg_has_op_type (alg, VNET_CRYPTO_OP_TYPE_DECRYPT))
	vnet_crypto_register_async_alg (vm, cm->crypto_engine_index, alg,
					VNET_CRYPTO_OP_TYPE_DECRYPT,
					crypto_sw_scheduler_enq_node.index);
    }

  return error;
}

VLIB_INIT_FUNCTION (crypto_sw_scheduler_init) = {
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SW Scheduler Crypto Async Engine plugin",
};

static clib_error_t *
crypto_sw_scheduler_config (vlib_main_t *vm, unformat_input_t *input)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  u32 crypto_sw_scheduler_queue_size = CRYPTO_SW_SCHEDULER_QUEUE_SIZE;
  clib_error_t *error = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  crypto_sw_scheduler_per_thread_data_t *ptd;
  u32 i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "crypto-sw-scheduler-queue-size %d",
		    &crypto_sw_scheduler_queue_size))
	{
	  if (!is_pow2 (crypto_sw_scheduler_queue_size))
	    {
	      return clib_error_return (0, "input %d is not pow2",
					format_unformat_error,
					crypto_sw_scheduler_queue_size);
	    }
	}
      else
	{
	  cm->crypto_sw_scheduler_queue_mask =
	    crypto_sw_scheduler_queue_size - 1;
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  cm->crypto_sw_scheduler_queue_mask = crypto_sw_scheduler_queue_size - 1;

  vec_validate_aligned (cm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      ptd = cm->per_thread_data + i;
      ptd->self_crypto_enabled = i > 0 || vlib_num_workers () < 1;

      ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT].head = 0;
      ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT].tail = 0;

      vec_validate_aligned (ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT].jobs,
			    crypto_sw_scheduler_queue_size - 1, CLIB_CACHE_LINE_BYTES);

      ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].head = 0;
      ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].tail = 0;

      ptd->last_serve_encrypt = 0;
      ptd->last_return_queue = 0;

      vec_validate_aligned (ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].jobs,
			    crypto_sw_scheduler_queue_size - 1, CLIB_CACHE_LINE_BYTES);
    }

  if (error)
    vec_free (cm->per_thread_data);

  return error;
}

VLIB_CONFIG_FUNCTION (crypto_sw_scheduler_config, "crypto_sw_scheduler");
