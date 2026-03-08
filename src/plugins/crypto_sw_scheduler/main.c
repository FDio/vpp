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

static int
crypto_sw_scheduler_frame_enqueue (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame, u8 is_enc)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  crypto_sw_scheduler_per_thread_data_t *ptd =
    vec_elt_at_index (cm->per_thread_data, vm->thread_index);
  crypto_sw_scheduler_queue_t *current_queue =
    is_enc ? &ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT] :
	     &ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT];
  vnet_crypto_async_frame_t **jobs = current_queue->jobs;
  u32 mask = cm->crypto_sw_scheduler_queue_mask;
  u64 head = current_queue->head;

  if (jobs[head & mask])
    {
      u32 n_elts = frame->n_elts, i;
      for (i = 0; i < n_elts; i++)
	vlib_crypto_async_frame_set_engine_error (frame, i);
      frame->state = VNET_CRYPTO_FRAME_STATE_COMPLETED;
      return -1;
    }

  jobs[head & mask] = frame;
  __atomic_store_n (&current_queue->head, head + 1, __ATOMIC_RELEASE);
  return 0;
}

static int
crypto_sw_scheduler_frame_enqueue_decrypt (vlib_main_t *vm,
					   vnet_crypto_async_frame_t *frame)
{
  return crypto_sw_scheduler_frame_enqueue (vm, frame, 0);
}

static int
crypto_sw_scheduler_frame_enqueue_encrypt (vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
{
  return crypto_sw_scheduler_frame_enqueue (vm, frame, 1);
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
   * offset is relative to b->data (can be negative if we stay in pre_data
   * area). Make sure it does not go beyond the 1st buffer.
   */
  ASSERT (b->current_data + b->current_length > offset);
  offset = clib_min (b->current_data + b->current_length, offset);

  op->chunk_index = vec_len (ptd->chunks);

  vec_add2 (ptd->chunks, ch, 1);
  ch->src = ch->dst = b->data + offset;
  ch->len = clib_min (b->current_data + b->current_length - offset, len);
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
			     vnet_crypto_async_frame_elt_t *fe, u32 index, u32 bi,
			     vnet_crypto_op_type_t type, u8 is_aead)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_crypto_op_t *op = 0;
  vnet_crypto_op_t integ_op;
  u32 cipher_len = fe->cipher_data_len;

  if (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
    {
      vec_add2 (ptd->chained_crypto_ops, op, 1);
      if (!is_aead)
	{
	  cryptodev_sw_scheduler_sgl (vm, ptd, b, &integ_op, fe->auth_data_start_off,
				      fe->auth_data_len);
	  op->auth_chunk_index = integ_op.chunk_index;
	  op->auth_n_chunks = integ_op.n_chunks;
	}

      cryptodev_sw_scheduler_sgl (vm, ptd, b, op, fe->cipher_data_start_off, cipher_len);
    }
  else
    {
      vec_add2 (ptd->crypto_ops, op, 1);
      op->src = op->dst = b->data + fe->cipher_data_start_off;
      op->len = fe->cipher_data_len;
      if (!is_aead)
	{
	  op->auth_src = b->data + fe->auth_data_start_off;
	  op->auth_src_len = fe->auth_data_len;
	}
    }

  op->type = type;
  op->iv = fe->iv;
  op->ctx = fe->ctx;
  op->flags = fe->flags;
  op->status = VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS;
  op->user_data = index;

  if (!is_aead)
    {
      op->auth = fe->icv;
      op->auth_len = fe->icv_len;
    }
  else
    {
      op->auth = fe->icv;
      op->aad = fe->aad;
      op->aad_len = fe->aad_len;
      op->auth_len = fe->icv_len;
    }
}

static_always_inline void
process_ops (vlib_main_t *vm, vnet_crypto_async_frame_t *f, vnet_crypto_op_t *ops,
	     vnet_crypto_op_chunk_t *chunks, u8 is_chained)
{
  u32 n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;
  u8 has_fail = 0;

  if (n_ops == 0)
    return;

  if (is_chained)
    vnet_crypto_process_ops (vm, op, chunks, n_ops);
  else
    vnet_crypto_process_ops (vm, op, 0, n_ops);

  for (u32 i = 0; i < n_ops; i++)
    {
      if (ops[i].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  has_fail = 1;
	  break;
	}
    }

  if (!has_fail)
    return;

  for (u32 i = 0; i < n_ops; i++, op++)
    {
      if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
	vlib_crypto_async_frame_set_hmac_fail (f, op->user_data);
      else if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	vlib_crypto_async_frame_set_engine_error (f, op->user_data);
    }
}

static_always_inline vnet_crypto_async_frame_t *
crypto_sw_scheduler_return_frame (crypto_sw_scheduler_queue_t *queue, u32 mask)
{
  vnet_crypto_async_frame_t **jobs = queue->jobs;
  vnet_crypto_async_frame_t *f;
  u32 tail = queue->tail & mask;

  if (!jobs[tail] ||
      __atomic_load_n (&jobs[tail]->state, __ATOMIC_ACQUIRE) != VNET_CRYPTO_FRAME_STATE_COMPLETED)
    return 0;

  queue->tail++;
  f = jobs[tail];
  jobs[tail] = 0;

  return f;
}

static_always_inline vnet_crypto_async_frame_t *
crypto_sw_scheduler_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			     clib_thread_index_t *enqueue_thread_idx)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  crypto_sw_scheduler_per_thread_data_t *ptd =
    cm->per_thread_data + vm->thread_index;
  vnet_crypto_async_frame_t *f = 0;
  vnet_crypto_async_frame_t **jobs;
  crypto_sw_scheduler_queue_t *current_queue = 0;
  u32 mask = cm->crypto_sw_scheduler_queue_mask;
  u32 tail, head;
  u8 found = 0;
  u8 recheck_queues = 1;

run_next_queues:
  /* get a pending frame to process */
  if (ptd->self_crypto_enabled)
    {
      u32 i = ptd->last_serve_lcore_id + 1;

      while (1)
	{
	  crypto_sw_scheduler_per_thread_data_t *st;
	  u32 j;

	  if (i >= vec_len (cm->per_thread_data))
	    i = 0;

	  st = cm->per_thread_data + i;

	  if (ptd->last_serve_encrypt)
	    current_queue = &st->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT];
	  else
	    current_queue = &st->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT];
	  jobs = current_queue->jobs;

	  tail = current_queue->tail;
	  head = __atomic_load_n (&current_queue->head, __ATOMIC_ACQUIRE);

	  /* Skip this queue unless tail < head or head has overflowed
	   * and tail has not. At the point where tail overflows (== 0),
	   * the largest possible value of head is (queue size - 1).
	   * Prior to that, the largest possible value of head is
	   * (queue size - 2).
	   */
	  if ((tail > head) && (head >= cm->crypto_sw_scheduler_queue_mask))
	    goto skip_queue;

	  for (j = tail; j != head; j++)
	    {

	      f = jobs[j & mask];

	      if (!f)
		continue;

	      if (clib_atomic_bool_cmp_and_swap (
		    &f->state, VNET_CRYPTO_FRAME_STATE_PENDING,
		    VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS))
		{
		  found = 1;
		  break;
		}
	    }

	skip_queue:
	  if (found || i == ptd->last_serve_lcore_id)
	    {
	      __atomic_store_n (&ptd->last_serve_encrypt, !ptd->last_serve_encrypt,
				__ATOMIC_RELEASE);
	      break;
	    }

	  i++;
	}

      ptd->last_serve_lcore_id = i;
    }

  if (found)
    {
      vnet_crypto_async_frame_elt_t *fe;
      vnet_crypto_async_frame_elt_t *elts = f->elts;
      u32 *bi;
      u32 *bis = f->buffer_indices;
      u32 n = f->n_elts;
      vec_reset_length (ptd->crypto_ops);
      vec_reset_length (ptd->chained_crypto_ops);
      vec_reset_length (ptd->chunks);

      if (crypto_main.algs[f->alg].alg_type == VNET_CRYPTO_ALG_T_AEAD)
	for (u32 i = 0; i < n; i++)
	  {
	    fe = &elts[i];
	    bi = &bis[i];
	    if (i + 1 < n)
	      clib_prefetch_load (fe + 1);
	    crypto_sw_scheduler_convert (vm, ptd, fe, i, bi[0], f->type, 1);
	  }
      else
	for (u32 i = 0; i < n; i++)
	  {
	    fe = &elts[i];
	    bi = &bis[i];
	    if (i + 1 < n)
	      clib_prefetch_load (fe + 1);
	    crypto_sw_scheduler_convert (vm, ptd, fe, i, bi[0], f->type, 0);
	  }

      process_ops (vm, f, ptd->crypto_ops, 0, 0);
      process_ops (vm, f, ptd->chained_crypto_ops, ptd->chunks, 1);
      __atomic_store_n (&f->state, VNET_CRYPTO_FRAME_STATE_COMPLETED, __ATOMIC_RELEASE);

      *enqueue_thread_idx = f->enqueue_thread_index;
      *nb_elts_processed = f->n_elts;
    }

  if (ptd->last_return_queue)
    {
      current_queue = &ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT];
      ptd->last_return_queue = 0;
    }
  else
    {
      current_queue = &ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT];
      ptd->last_return_queue = 1;
    }

  f = crypto_sw_scheduler_return_frame (current_queue, mask);
  if (f)
    return f;

  if (ptd->last_return_queue)
    current_queue = &ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT];
  else
    current_queue = &ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT];

  f = crypto_sw_scheduler_return_frame (current_queue, mask);
  if (f)
    return f;

  if (!found && recheck_queues)
    {
      recheck_queues = 0;
      goto run_next_queues;
    }
  return 0;
}

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

  for (alg = 1; alg < VNET_CRYPTO_N_ALGS; alg++)
    {
      if (vnet_crypto_alg_has_op_type (alg, VNET_CRYPTO_OP_TYPE_ENCRYPT))
	vnet_crypto_register_enqueue_handler_by_alg (vm, cm->crypto_engine_index, alg,
						     VNET_CRYPTO_OP_TYPE_ENCRYPT,
						     crypto_sw_scheduler_frame_enqueue_encrypt);
      if (vnet_crypto_alg_has_op_type (alg, VNET_CRYPTO_OP_TYPE_DECRYPT))
	vnet_crypto_register_enqueue_handler_by_alg (vm, cm->crypto_engine_index, alg,
						     VNET_CRYPTO_OP_TYPE_DECRYPT,
						     crypto_sw_scheduler_frame_enqueue_decrypt);
    }

  vnet_crypto_register_dequeue_handler (vm, cm->crypto_engine_index, crypto_sw_scheduler_dequeue);

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

      vec_validate_aligned (
	ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT].jobs,
	CRYPTO_SW_SCHEDULER_QUEUE_SIZE - 1, CLIB_CACHE_LINE_BYTES);

      ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].head = 0;
      ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].tail = 0;

      ptd->last_serve_encrypt = 0;
      ptd->last_return_queue = 0;

      vec_validate_aligned (
	ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].jobs,
	CRYPTO_SW_SCHEDULER_QUEUE_SIZE - 1, CLIB_CACHE_LINE_BYTES);
    }

  if (error)
    vec_free (cm->per_thread_data);

  return error;
}

VLIB_CONFIG_FUNCTION (crypto_sw_scheduler_config, "crypto_sw_scheduler");
