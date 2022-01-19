/*
 * Copyright (c) 2020 Intel and/or its affiliates.
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
  u32 count = 0, i = vlib_num_workers () > 0;

  if (worker_idx >= vlib_num_workers ())
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }

  for (; i < tm->n_vlib_mains; i++)
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

static void
crypto_sw_scheduler_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
				 vnet_crypto_key_index_t idx)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);

  vec_validate (cm->keys, idx);

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    {
      if (kop == VNET_CRYPTO_KEY_OP_DEL)
	{
	  cm->keys[idx].index_crypto = UINT32_MAX;
	  cm->keys[idx].index_integ = UINT32_MAX;
	}
      else
	{
	  cm->keys[idx] = *key;
	}
    }
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
  u64 head = current_queue->head;

  if (current_queue->jobs[head & CRYPTO_SW_SCHEDULER_QUEUE_MASK])
    {
      u32 n_elts = frame->n_elts, i;
      for (i = 0; i < n_elts; i++)
	frame->elts[i].status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
      return -1;
    }

  current_queue->jobs[head & CRYPTO_SW_SCHEDULER_QUEUE_MASK] = frame;
  head += 1;
  CLIB_MEMORY_STORE_BARRIER ();
  current_queue->head = head;
  return 0;
}

static int
crypto_sw_scheduler_frame_enqueue_decrypt (vlib_main_t *vm,
					   vnet_crypto_async_frame_t *frame)
{
  return crypto_sw_scheduler_frame_enqueue (vm, frame, 0);
    }
    static int
    crypto_sw_scheduler_frame_enqueue_encrypt (
      vlib_main_t *vm, vnet_crypto_async_frame_t *frame)
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

  if (len)
    {
      /* Some async crypto users can use buffers in creative ways, let's allow
       * some flexibility here...
       * Current example is ESP decrypt with ESN in async mode: it will stash
       * ESN at the end of the last buffer (if it can) because it must be part
       * of the integrity check but it will not update the buffer length.
       * Fixup the last operation chunk length if we have room.
       */
      ASSERT (vlib_buffer_space_left_at_end (vm, b) >= len);
      if (vlib_buffer_space_left_at_end (vm, b) >= len)
	ch->len += len;
    }

  op->n_chunks = n_chunks;
}

static_always_inline void
crypto_sw_scheduler_convert_aead (vlib_main_t * vm,
				  crypto_sw_scheduler_per_thread_data_t * ptd,
				  vnet_crypto_async_frame_elt_t * fe,
				  u32 index, u32 bi,
				  vnet_crypto_op_id_t op_id, u16 aad_len,
				  u8 tag_len)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_crypto_op_t *op = 0;

  if (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
    {
      vec_add2 (ptd->chained_crypto_ops, op, 1);
      cryptodev_sw_scheduler_sgl (vm, ptd, b, op, fe->crypto_start_offset,
				  fe->crypto_total_length);
    }
  else
    {
      vec_add2 (ptd->crypto_ops, op, 1);
      op->src = op->dst = b->data + fe->crypto_start_offset;
      op->len = fe->crypto_total_length;
    }

  op->op = op_id;
  op->tag = fe->tag;
  op->flags = fe->flags;
  op->key_index = fe->key_index;
  op->iv = fe->iv;
  op->aad = fe->aad;
  op->aad_len = aad_len;
  op->tag_len = tag_len;
  op->user_data = index;
}

static_always_inline void
crypto_sw_scheduler_convert_link_crypto (vlib_main_t * vm,
					 crypto_sw_scheduler_per_thread_data_t
					 * ptd, vnet_crypto_key_t * key,
					 vnet_crypto_async_frame_elt_t * fe,
					 u32 index, u32 bi,
					 vnet_crypto_op_id_t crypto_op_id,
					 vnet_crypto_op_id_t integ_op_id,
					 u32 digest_len, u8 is_enc)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_crypto_op_t *crypto_op = 0, *integ_op = 0;

  if (fe->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
    {
      vec_add2 (ptd->chained_crypto_ops, crypto_op, 1);
      vec_add2 (ptd->chained_integ_ops, integ_op, 1);
      cryptodev_sw_scheduler_sgl (vm, ptd, b, crypto_op,
				  fe->crypto_start_offset,
				  fe->crypto_total_length);
      cryptodev_sw_scheduler_sgl (vm, ptd, b, integ_op,
				  fe->integ_start_offset,
				  fe->crypto_total_length +
				  fe->integ_length_adj);
    }
  else
    {
      vec_add2 (ptd->crypto_ops, crypto_op, 1);
      vec_add2 (ptd->integ_ops, integ_op, 1);
      crypto_op->src = crypto_op->dst = b->data + fe->crypto_start_offset;
      crypto_op->len = fe->crypto_total_length;
      integ_op->src = integ_op->dst = b->data + fe->integ_start_offset;
      integ_op->len = fe->crypto_total_length + fe->integ_length_adj;
    }

  crypto_op->op = crypto_op_id;
  crypto_op->iv = fe->iv;
  crypto_op->key_index = key->index_crypto;
  crypto_op->user_data = 0;
  crypto_op->flags = fe->flags & ~VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
  integ_op->op = integ_op_id;
  integ_op->digest = fe->digest;
  integ_op->digest_len = digest_len;
  integ_op->key_index = key->index_integ;
  integ_op->flags = fe->flags;
  crypto_op->user_data = integ_op->user_data = index;
}

static_always_inline void
process_ops (vlib_main_t * vm, vnet_crypto_async_frame_t * f,
	     vnet_crypto_op_t * ops, u8 * state)
{
  u32 n_fail, n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  f->elts[op->user_data].status = op->status;
	  *state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
process_chained_ops (vlib_main_t * vm, vnet_crypto_async_frame_t * f,
		     vnet_crypto_op_t * ops, vnet_crypto_op_chunk_t * chunks,
		     u8 * state)
{
  u32 n_fail, n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  n_fail = n_ops - vnet_crypto_process_chained_ops (vm, op, chunks, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  f->elts[op->user_data].status = op->status;
	  *state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
crypto_sw_scheduler_process_aead (vlib_main_t *vm,
				  crypto_sw_scheduler_per_thread_data_t *ptd,
				  vnet_crypto_async_frame_t *f, u32 aead_op,
				  u32 aad_len, u32 digest_len)
{
  vnet_crypto_async_frame_elt_t *fe;
  u32 *bi;
  u32 n_elts = f->n_elts;
  u8 state = VNET_CRYPTO_FRAME_STATE_SUCCESS;

  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->integ_ops);
  vec_reset_length (ptd->chained_crypto_ops);
  vec_reset_length (ptd->chained_integ_ops);
  vec_reset_length (ptd->chunks);

  fe = f->elts;
  bi = f->buffer_indices;

  while (n_elts--)
    {
      if (n_elts > 1)
	clib_prefetch_load (fe + 1);

      crypto_sw_scheduler_convert_aead (vm, ptd, fe, fe - f->elts, bi[0],
					aead_op, aad_len, digest_len);
      bi++;
      fe++;
    }

      process_ops (vm, f, ptd->crypto_ops, &state);
      process_chained_ops (vm, f, ptd->chained_crypto_ops, ptd->chunks,
			   &state);
      f->state = state;
    }

    static_always_inline void
    crypto_sw_scheduler_process_link (
      vlib_main_t *vm, crypto_sw_scheduler_main_t *cm,
      crypto_sw_scheduler_per_thread_data_t *ptd, vnet_crypto_async_frame_t *f,
      u32 crypto_op, u32 auth_op, u16 digest_len, u8 is_enc)
    {
      vnet_crypto_async_frame_elt_t *fe;
      u32 *bi;
      u32 n_elts = f->n_elts;
      u8 state = VNET_CRYPTO_FRAME_STATE_SUCCESS;

      vec_reset_length (ptd->crypto_ops);
      vec_reset_length (ptd->integ_ops);
      vec_reset_length (ptd->chained_crypto_ops);
      vec_reset_length (ptd->chained_integ_ops);
      vec_reset_length (ptd->chunks);
      fe = f->elts;
      bi = f->buffer_indices;

      while (n_elts--)
	{
	  if (n_elts > 1)
	    clib_prefetch_load (fe + 1);

	  crypto_sw_scheduler_convert_link_crypto (
	    vm, ptd, cm->keys + fe->key_index, fe, fe - f->elts, bi[0],
	    crypto_op, auth_op, digest_len, is_enc);
	  bi++;
	  fe++;
	}

      if (is_enc)
	{
	  process_ops (vm, f, ptd->crypto_ops, &state);
	  process_chained_ops (vm, f, ptd->chained_crypto_ops, ptd->chunks,
			       &state);
	  process_ops (vm, f, ptd->integ_ops, &state);
	  process_chained_ops (vm, f, ptd->chained_integ_ops, ptd->chunks,
			       &state);
	}
      else
	{
	  process_ops (vm, f, ptd->integ_ops, &state);
	  process_chained_ops (vm, f, ptd->chained_integ_ops, ptd->chunks,
			       &state);
	  process_ops (vm, f, ptd->crypto_ops, &state);
	  process_chained_ops (vm, f, ptd->chained_crypto_ops, ptd->chunks,
			       &state);
	}

      f->state = state;
    }

    static_always_inline int
    convert_async_crypto_id (vnet_crypto_async_op_id_t async_op_id,
			     u32 *crypto_op, u32 *auth_op_or_aad_len,
			     u16 *digest_len, u8 *is_enc)
    {
      switch (async_op_id)
	{
#define _(n, s, k, t, a)                                                      \
  case VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC:                            \
    *crypto_op = VNET_CRYPTO_OP_##n##_ENC;                                    \
    *auth_op_or_aad_len = a;                                                  \
    *digest_len = t;                                                          \
    *is_enc = 1;                                                              \
    return 1;                                                                 \
  case VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC:                            \
    *crypto_op = VNET_CRYPTO_OP_##n##_DEC;                                    \
    *auth_op_or_aad_len = a;                                                  \
    *digest_len = t;                                                          \
    *is_enc = 0;                                                              \
    return 1;
	  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                      \
  case VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC:                               \
    *crypto_op = VNET_CRYPTO_OP_##c##_ENC;                                    \
    *auth_op_or_aad_len = VNET_CRYPTO_OP_##h##_HMAC;                          \
    *digest_len = d;                                                          \
    *is_enc = 1;                                                              \
    return 0;                                                                 \
  case VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC:                               \
    *crypto_op = VNET_CRYPTO_OP_##c##_DEC;                                    \
    *auth_op_or_aad_len = VNET_CRYPTO_OP_##h##_HMAC;                          \
    *digest_len = d;                                                          \
    *is_enc = 0;                                                              \
    return 0;
	    foreach_crypto_link_async_alg
#undef _

	    default : return -1;
	}

      return -1;
    }

    static_always_inline vnet_crypto_async_frame_t *
    crypto_sw_scheduler_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
				 u32 *enqueue_thread_idx)
    {
      crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
      crypto_sw_scheduler_per_thread_data_t *ptd =
	cm->per_thread_data + vm->thread_index;
      vnet_crypto_async_frame_t *f = 0;
      crypto_sw_scheduler_queue_t *current_queue = 0;
      u32 tail, head;
      u8 found = 0;

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

	      tail = current_queue->tail;
	      head = current_queue->head;

	      for (j = tail; j != head; j++)
		{

		  f = current_queue->jobs[j & CRYPTO_SW_SCHEDULER_QUEUE_MASK];

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

	      if (found || i == ptd->last_serve_lcore_id)
		{
		  CLIB_MEMORY_STORE_BARRIER ();
		  ptd->last_serve_encrypt = !ptd->last_serve_encrypt;
		  break;
		}

	      i++;
	    }

	  ptd->last_serve_lcore_id = i;
	}

      if (found)
	{
	  u32 crypto_op, auth_op_or_aad_len;
	  u16 digest_len;
	  u8 is_enc;
	  int ret;

	  ret = convert_async_crypto_id (
	    f->op, &crypto_op, &auth_op_or_aad_len, &digest_len, &is_enc);

	  if (ret == 1)
	    crypto_sw_scheduler_process_aead (vm, ptd, f, crypto_op,
					      auth_op_or_aad_len, digest_len);
	  else if (ret == 0)
	    crypto_sw_scheduler_process_link (vm, cm, ptd, f, crypto_op,
					      auth_op_or_aad_len, digest_len,
					      is_enc);

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

      tail = current_queue->tail & CRYPTO_SW_SCHEDULER_QUEUE_MASK;

      if (current_queue->jobs[tail] &&
	  current_queue->jobs[tail]->state >= VNET_CRYPTO_FRAME_STATE_SUCCESS)
	{

	  CLIB_MEMORY_STORE_BARRIER ();
	  current_queue->tail++;
	  f = current_queue->jobs[tail];
	  current_queue->jobs[tail] = 0;

	  return f;
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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_sw_scheduler_worker_crypto, static) = {
  .path = "set sw_scheduler",
  .short_help = "set sw_scheduler worker <idx> crypto <on|off>",
  .function = sw_scheduler_set_worker_crypto,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

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
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_sw_scheduler_workers, static) = {
  .path = "show sw_scheduler workers",
  .short_help = "show sw_scheduler workers",
  .function = sw_scheduler_show_workers,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

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
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  crypto_sw_scheduler_per_thread_data_t *ptd;

  vec_validate_aligned (cm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vec_foreach (ptd, cm->per_thread_data)
  {
    ptd->self_crypto_enabled = 1;

    ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT].head = 0;
    ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT].tail = 0;

    vec_validate_aligned (ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT].jobs,
			  CRYPTO_SW_SCHEDULER_QUEUE_SIZE - 1,
			  CLIB_CACHE_LINE_BYTES);

    ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].head = 0;
    ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].tail = 0;

    ptd->last_serve_encrypt = 0;
    ptd->last_return_queue = 0;

    vec_validate_aligned (ptd->queue[CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT].jobs,
			  CRYPTO_SW_SCHEDULER_QUEUE_SIZE - 1,
			  CLIB_CACHE_LINE_BYTES);
  }

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "sw_scheduler", 100,
				 "SW Scheduler Async Engine");

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_sw_scheduler_key_handler);

  crypto_sw_scheduler_api_init (vm);

  /* *INDENT-OFF* */
#define _(n, s, k, t, a)                                                      \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, cm->crypto_engine_index, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,  \
    crypto_sw_scheduler_frame_enqueue_encrypt);                               \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, cm->crypto_engine_index, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,  \
    crypto_sw_scheduler_frame_enqueue_decrypt);
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                      \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, cm->crypto_engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,     \
    crypto_sw_scheduler_frame_enqueue_encrypt);                               \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, cm->crypto_engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,     \
    crypto_sw_scheduler_frame_enqueue_decrypt);
    foreach_crypto_link_async_alg
#undef _
      /* *INDENT-ON* */

      vnet_crypto_register_dequeue_handler (vm, cm->crypto_engine_index,
					    crypto_sw_scheduler_dequeue);

  if (error)
    vec_free (cm->per_thread_data);

  return error;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_sw_scheduler_init) = {
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SW Scheduler Crypto Async Engine plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
