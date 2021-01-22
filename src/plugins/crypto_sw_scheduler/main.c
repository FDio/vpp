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
crypto_sw_scheduler_frame_enqueue (vlib_main_t * vm,
				   vnet_crypto_async_frame_t * frame)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  crypto_sw_scheduler_per_thread_data_t *ptd
    = vec_elt_at_index (cm->per_thread_data, vm->thread_index);
  crypto_sw_scheduler_queue_t *q = ptd->queues[frame->op];
  u64 head = q->head;

  if (q->jobs[head & CRYPTO_SW_SCHEDULER_QUEUE_MASK])
    {
      u32 n_elts = frame->n_elts, i;
      for (i = 0; i < n_elts; i++)
	frame->elts[i].status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
      return -1;
    }
  q->jobs[head & CRYPTO_SW_SCHEDULER_QUEUE_MASK] = frame;
  head += 1;
  CLIB_MEMORY_STORE_BARRIER ();
  q->head = head;
  return 0;
}

static_always_inline vnet_crypto_async_frame_t *
crypto_sw_scheduler_get_pending_frame (crypto_sw_scheduler_queue_t * q)
{
  vnet_crypto_async_frame_t *f;
  u32 i;
  u32 tail = q->tail;
  u32 head = q->head;

  for (i = tail; i < head; i++)
    {
      f = q->jobs[i & CRYPTO_SW_SCHEDULER_QUEUE_MASK];
      if (!f)
	continue;
      if (clib_atomic_bool_cmp_and_swap
	  (&f->state, VNET_CRYPTO_FRAME_STATE_PENDING,
	   VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS))
	{
	  return f;
	}
    }
  return NULL;
}

static_always_inline vnet_crypto_async_frame_t *
crypto_sw_scheduler_get_completed_frame (crypto_sw_scheduler_queue_t * q)
{
  vnet_crypto_async_frame_t *f = 0;
  if (q->jobs[q->tail & CRYPTO_SW_SCHEDULER_QUEUE_MASK]
      && q->jobs[q->tail & CRYPTO_SW_SCHEDULER_QUEUE_MASK]->state
      >= VNET_CRYPTO_FRAME_STATE_SUCCESS)
    {
      u32 tail = q->tail;
      CLIB_MEMORY_STORE_BARRIER ();
      q->tail++;
      f = q->jobs[tail & CRYPTO_SW_SCHEDULER_QUEUE_MASK];
      q->jobs[tail & CRYPTO_SW_SCHEDULER_QUEUE_MASK] = 0;
    }
  return f;
}

static_always_inline void
cryptodev_sw_scheduler_sgl (vlib_main_t * vm,
			    crypto_sw_scheduler_per_thread_data_t * ptd,
			    vlib_buffer_t * b, vnet_crypto_op_t * op,
			    i32 offset, i32 len)
{
  vnet_crypto_op_chunk_t *ch;
  vlib_buffer_t *nb = b;
  u32 n_chunks = 0;
  u32 chunk_index = vec_len (ptd->chunks);

  while (len)
    {
      if (nb->current_data + nb->current_length > offset)
	{
	  vec_add2 (ptd->chunks, ch, 1);
	  ch->src = ch->dst = nb->data + offset;
	  ch->len
	    = clib_min (nb->current_data + nb->current_length - offset, len);
	  len -= ch->len;
	  offset = 0;
	  n_chunks++;
	  if (!len)
	    break;
	}
      if (offset)
	offset -= nb->current_data + nb->current_length;
      if (nb->flags & VLIB_BUFFER_NEXT_PRESENT)
	nb = vlib_get_buffer (vm, nb->next_buffer);
      else
	break;
    }

  ASSERT (offset == 0 && len == 0);
  op->chunk_index = chunk_index;
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
  integ_op->flags = fe->flags & ~VNET_CRYPTO_OP_FLAG_INIT_IV;
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

static_always_inline vnet_crypto_async_frame_t *
crypto_sw_scheduler_dequeue_aead (vlib_main_t * vm,
				  vnet_crypto_async_op_id_t async_op_id,
				  vnet_crypto_op_id_t sync_op_id, u8 tag_len,
				  u8 aad_len, u32 * nb_elts_processed,
				  u32 * enqueue_thread_idx)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  crypto_sw_scheduler_per_thread_data_t *ptd = 0;
  crypto_sw_scheduler_queue_t *q = 0;
  vnet_crypto_async_frame_t *f = 0;
  vnet_crypto_async_frame_elt_t *fe;
  u32 *bi;
  u32 n_elts;
  int i = 0;
  u8 state = VNET_CRYPTO_FRAME_STATE_SUCCESS;

  if (cm->per_thread_data[vm->thread_index].self_crypto_enabled)
    {
      /* *INDENT-OFF* */
      vec_foreach_index (i, cm->per_thread_data)
      {
        ptd = cm->per_thread_data + i;
        q = ptd->queues[async_op_id];
        f = crypto_sw_scheduler_get_pending_frame (q);
        if (f)
          break;
      }
      /* *INDENT-ON* */
    }

  ptd = cm->per_thread_data + vm->thread_index;

  if (f)
    {
      *nb_elts_processed = n_elts = f->n_elts;
      fe = f->elts;
      bi = f->buffer_indices;

      vec_reset_length (ptd->crypto_ops);
      vec_reset_length (ptd->chained_crypto_ops);
      vec_reset_length (ptd->chunks);

      while (n_elts--)
	{
	  if (n_elts > 1)
	    CLIB_PREFETCH (fe + 1, CLIB_CACHE_LINE_BYTES, LOAD);

	  crypto_sw_scheduler_convert_aead (vm, ptd, fe, fe - f->elts, bi[0],
					    sync_op_id, aad_len, tag_len);
	  bi++;
	  fe++;
	}

      process_ops (vm, f, ptd->crypto_ops, &state);
      process_chained_ops (vm, f, ptd->chained_crypto_ops, ptd->chunks,
			   &state);
      f->state = state;
      *enqueue_thread_idx = f->enqueue_thread_index;
    }

  return crypto_sw_scheduler_get_completed_frame (ptd->queues[async_op_id]);
}

static_always_inline vnet_crypto_async_frame_t *
crypto_sw_scheduler_dequeue_link (vlib_main_t * vm,
				  vnet_crypto_async_op_id_t async_op_id,
				  vnet_crypto_op_id_t sync_crypto_op_id,
				  vnet_crypto_op_id_t sync_integ_op_id,
				  u16 digest_len, u8 is_enc,
				  u32 * nb_elts_processed,
				  u32 * enqueue_thread_idx)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  crypto_sw_scheduler_per_thread_data_t *ptd = 0;
  crypto_sw_scheduler_queue_t *q = 0;
  vnet_crypto_async_frame_t *f = 0;
  vnet_crypto_async_frame_elt_t *fe;
  u32 *bi;
  u32 n_elts;
  int i = 0;
  u8 state = VNET_CRYPTO_FRAME_STATE_SUCCESS;

  if (cm->per_thread_data[vm->thread_index].self_crypto_enabled)
    {
      /* *INDENT-OFF* */
      vec_foreach_index (i, cm->per_thread_data)
      {
        ptd = cm->per_thread_data + i;
        q = ptd->queues[async_op_id];
        f = crypto_sw_scheduler_get_pending_frame (q);
        if (f)
          break;
      }
      /* *INDENT-ON* */
    }

  ptd = cm->per_thread_data + vm->thread_index;

  if (f)
    {
      vec_reset_length (ptd->crypto_ops);
      vec_reset_length (ptd->integ_ops);
      vec_reset_length (ptd->chained_crypto_ops);
      vec_reset_length (ptd->chained_integ_ops);
      vec_reset_length (ptd->chunks);

      *nb_elts_processed = n_elts = f->n_elts;
      fe = f->elts;
      bi = f->buffer_indices;

      while (n_elts--)
	{
	  if (n_elts > 1)
	    CLIB_PREFETCH (fe + 1, CLIB_CACHE_LINE_BYTES, LOAD);

	  crypto_sw_scheduler_convert_link_crypto (vm, ptd,
						   cm->keys + fe->key_index,
						   fe, fe - f->elts, bi[0],
						   sync_crypto_op_id,
						   sync_integ_op_id,
						   digest_len, is_enc);
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
      *enqueue_thread_idx = f->enqueue_thread_index;
    }

  return crypto_sw_scheduler_get_completed_frame (ptd->queues[async_op_id]);
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

/* *INDENT-OFF* */
#define _(n, s, k, t, a)                                                      \
  static vnet_crypto_async_frame_t                                            \
      *crypto_sw_scheduler_frame_dequeue_##n##_TAG_##t##_AAD_##a##_enc (      \
          vlib_main_t *vm, u32 *nb_elts_processed, u32 * thread_idx)          \
  {                                                                           \
    return crypto_sw_scheduler_dequeue_aead (                                 \
        vm, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,                       \
        VNET_CRYPTO_OP_##n##_ENC, t, a, nb_elts_processed, thread_idx);       \
  }                                                                           \
  static vnet_crypto_async_frame_t                                            \
      *crypto_sw_scheduler_frame_dequeue_##n##_TAG_##t##_AAD_##a##_dec (      \
          vlib_main_t *vm, u32 *nb_elts_processed, u32 * thread_idx)          \
  {                                                                           \
    return crypto_sw_scheduler_dequeue_aead (                                 \
        vm, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,                       \
        VNET_CRYPTO_OP_##n##_DEC, t, a, nb_elts_processed, thread_idx);       \
  }
foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                      \
  static vnet_crypto_async_frame_t                                            \
      *crypto_sw_scheduler_frame_dequeue_##c##_##h##_TAG##d##_enc (           \
          vlib_main_t *vm, u32 *nb_elts_processed, u32 * thread_idx)          \
  {                                                                           \
    return crypto_sw_scheduler_dequeue_link (                                 \
        vm, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,                          \
        VNET_CRYPTO_OP_##c##_ENC, VNET_CRYPTO_OP_##h##_HMAC, d, 1,            \
        nb_elts_processed, thread_idx);                                       \
  }                                                                           \
  static vnet_crypto_async_frame_t                                            \
      *crypto_sw_scheduler_frame_dequeue_##c##_##h##_TAG##d##_dec (           \
          vlib_main_t *vm, u32 *nb_elts_processed, u32 * thread_idx)          \
  {                                                                           \
    return crypto_sw_scheduler_dequeue_link (                                 \
        vm, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,                          \
        VNET_CRYPTO_OP_##c##_DEC, VNET_CRYPTO_OP_##h##_HMAC, d, 0,            \
        nb_elts_processed, thread_idx);                                       \
  }
    foreach_crypto_link_async_alg
#undef _
        /* *INDENT-ON* */

crypto_sw_scheduler_main_t crypto_sw_scheduler_main;
clib_error_t *
crypto_sw_scheduler_init (vlib_main_t * vm)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  crypto_sw_scheduler_per_thread_data_t *ptd;

  u32 queue_size = CRYPTO_SW_SCHEDULER_QUEUE_SIZE * sizeof (void *)
    + sizeof (crypto_sw_scheduler_queue_t);

  vec_validate_aligned (cm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vec_foreach (ptd, cm->per_thread_data)
  {
    ptd->self_crypto_enabled = 1;
    u32 i;
    for (i = 0; i < VNET_CRYPTO_ASYNC_OP_N_IDS; i++)
      {
	crypto_sw_scheduler_queue_t *q
	  = clib_mem_alloc_aligned (queue_size, CLIB_CACHE_LINE_BYTES);
	ASSERT (q != 0);
	ptd->queues[i] = q;
	clib_memset_u8 (q, 0, queue_size);
      }
  }

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "sw_scheduler", 100,
				 "SW Scheduler Async Engine");

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_sw_scheduler_key_handler);

  crypto_sw_scheduler_api_init (vm);

  /* *INDENT-OFF* */
#define _(n, s, k, t, a)                                                      \
  vnet_crypto_register_async_handler (                                        \
      vm, cm->crypto_engine_index,                                            \
      VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,                             \
      crypto_sw_scheduler_frame_enqueue,                                      \
      crypto_sw_scheduler_frame_dequeue_##n##_TAG_##t##_AAD_##a##_enc);       \
  vnet_crypto_register_async_handler (                                        \
      vm, cm->crypto_engine_index,                                            \
      VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,                             \
      crypto_sw_scheduler_frame_enqueue,                                      \
      crypto_sw_scheduler_frame_dequeue_##n##_TAG_##t##_AAD_##a##_dec);
  foreach_crypto_aead_async_alg
#undef _

#define _(c, h, s, k, d)                                                      \
  vnet_crypto_register_async_handler (                                        \
      vm, cm->crypto_engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,   \
      crypto_sw_scheduler_frame_enqueue,                                      \
      crypto_sw_scheduler_frame_dequeue_##c##_##h##_TAG##d##_enc);            \
  vnet_crypto_register_async_handler (                                        \
      vm, cm->crypto_engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,   \
      crypto_sw_scheduler_frame_enqueue,                                      \
      crypto_sw_scheduler_frame_dequeue_##c##_##h##_TAG##d##_dec);
      foreach_crypto_link_async_alg
#undef _
      /* *INDENT-ON* */

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
