/*
 * crypto_trace.c - based on handoff_trace.c
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco Systems and/or its affiliates.
 * Copyright (c) 2026 LabN, LLC
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

/*
 * Capture up to this many bytes of each
 */
#define AAD_LEN_MAX   32
#define AUTH_LEN_MAX  32
#define DATA_HEAD_LEN 32
#define DATA_TAIL_LEN 32

typedef struct
{
  u32 bi;
  vnet_crypto_op_t op; /* copy of original op */
  vnet_crypto_alg_t alg;
  u8 *tail_start_addr;
  int data_head_len;
  int data_tail_len;
  u8 aad[AAD_LEN_MAX];
  u8 auth[AUTH_LEN_MAX];
  u8 data_head[DATA_HEAD_LEN];
  u8 data_tail[DATA_TAIL_LEN];
} crypto_trace_t;

static u8 *
format_crypto_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  crypto_trace_t *t = va_arg (*args, crypto_trace_t *);
  vnet_crypto_op_t *o = &t->op;
  int offset_iv, offset_aad, offset_auth;
  int len;
  u8 status = o->status;

  s = format (s, "crypto: bi %u=0x%x, alg %U, op %U\n", t->bi, t->bi, format_vnet_crypto_alg,
	      t->alg, format_vnet_crypto_op_type, o->type);
  s = format (s, "  status %U, flags [%U], ", format_vnet_crypto_op_status, status,
	      format_vnet_crypto_op_flags, o->flags);

  s = format (s, "auth_src_len/aad_len %u, auth_len %u\n", o->aad_len, o->auth_len);

  if (o->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
    {
      s = format (s, "  n_chunks %u, chunk_index %u, auth_chunk_index %u\n", o->n_chunks,
		  o->chunk_index, o->auth_chunk_index);
    }
  else
    {
      s = format (s, "  src %p, dst %p, len %u\n", o->src, o->dst, o->len);
    }

  offset_iv = (intptr_t) o->iv - (intptr_t) o->src;	/* read */
  offset_aad = (intptr_t) o->aad - (intptr_t) o->src;	/* read */
  offset_auth = (intptr_t) o->auth - (intptr_t) o->dst; /* write */

  s = format (s, "  iv %p(%d), aad %p(%d), auth %p(%d)\n", o->iv, offset_iv, o->aad, offset_aad,
	      o->auth, offset_auth);
  s = format (s, "  user_data %u=0x%x\n", o->user_data, o->user_data);

  if (o->aad_len)
    {
      len = clib_min (o->aad_len, AAD_LEN_MAX);
      s = format (s, "  AAD%s\n    %U\n", ((o->aad_len > AAD_LEN_MAX) ? " (truncated)" : ""),
		  format_hexdump, t->aad, len);
    }
  if (o->auth_len)
    {
      len = clib_min (o->auth_len, AUTH_LEN_MAX);
      s = format (s, "  Auth%s\n    %U\n", ((o->auth_len > AUTH_LEN_MAX) ? " (truncated)" : ""),
		  format_hexdump, t->auth, len);
    }

  if (t->data_head_len)
    {
      s = format (s, "  Data head (%p)\n    %U\n", o->src, format_hexdump, t->data_head,
		  t->data_head_len);
    }
  if (t->data_tail_len)
    {
      s = format (s, "  Data tail (%p)\n    %U\n", t->tail_start_addr, format_hexdump, t->data_tail,
		  t->data_tail_len);
    }

  return s;
}

static vlib_node_registration_t crypto_trace_node;

#define foreach_crypto_trace_error _ (BUGS, "Warning: packet sent to the crypto trace node")

typedef enum
{
#define _(sym, str) CRYPTO_TRACE_ERROR_##sym,
  foreach_crypto_trace_error
#undef _
    CRYPTO_TRACE_N_ERROR,
} crypto_trace_error_t;

static char *crypto_trace_error_strings[] = {
#define _(sym, string) string,
  foreach_crypto_trace_error
#undef _
};

static uword
crypto_trace_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index, CRYPTO_TRACE_ERROR_BUGS, frame->n_vectors);

  return frame->n_vectors;
}

typedef enum
{
  CRYPTO_TRACE_NEXT_DROP,
  CRYPTO_TRACE_N_NEXT,
} tplaceholder_next_t;

VLIB_REGISTER_NODE (crypto_trace_node, static) =
{
  .name = "crypto_trace",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .function = crypto_trace_node_fn,
  .vector_size = sizeof (u32),
  .format_trace = format_crypto_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = CRYPTO_TRACE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [CRYPTO_TRACE_NEXT_DROP] = "error-drop",
  },

  .n_errors = ARRAY_LEN(crypto_trace_error_strings),
  .error_strings = crypto_trace_error_strings,
};

/*
 * This trace function makes a snapshot of the current vnet_crypto_op_t
 * in the vlib_buffer trace. Thus, it needs to be called from a place
 * where both the buffer and the corresponding crypto op are available.
 * Typically, this place will be whatever function assembles the crypto
 * op vector from the buffers.
 *
 * The call should be made before but as close as possible to the call
 * to vnet_crypto_process*_ops() so that it accurately captures the
 * contents of the op before the crypto operation. In the case of
 * synchronous operation, that will be the client of vnet_crypto. But in
 * the asynchronous case, that will be crypto_sw_scheduler.
 */
int
vnet_crypto_add_trace (vlib_main_t *vm, u32 bi, vnet_crypto_op_t *op)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  crypto_trace_t *t;
  int len;
  vlib_node_runtime_t *node = vlib_node_get_runtime (vm, crypto_trace_node.index);
  bool is_chain = (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS);

  if (PREDICT_FALSE (
	!vlib_trace_buffer (vm, node, 0 /* fake next frame index */, b, 1 /* follow chain */)))
    return 0;

  t = vlib_add_trace (vm, node, b, sizeof (*t));
  t->op = *op;
  t->bi = bi;
  t->alg = op->ctx->alg;
  t->data_head_len = 0;
  t->data_tail_len = 0;

  if (op->aad_len)
    {
      len = clib_min (op->aad_len, sizeof (t->aad));
      clib_memcpy_fast (t->aad, op->aad, len);
    }
  if (t->op.auth_len)
    {
      len = clib_min (op->auth_len, sizeof (t->auth));
      clib_memcpy_fast (t->auth, op->auth, len);
    }

  /*
   * This head and tail data sampling does not handle chained buffers yet
   */
  if (!is_chain)
    {
      if (t->op.len)
	{
	  len = clib_min (t->op.len, sizeof (t->data_head));
	  clib_memcpy_fast (t->data_head, t->op.src, len);
	  t->data_head_len = len;

	  if (t->op.len > sizeof (t->data_head))
	    {
	      u8 *src;

	      len = clib_min (t->op.len, sizeof (t->data_tail));
	      src = t->op.src + t->op.len - len;

	      t->tail_start_addr = src;
	      clib_memcpy_fast (t->data_tail, src, len);
	      t->data_tail_len = len;
	    }
	}
    }

  return 1;
}
