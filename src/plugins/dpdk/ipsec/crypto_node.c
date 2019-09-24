/*
 *------------------------------------------------------------------
 * crypto_node.c - DPDK Cryptodev input node
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a opy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ipsec/ipsec.h>

#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <dpdk/ipsec/ipsec.h>

#define foreach_dpdk_crypto_input_error		\
  _(DQ_COPS, "Crypto ops dequeued")		\
  _(AUTH_FAILED, "Crypto verification failed")	      \
  _(STATUS, "Crypto operation failed")

typedef enum
{
#define _(f,s) DPDK_CRYPTO_INPUT_ERROR_##f,
  foreach_dpdk_crypto_input_error
#undef _
    DPDK_CRYPTO_INPUT_N_ERROR,
} dpdk_crypto_input_error_t;

static char *dpdk_crypto_input_error_strings[] = {
#define _(n, s) s,
  foreach_dpdk_crypto_input_error
#undef _
};

extern vlib_node_registration_t dpdk_crypto_input_node;

typedef struct
{
  /* dev id of this cryptodev */
  u16 dev_id;
  u16 next_index;
} dpdk_crypto_input_trace_t;

static u8 *
format_dpdk_crypto_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dpdk_crypto_input_trace_t *t = va_arg (*args, dpdk_crypto_input_trace_t *);

  s = format (s, "cryptodev-id %d next-index %d", t->dev_id, t->next_index);

  return s;
}

static_always_inline void
dpdk_crypto_input_check_op (vlib_main_t * vm, vlib_node_runtime_t * node,
			    struct rte_crypto_op *op0, u16 * next)
{
  if (PREDICT_FALSE (op0->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
    {
      next[0] = DPDK_CRYPTO_INPUT_NEXT_DROP;
      vlib_node_increment_counter (vm,
				   node->node_index,
				   DPDK_CRYPTO_INPUT_ERROR_STATUS, 1);
      /* if auth failed */
      if (op0->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED)
	vlib_node_increment_counter (vm,
				     node->node_index,
				     DPDK_CRYPTO_INPUT_ERROR_AUTH_FAILED, 1);
    }
}

always_inline void
dpdk_crypto_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
			 u8 dev_id, u32 * bis, u16 * nexts, u32 n_deq)
{
  u32 n_left, n_trace;

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      n_left = n_deq;

      while (n_trace && n_left)
	{
	  vlib_buffer_t *b0;
	  u16 next;
	  u32 bi;

	  bi = bis[0];
	  next = nexts[0];

	  b0 = vlib_get_buffer (vm, bi);

	  vlib_trace_buffer (vm, node, next, b0, /* follow_chain */ 0);

	  dpdk_crypto_input_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->dev_id = dev_id;
	  tr->next_index = next;

	  n_trace--;
	  n_left--;
	  nexts++;
	  bis++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }
}

static_always_inline u32
dpdk_crypto_dequeue (vlib_main_t * vm, crypto_worker_main_t * cwm,
		     vlib_node_runtime_t * node, crypto_resource_t * res)
{
  u8 numa = rte_socket_id ();
  u32 n_ops, total_n_deq, n_deq[2];
  u32 bis[VLIB_FRAME_SIZE], *bi;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  struct rte_crypto_op **ops;

  n_deq[0] = 0;
  n_deq[1] = 0;
  bi = bis;
  next = nexts;
  ops = cwm->ops;

  n_ops = total_n_deq = rte_cryptodev_dequeue_burst (res->dev_id,
						     res->qp_id,
						     ops, VLIB_FRAME_SIZE);
  /* no op dequeued, do not proceed */
  if (n_ops == 0)
    return 0;

  while (n_ops >= 4)
    {
      struct rte_crypto_op *op0, *op1, *op2, *op3;

      /* Prefetch next iteration. */
      if (n_ops >= 8)
	{
	  CLIB_PREFETCH (ops[4], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (ops[5], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (ops[6], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (ops[7], CLIB_CACHE_LINE_BYTES, LOAD);

	  CLIB_PREFETCH (crypto_op_get_priv (ops[4]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (crypto_op_get_priv (ops[5]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (crypto_op_get_priv (ops[6]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (crypto_op_get_priv (ops[7]),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	}

      op0 = ops[0];
      op1 = ops[1];
      op2 = ops[2];
      op3 = ops[3];

      next[0] = crypto_op_get_priv (op0)->next;
      next[1] = crypto_op_get_priv (op1)->next;
      next[2] = crypto_op_get_priv (op2)->next;
      next[3] = crypto_op_get_priv (op3)->next;

      bi[0] = crypto_op_get_priv (op0)->bi;
      bi[1] = crypto_op_get_priv (op1)->bi;
      bi[2] = crypto_op_get_priv (op2)->bi;
      bi[3] = crypto_op_get_priv (op3)->bi;

      n_deq[crypto_op_get_priv (op0)->encrypt] += 1;
      n_deq[crypto_op_get_priv (op1)->encrypt] += 1;
      n_deq[crypto_op_get_priv (op2)->encrypt] += 1;
      n_deq[crypto_op_get_priv (op3)->encrypt] += 1;

      dpdk_crypto_input_check_op (vm, node, op0, next + 0);
      dpdk_crypto_input_check_op (vm, node, op1, next + 1);
      dpdk_crypto_input_check_op (vm, node, op2, next + 2);
      dpdk_crypto_input_check_op (vm, node, op3, next + 3);

      op0->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
      op1->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
      op2->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
      op3->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

      /* next */
      next += 4;
      n_ops -= 4;
      ops += 4;
      bi += 4;
    }
  while (n_ops > 0)
    {
      struct rte_crypto_op *op0;

      op0 = ops[0];

      next[0] = crypto_op_get_priv (op0)->next;
      bi[0] = crypto_op_get_priv (op0)->bi;

      n_deq[crypto_op_get_priv (op0)->encrypt] += 1;

      dpdk_crypto_input_check_op (vm, node, op0, next + 0);

      op0->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

      /* next */
      next += 1;
      n_ops -= 1;
      ops += 1;
      bi += 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       DPDK_CRYPTO_INPUT_ERROR_DQ_COPS, total_n_deq);

  res->inflights[0] -= n_deq[0];
  res->inflights[1] -= n_deq[1];

  vlib_buffer_enqueue_to_next (vm, node, bis, nexts, total_n_deq);

  dpdk_crypto_input_trace (vm, node, res->dev_id, bis, nexts, total_n_deq);

  crypto_free_ops (numa, cwm->ops, total_n_deq);

  return total_n_deq;
}

static_always_inline uword
dpdk_crypto_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm = &dcm->workers_main[vm->thread_index];
  crypto_resource_t *res;
  u32 n_deq = 0;
  u16 *remove = NULL, *res_idx;
  word i;

  /* *INDENT-OFF* */
  vec_foreach (res_idx, cwm->resource_idx)
    {
      res = vec_elt_at_index (dcm->resource, res_idx[0]);
      u32 inflights = res->inflights[0] + res->inflights[1];

      if (inflights)
	n_deq += dpdk_crypto_dequeue (vm, cwm, node, res);

      inflights = res->inflights[0] + res->inflights[1];
      if (PREDICT_FALSE (res->remove && !(inflights)))
	vec_add1 (remove, res_idx[0]);
    }
  /* *INDENT-ON* */

  /* TODO removal on master thread? */
  if (PREDICT_FALSE (remove != NULL))
    {
      /* *INDENT-OFF* */
      vec_foreach (res_idx, remove)
	{
	  i = vec_search (cwm->resource_idx, res_idx[0]);
	  vec_del1 (cwm->resource_idx, i);

	  res = vec_elt_at_index (dcm->resource, res_idx[0]);
	  res->thread_idx = (u16) ~0;
	  res->remove = 0;

	  i = vec_search (dcm->dev[res->dev_id].used_resources, res_idx[0]);
	  ASSERT (i != (u16) ~0);
	  vec_del1 (dcm->dev[res->dev_id].used_resources, i);
	  vec_add1 (dcm->dev[res->dev_id].free_resources, res_idx[0]);
	}
      /* *INDENT-ON* */

      vec_free (remove);
    }

  return n_deq;
}

VLIB_NODE_FN (dpdk_crypto_input_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * from_frame)
{
  return dpdk_crypto_input_inline (vm, node, from_frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_crypto_input_node) =
{
  .name = "dpdk-crypto-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_dpdk_crypto_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = DPDK_CRYPTO_INPUT_N_ERROR,
  .error_strings = dpdk_crypto_input_error_strings,
  .n_next_nodes = DPDK_CRYPTO_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [DPDK_CRYPTO_INPUT_NEXT_##s] = n,
    foreach_dpdk_crypto_input_next
#undef _
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
