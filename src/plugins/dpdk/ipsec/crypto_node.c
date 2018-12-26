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
  u32 status;
} dpdk_crypto_input_trace_t;

#define foreach_cryptodev_status \
    _(SUCCESS, "success") \
    _(NOT_PROCESSED, "not processed") \
    _(AUTH_FAILED, "auth failed") \
    _(INVALID_SESSION, "invalid session") \
    _(INVALID_ARGS, "invalid arguments") \
    _(ERROR, "error")

static u8 *
format_cryptodev_status (u8 * s, va_list * args)
{
  u32 status = va_arg (*args, u32);
  char *str = 0;

  switch (status)
    {
#define _(x, z) case RTE_CRYPTO_OP_STATUS_##x: str = z; break;
      foreach_cryptodev_status
#undef _
    }
  s = format (s, "%s", str);

  return s;
}

static u8 *
format_dpdk_crypto_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dpdk_crypto_input_trace_t *t = va_arg (*args, dpdk_crypto_input_trace_t *);

  s = format (s, "status: %U", format_cryptodev_status, t->status);

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
			 struct rte_crypto_op **ops, u32 n_deq)
{
  u32 n_left, n_trace;
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      n_left = n_deq;

      while (n_trace && n_left)
	{
	  vlib_buffer_t *b0;
	  struct rte_crypto_op *op0;
	  u16 next;

	  op0 = ops[0];

	  next = crypto_op_get_priv (op0)->next;

	  b0 = vlib_buffer_from_rte_mbuf (op0->sym[0].m_src);

	  vlib_trace_buffer (vm, node, next, b0, /* follow_chain */ 0);

	  dpdk_crypto_input_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->status = op0->status;

	  n_trace--;
	  n_left--;
	  ops++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }
}

static_always_inline u32
dpdk_crypto_dequeue (vlib_main_t * vm, vlib_node_runtime_t * node,
		     crypto_resource_t * res, u8 outbound)
{
  u32 thread_idx = vlib_get_thread_index ();
  u8 numa = rte_socket_id ();

  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm =
    vec_elt_at_index (dcm->workers_main, thread_idx);

  u32 n_ops, n_deq;
  u32 bis[VLIB_FRAME_SIZE], *bi;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  struct rte_crypto_op **ops;

  bi = bis;
  next = nexts;
  ops = cwm->ops;

  n_ops = n_deq = rte_cryptodev_dequeue_burst (res->dev_id,
					       res->qp_id + outbound,
					       ops, VLIB_FRAME_SIZE);

  if (n_deq > 0)
    {
      res->inflights[outbound] -= n_ops;

      dpdk_crypto_input_trace (vm, node, ops, n_deq);

      while (n_ops >= 4)
	{
	  struct rte_crypto_op *op0, *op1, *op2, *op3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;

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

	  dpdk_crypto_input_check_op (vm, node, op0, next + 0);
	  dpdk_crypto_input_check_op (vm, node, op1, next + 1);
	  dpdk_crypto_input_check_op (vm, node, op2, next + 2);
	  dpdk_crypto_input_check_op (vm, node, op3, next + 3);

	  b0 = vlib_buffer_from_rte_mbuf (op0->sym[0].m_src);
	  b1 = vlib_buffer_from_rte_mbuf (op1->sym[0].m_src);
	  b2 = vlib_buffer_from_rte_mbuf (op2->sym[0].m_src);
	  b3 = vlib_buffer_from_rte_mbuf (op3->sym[0].m_src);

	  bi[0] = vlib_get_buffer_index (vm, b0);
	  bi[1] = vlib_get_buffer_index (vm, b1);
	  bi[2] = vlib_get_buffer_index (vm, b2);
	  bi[3] = vlib_get_buffer_index (vm, b3);

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
	  vlib_buffer_t *b0;

	  op0 = ops[0];

	  next[0] = crypto_op_get_priv (op0)->next;

	  dpdk_crypto_input_check_op (vm, node, op0, next + 0);

	  /* XXX store bi0 and next0 in op0 private? */
	  b0 = vlib_buffer_from_rte_mbuf (op0->sym[0].m_src);
	  bi[0] = vlib_get_buffer_index (vm, b0);

	  op0->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

	  /* next */
	  next += 1;
	  n_ops -= 1;
	  ops += 1;
	  bi += 1;
	}

      vlib_node_increment_counter (vm, node->node_index,
				   DPDK_CRYPTO_INPUT_ERROR_DQ_COPS, n_deq);

      vlib_buffer_enqueue_to_next (vm, node, bis, nexts, n_deq);

      crypto_free_ops (numa, cwm->ops, n_deq);
    }

  return n_deq;
}

static_always_inline uword
dpdk_crypto_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  u32 thread_index = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm = &dcm->workers_main[thread_index];
  crypto_resource_t *res;
  u32 n_deq = 0;
  u16 *remove = NULL, *res_idx;
  word i;

  /* *INDENT-OFF* */
  vec_foreach (res_idx, cwm->resource_idx)
    {
      res = vec_elt_at_index (dcm->resource, res_idx[0]);

      if (res->inflights[0])
	n_deq += dpdk_crypto_dequeue (vm, node, res, 0);

      if (res->inflights[1])
	n_deq += dpdk_crypto_dequeue (vm, node, res, 1);

      if (PREDICT_FALSE (res->remove && !(res->inflights[0] || res->inflights[1])))
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
