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

vlib_node_registration_t dpdk_crypto_input_node;

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
  i8 *str = 0;

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

static_always_inline u32
dpdk_crypto_dequeue (vlib_main_t * vm, vlib_node_runtime_t * node,
		     crypto_resource_t * res, u8 outbound)
{
  u32 n_deq, total_n_deq = 0, *to_next = 0, n_ops, next_index;
  u32 thread_idx = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  u8 numa = rte_socket_id ();
  crypto_worker_main_t *cwm =
    vec_elt_at_index (dcm->workers_main, thread_idx);
  struct rte_crypto_op **ops;

  next_index = node->cached_next_index;

  do
    {
      ops = cwm->ops;
      n_ops = rte_cryptodev_dequeue_burst (res->dev_id,
					   res->qp_id + outbound,
					   ops, VLIB_FRAME_SIZE);
      res->inflights[outbound] -= n_ops;
      ASSERT (res->inflights >= 0);

      n_deq = n_ops;
      total_n_deq += n_ops;

      while (n_ops > 0)
	{
	  u32 n_left_to_next;

	  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	  while (n_ops > 0 && n_left_to_next > 0)
	    {
	      u32 bi0, next0;
	      vlib_buffer_t *b0 = 0;
	      struct rte_crypto_op *op;

	      op = ops[0];
	      ops += 1;
	      n_ops -= 1;
	      n_left_to_next -= 1;

	      dpdk_op_priv_t *priv = crypto_op_get_priv (op);
	      next0 = priv->next;

	      if (PREDICT_FALSE (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
		{
		  next0 = DPDK_CRYPTO_INPUT_NEXT_DROP;
		  vlib_node_increment_counter (vm,
					       dpdk_crypto_input_node.index,
					       DPDK_CRYPTO_INPUT_ERROR_STATUS,
					       1);
		}

	      /* XXX store bi0 and next0 in op private? */

	      b0 = vlib_buffer_from_rte_mbuf (op->sym[0].m_src);
	      bi0 = vlib_get_buffer_index (vm, b0);

	      to_next[0] = bi0;
	      to_next += 1;

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  vlib_trace_next_frame (vm, node, next0);
		  dpdk_crypto_input_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->status = op->status;
		}

	      op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}

      crypto_free_ops (numa, cwm->ops, n_deq);
    }
  while (n_deq == VLIB_FRAME_SIZE && res->inflights[outbound]);

  vlib_node_increment_counter (vm, dpdk_crypto_input_node.index,
			       DPDK_CRYPTO_INPUT_ERROR_DQ_COPS, total_n_deq);
  return total_n_deq;
}

static uword
dpdk_crypto_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  u32 thread_index = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm = &dcm->workers_main[thread_index];
  crypto_resource_t *res;
  u32 n_deq = 0;
  u8 outbound;
  u16 *remove = NULL, *res_idx;
  word i;

  /* *INDENT-OFF* */
  vec_foreach (res_idx, cwm->resource_idx)
    {
      res = vec_elt_at_index (dcm->resource, res_idx[0]);

      outbound = 0;
      if (res->inflights[outbound])
	n_deq += dpdk_crypto_dequeue (vm, node, res, outbound);

      outbound = 1;
      if (res->inflights[outbound])
	n_deq += dpdk_crypto_dequeue (vm, node, res, outbound);

      if (unlikely(res->remove && !(res->inflights[0] || res->inflights[1])))
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

  /* TODO Clear all sessions in device */

  return n_deq;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_crypto_input_node) =
{
  .function = dpdk_crypto_input_fn,
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

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_crypto_input_node, dpdk_crypto_input_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
