/*
 *------------------------------------------------------------------
 * crypto_node.c - DPDK Cryptodev input node
 *
 * Copyright (c) 2016 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ipsec/ipsec.h>

#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <dpdk/ipsec/ipsec.h>

#define foreach_dpdk_crypto_input_next		\
  _(DROP, "error-drop")				\
  _(ENCRYPT_POST, "dpdk-esp-encrypt-post")	\
  _(DECRYPT_POST, "dpdk-esp-decrypt-post")

typedef enum
{
#define _(f,s) DPDK_CRYPTO_INPUT_NEXT_##f,
  foreach_dpdk_crypto_input_next
#undef _
    DPDK_CRYPTO_INPUT_N_NEXT,
} dpdk_crypto_input_next_t;

#define foreach_dpdk_crypto_input_error		\
  _(DQ_COPS, "Crypto ops dequeued")		\
  _(COP_FAILED, "Crypto op failed")

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
  u32 cdev;
  u32 qp;
  u32 status;
  u32 sa_idx;
  u32 next_index;
} dpdk_crypto_input_trace_t;

static u8 *
format_dpdk_crypto_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dpdk_crypto_input_trace_t *t = va_arg (*args, dpdk_crypto_input_trace_t *);

  s = format (s, "dpdk_crypto: cryptodev-id %u queue-pair %u next-index %d",
	      t->cdev, t->qp, t->next_index);

  s = format (s, " status %u sa-idx %u\n", t->status, t->sa_idx);

  return s;
}

static_always_inline u32
dpdk_crypto_dequeue (vlib_main_t * vm, vlib_node_runtime_t * node,
		     crypto_qp_data_t * qpd)
{
  u32 n_deq, *to_next = 0, next_index, n_cops, def_next_index;
  struct rte_crypto_op **cops = qpd->cops;

  if (qpd->inflights == 0)
    return 0;

  if (qpd->is_outbound)
    def_next_index = DPDK_CRYPTO_INPUT_NEXT_ENCRYPT_POST;
  else
    def_next_index = DPDK_CRYPTO_INPUT_NEXT_DECRYPT_POST;

  n_cops = rte_cryptodev_dequeue_burst (qpd->dev_id, qpd->qp_id,
					cops, VLIB_FRAME_SIZE);
  n_deq = n_cops;
  next_index = def_next_index;

  qpd->inflights -= n_cops;
  ASSERT (qpd->inflights >= 0);

  while (n_cops > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_cops > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0 = 0;
	  struct rte_crypto_op *cop;
	  struct rte_crypto_sym_op *sym_cop;

	  cop = cops[0];
	  cops += 1;
	  n_cops -= 1;
	  n_left_to_next -= 1;

	  next0 = def_next_index;

	  if (PREDICT_FALSE (cop->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
	    {
	      next0 = DPDK_CRYPTO_INPUT_NEXT_DROP;
	      vlib_node_increment_counter (vm, dpdk_crypto_input_node.index,
					   DPDK_CRYPTO_INPUT_ERROR_COP_FAILED,
					   1);
	    }
	  cop->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

	  sym_cop = (struct rte_crypto_sym_op *) (cop + 1);
	  b0 = vlib_buffer_from_rte_mbuf (sym_cop->m_src);
	  bi0 = vlib_get_buffer_index (vm, b0);

	  to_next[0] = bi0;
	  to_next += 1;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vlib_trace_next_frame (vm, node, next0);
	      dpdk_crypto_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->cdev = qpd->dev_id;
	      tr->qp = qpd->qp_id;
	      tr->status = cop->status;
	      tr->next_index = next0;
	      tr->sa_idx = vnet_buffer (b0)->ipsec.sad_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  crypto_free_cop (qpd, qpd->cops, n_deq);

  vlib_node_increment_counter (vm, dpdk_crypto_input_node.index,
			       DPDK_CRYPTO_INPUT_ERROR_DQ_COPS, n_deq);
  return n_deq;
}

static uword
dpdk_crypto_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  u32 thread_index = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm = &dcm->workers_main[thread_index];
  crypto_qp_data_t *qpd;
  u32 n_deq = 0;

  /* *INDENT-OFF* */
  vec_foreach (qpd, cwm->qp_data)
      n_deq += dpdk_crypto_dequeue(vm, node, qpd);
  /* *INDENT-ON* */

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
