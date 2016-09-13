/*
 *------------------------------------------------------------------
 * dpdk_crypto_node.c - DPDK Cryptodev interface
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
#include <vnet/ipsec/dpdk_ipsec.h>
#include <vnet/ipsec/esp.h>

#define foreach_dpdk_crypto_input_next      \
_(DROP, "error-drop")                       \
_(ENCRYPT_POST, "dpdk-esp-encrypt-post")        \
_(DECRYPT_POST, "dpdk-esp-decrypt-post")   

typedef enum {
#define _(f,s) DPDK_CRYPTO_INPUT_NEXT_##f,
  foreach_dpdk_crypto_input_next
#undef _
  DPDK_CRYPTO_INPUT_N_NEXT,
} dpdk_crypto_input_next_t;

#define foreach_dpdk_crypto_input_error             \
 _(DQ_COPS, "Crypto ops dequeued")                  \
 _(COP_FAILED, "Crypto op failed")

typedef enum {
#define _(f,s) DPDK_CRYPTO_INPUT_ERROR_##f,
  foreach_dpdk_crypto_input_error
#undef _
  DPDK_CRYPTO_INPUT_N_ERROR,
} dpdk_crypto_input_error_t;

static char * dpdk_crypto_input_error_strings[] = {
#define _(n,s) s,
    foreach_dpdk_crypto_input_error
#undef _
};

vlib_node_registration_t dpdk_crypto_input_node;

typedef struct {
  u32 cdev;
  u32 qp;
	u32 status;
	u32 sa_idx;
	u32 next_index;
} dpdk_crypto_input_trace_t;

static u8 * format_dpdk_crypto_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dpdk_crypto_input_trace_t * t = va_arg (*args, dpdk_crypto_input_trace_t *);

  s = format (s, "dpdk_crypto: cryptodev-id %u queue-pair %u next-index %d",
							t->cdev, t->qp, t->next_index);

  s = format (s, "status %u sa-idx %u\n", t->status, t->sa_idx);

  return s;
}

always_inline uword
dpdk_crypto_device_input  (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, ipsec_qp_data_t *qp_data)
{
  u32 n_left, * to_next = 0, next_index, n_cops, total_cops;
  struct rte_crypto_op *cops_buffer[VLIB_FRAME_SIZE];
  struct rte_crypto_op **cops = cops_buffer;

  n_left = VLIB_FRAME_SIZE;

  if (qp_data->outbound)
	  next_index = DPDK_CRYPTO_INPUT_NEXT_ENCRYPT_POST;
  else
	  next_index = DPDK_CRYPTO_INPUT_NEXT_DECRYPT_POST;

  n_cops = rte_cryptodev_dequeue_burst(qp_data->dev_id, qp_data->qp_id, cops, n_left);
  total_cops = n_cops;

  while (n_cops > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_cops > 0 && n_left_to_next > 0)
        {
          u32 bi0, next0;
          vlib_buffer_t * b0 = 0;
	  struct rte_crypto_op * cop;
	  struct rte_crypto_sym_op *sym_cop;

	  cop = cops[0];
	  cops += 1;
	  n_cops -= 1;
	  n_left_to_next -= 1;

	  next0 = next_index;

	  if (PREDICT_FALSE(cop->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
	    {
	      next0 = DPDK_CRYPTO_INPUT_NEXT_DROP;
              vlib_node_increment_counter (vm, dpdk_crypto_input_node.index,
                                           DPDK_CRYPTO_INPUT_ERROR_COP_FAILED, 1);
	    }

	  sym_cop = (struct rte_crypto_sym_op *)(cop + 1);

	  b0 = vlib_buffer_from_rte_mbuf(sym_cop->m_src);

	  bi0 = vlib_get_buffer_index (vm, b0);

	  to_next[0] = bi0;
          to_next += 1;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              b0->flags |= VLIB_BUFFER_IS_TRACED;
	      dpdk_crypto_input_trace_t * tr;
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->cdev = qp_data->dev_id;
	      tr->qp = qp_data->qp_id;
	      tr->status = cop->status;
	      tr->next_index = next0;
	      tr->sa_idx = vnet_buffer(b0)->output_features.ipsec_sad_index;
	    }

          ipsec_free_cop(qp_data, cop);

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
              to_next, n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, dpdk_crypto_input_node.index,
                               DPDK_CRYPTO_INPUT_ERROR_DQ_COPS,
			       total_cops);
  return total_cops;
}

static uword
dpdk_crypto_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
  u32 cpu_index = os_get_cpu_number();
  dpdk_crypto_main_t * dcm = &dpdk_crypto_main;
  ipsec_lcore_main_t *lcore_main = dcm->lcores_main[cpu_index];
  u32 i, n_cops = 0;

  for (i = 0; i < lcore_main->n_qps; i++)
    n_cops += dpdk_crypto_device_input(vm, node, frame, &lcore_main->qp_data[i]);
  return n_cops;
}

VLIB_REGISTER_NODE (dpdk_crypto_input_node) = {
  .function = dpdk_crypto_input_fn,
  .name = "dpdk-crypto-input",
  .format_trace = format_dpdk_crypto_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = DPDK_CRYPTO_INPUT_N_ERROR,
  .error_strings = dpdk_crypto_input_error_strings,

  .n_next_nodes = DPDK_CRYPTO_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPDK_CRYPTO_INPUT_NEXT_##s] = n,
    foreach_dpdk_crypto_input_next
#undef _
  },
};

#if DPDK==1
VLIB_NODE_FUNCTION_MULTIARCH (dpdk_crypto_input_node, dpdk_crypto_input_fn)
#endif

