/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/*
 *   WARNING!
 *   This driver is not intended for production use and it is unsupported.
 *   It is provided for educational use only.
 *   Please use supported DPDK driver instead.
 */


#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <mlx5/mlx5.h>

#define foreach_mlx5_input_error \
  _(NOT_IP, "not ip packet")

typedef enum
{
#define _(f,s) MLX5_INPUT_ERROR_##f,
  foreach_mlx5_input_error
#undef _
    MLX5_INPUT_N_ERROR,
} mlx5_input_error_t;

static char *mlx5_input_error_strings[] = {
#define _(n,s) s,
  foreach_mlx5_input_error
#undef _
};

#define foreach_cqe_rx_field \
  _(0x1c, 26, 26, l4_ok)	\
  _(0x1c, 25, 25, l3_ok)	\
  _(0x1c, 24, 24, l2_ok)	\
  _(0x1c, 23, 23, ip_frag)	\
  _(0x1c, 22, 20, l4_hdr_type)	\
  _(0x1c, 19, 18, l3_hdr_type)	\
  _(0x1c, 17, 17, ip_ext_opts)	\
  _(0x1c, 16, 16, cv)	\
  _(0x2c, 31,  0, byte_cnt)	\
  _(0x30, 63,  0, timestamp)	\
  _(0x38, 31, 24, rx_drop_counter)	\
  _(0x38, 23,  0, flow_tag)	\
  _(0x3c, 31, 16, wqe_counter)	\
  _(0x3c, 15,  8, signature)	\
  _(0x3c,  7,  4, opcode)	\
  _(0x3c,  3,  2, cqe_format)	\
  _(0x3c,  1,  1, sc)	\
  _(0x3c,  0,  0, owner)

u8 *
format_mlx5_cqe_rx (u8 * s, va_list * args)
{
  void *cqe = va_arg (*args, void *);
  uword indent = format_get_indent (s);
  int line = 0;

#define _(a, b, c, d) if (mlx5_get_bits (cqe, a, b, c)) s = format (s, "%U%U\n",	\
				    format_white_space, line++ ? indent : 0,	\
				    format_mlx5_field, cqe, a, b, c, #d);
  foreach_cqe_rx_field;
#undef _
  return s;
}

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u8 cqe[64];
} mlx5_input_trace_t;

static u8 *
format_mlx5_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mlx5_input_trace_t *t = va_arg (*args, mlx5_input_trace_t *);
  uword indent = format_get_indent (s);

  s = format (s, "mlx5: hw_if_index %d next-index %d\n%U%U",
	      t->hw_if_index, t->next_index, format_white_space, indent + 2,
	      format_mlx5_cqe_rx, t->cqe);
  return s;
}

static_always_inline uword
mlx5_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, mlx5_device_t * md, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword n_trace = vlib_get_trace_count (vm, node);
  mlx5_rxq_t *rxq = vec_elt_at_index (md->rx_queues, 0);
  u16 mask = (1 << rxq->log_wq_sz) - 1;
  void *cqe = rxq->cq_mem + 64 * (rxq->cq_ci & mask);
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 next_index;
  u32 *to_next = 0;
  u32 n_left_to_next;

  next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
  while (n_left_to_next && (mlx5_get_u32 (cqe, 0x3c) & ~1))
    {
      u16 idx0 = rxq->cq_ci & mask;
      u32 bi0 = rxq->enq[idx0];
      u32 next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      b0->total_length_not_including_first_buffer = 0;
      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = md->sw_if_index;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
      b0->current_length = mlx5_get_u32 (cqe, 0x2c);
      n_rx_bytes += b0->current_length;

      //fformat (stderr, "\ncqe %U\n", format_mlx5_cqe_rx, cqe);
      if (PREDICT_FALSE (n_trace > 0))
	{
	  mlx5_input_trace_t *tr;
	  vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0);
	  vlib_set_trace_count (vm, node, --n_trace);
	  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->next_index = next0;
	  tr->hw_if_index = md->hw_if_index;
	  clib_memcpy (tr->cqe, cqe, 64);
	}
      to_next[0] = rxq->enq[rxq->cq_ci & mask];
      to_next++;
      n_left_to_next--;
      rxq->cq_ci++;
      cqe = rxq->cq_mem + 64 * (rxq->cq_ci & mask);
      n_rx_packets++;
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  CLIB_MEMORY_BARRIER ();
  *rxq->cq_db = clib_host_to_net_u32 (rxq->cq_ci);
  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX,
				   node->thread_index, md->hw_if_index,
				   n_rx_packets, n_rx_bytes);
  return n_rx_packets;
}

static uword
mlx5_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  u32 n_rx = 0;
  mlx5_main_t *mm = &mlx5_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    mlx5_device_t *md;
    md = vec_elt_at_index (mm->devices, dq->dev_instance);
    if (md->flags & MLX5_DEVICE_F_ADMIN_UP)
      {
	n_rx += mlx5_device_input_inline (vm, node, frame, md, dq->queue_id);
      }
  }

  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mlx5_input_node) = {
  .function = mlx5_input_fn,
  .name = "mlx5-input",
  .sibling_of = "device-input",
  .format_trace = format_mlx5_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = MLX5_INPUT_N_ERROR,
  .error_strings = mlx5_input_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (mlx5_input_node, mlx5_input_fn)
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
