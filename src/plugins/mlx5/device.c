/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>

#include <mlx5/mlx5.h>
#define foreach_cqe_field \
  _(0x30, 63,  0, timestamp)	\
  _(0x38, 31, 24, send_wqe_opcode)	\
  _(0x3c, 31, 16, wqe_counter)	\
  _(0x3c, 15,  8, signature)	\
  _(0x3c,  7,  4, opcode)	\
  _(0x3c,  3,  2, cqe_format)	\
  _(0x3c,  1,  1, sc)	\
  _(0x3c,  0,  0, owner)

u8 *
format_mlx5_cqe (u8 * s, va_list * args)
{
  void *cqe = va_arg (*args, void *);
  uword indent = format_get_indent (s);
  int line = 0;

#define _(a, b, c, d) s = format (s, "%U%U\n",				\
				    format_white_space, line++ ? indent : 0,	\
				    format_mlx5_field, cqe, a, b, c, #d);
  foreach_cqe_field;
#undef _
  return s;
}

static_always_inline void
mlx5_buffer_free (vlib_main_t * vm, u32 * buffers, u32 n_packets)
{
  vlib_buffer_free (vm, buffers, n_packets);
}

static uword
mlx5_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  mlx5_main_t *mm = &mlx5_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  mlx5_device_t *md = vec_elt_at_index (mm->devices, rd->dev_instance);
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  u32 qid = 0;
  void *wqe = 0;
  mlx5_txq_t *txq = vec_elt_at_index (md->tx_queues, qid);

  /* check if we have transmitted buffers */
  if (mlx5_get_bits (txq->cq_mem, 0x3c, 0, 0) == 0)
    {
      u8 send_wqe_opcode = mlx5_get_bits (txq->cq_mem, 0x38, 31, 24);
      u16 wqe_counter;

      if (PREDICT_FALSE (send_wqe_opcode != 0x0a))
	{
	  clib_warning ("unknown opcode 0x%0x, interface disabled",
			send_wqe_opcode);
	  clib_warning ("CQE data: %U", format_mlx5_cqe, txq->cq_mem);
	}
      wqe_counter = mlx5_get_bits (txq->cq_mem, 0x3c, 31, 16);
      while (txq->last_wqe_counter != wqe_counter)
	{
	  txq->last_wqe_counter++;
	  mlx5_buffer_free (vm, &txq->enq[txq->last_wqe_counter], 1);
	}
    }

  while (n_left)
    {
      u32 bi0 = buffers[0];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      u64 pa = 0;
      wqe = txq->sq_mem + (txq->slot << txq->log_wq_stride);

      txq->enq[txq->slot] = bi0;

//      fformat (stderr, "===========================\nslot   %u\n", txq->slot);
      memset (wqe, 0, 64);
      /* Control Segment */
      mlx5_set_bits (wqe, 0x00, 23, 8, txq->slot);	/* WQE Index */
      mlx5_set_bits (wqe, 0x00, 7, 0, 0x0a);	/* opcode 0x0a - Send */
      mlx5_set_bits (wqe, 0x04, 31, 8, txq->sqn);
      mlx5_set_bits (wqe, 0x04, 5, 0, 4);	/* DS: 4 => 64 byte */
      mlx5_set_bits (wqe, 0x08, 3, 2, 3 /*2 */ );	/* CE: 2 => cqe always */

      /* Ethernet Segment */
      mlx5_set_bits (wqe, 0x1c, 25, 16, 16);
      memcpy (wqe + 0x1e, vlib_buffer_get_current (b0), 16);

      /* Send Data Segment */
      mlx5_set_bits (wqe, 0x30, 30, 0, b0->current_length);	/* byte_count */
      mlx5_set_bits (wqe, 0x34, 31, 0, md->reserved_lkey);	/* l_key */
      pa = vlib_buffer_get_current_pa (vm, vlib_get_buffer (vm, bi0)) + 16;
      mlx5_set_u64 (wqe, 0x38, pa);

      buffers++;
      n_left--;
      txq->slot = (txq->slot + 1) & 0x3f;
    }

  if (wqe)
    {
      void *bf_next = ((void *) md->hca) + 4096 * md->uar + 0x800;
      void *bf_alt = ((void *) md->hca) + 4096 * md->uar + 0x900;
      if (txq->slot % 1)
	*(volatile u64 *) bf_next = *(u64 *) wqe;
      else
	*(volatile u64 *) bf_alt = *(u64 *) wqe;
    }
  return frame->n_vectors;
}

static clib_error_t *
mlx5_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  mlx5_main_t *mm = &mlx5_main;
  mlx5_device_t *md = vec_elt_at_index (mm->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  clib_error_t *error;

  mlx5_cmdq_t *cmdq = mlx5_get_cmdq (md);
  error = mlx5_cmd_modify_nic_vport_state (md, cmdq, is_up);
  mlx5_put_cmdq (cmdq);

  if (error)
    return error;

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, md->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      md->flags |= MLX5_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, md->hw_if_index, 0);
      md->flags &= ~MLX5_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (mlx5_device_class) = {
  .name = "mlx5",
  .tx_function = mlx5_interface_tx,
  .format_device_name = format_mlx5_device_name,
  .format_device = format_mlx5_device,
  .admin_up_down_function = mlx5_interface_admin_up_down,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
