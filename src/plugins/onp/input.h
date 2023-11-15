/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_input_h
#define included_onp_input_h

void static_always_inline
onp_update_bt_fields (vlib_node_runtime_t *node, vlib_buffer_t *bt,
		      vlib_error_t error_code)
{
  bt->error = node->errors[error_code];
  vnet_buffer (bt)->feature_arc_index = 0;
  bt->current_config_index = 0;
  bt->ref_count = 1;
}

void static_always_inline
onp_prepare_next_eth_input_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
				  onp_pktio_t *op, cnxk_per_thread_data_t *ptd,
				  u32 next_index, u8 is_default_frame)
{
  ethernet_input_frame_t *ef;
  vlib_next_frame_t *nf;
  vlib_frame_t *f;

  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
  f = vlib_get_frame (vm, nf->frame);

  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
  ef = vlib_frame_scalar_args (f);
  ef->sw_if_index = op->sw_if_index;
  ef->hw_if_index = op->hw_if_index;

  if (!ptd->out_flags)
    f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;

  vlib_frame_no_append (f);
}

#endif /* included_onp_input_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
