/*
 * l2_bvi.c : layer 2 Bridged Virtual Interface
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vnet/l2/l2_bvi.h>

/**
 * send packets to l2-input.
 */
VNET_DEVICE_CLASS_TX_FN (bvi_device_class) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sw_if_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE];
  u32 n_left, *from;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  vlib_get_buffers (vm, from, bufs, n_left);

  b = bufs;
  sw_if_index = sw_if_indices;

  /* It's all going to l2-input */
  clib_memset_u16 (nexts, 0, VLIB_FRAME_SIZE);

  /*
   * For each packet:
   *  - fixup the L2 length of the packet
   *  - set the RX interface (which the bridge will use) to the
   *    TX interface (which routing has chosen)
   *  - Set the TX interface to the special ID so the DP knows this is a BVI
   * Don't counts packets and bytes, that's done in the bviX-output node
   */
  while (n_left >= 4)
    {
      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left >= 8))
	{
	  /* LOAD pre-fetch since meta and packet data is read */
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);

	  vlib_prefetch_buffer_data (b[4], LOAD);
	  vlib_prefetch_buffer_data (b[5], LOAD);
	  vlib_prefetch_buffer_data (b[6], LOAD);
	  vlib_prefetch_buffer_data (b[7], LOAD);
	}

      vnet_update_l2_len (b[0]);
      vnet_update_l2_len (b[1]);
      vnet_update_l2_len (b[2]);
      vnet_update_l2_len (b[3]);

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_TX];
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_TX];

      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = L2INPUT_BVI;
      vnet_buffer (b[1])->sw_if_index[VLIB_TX] = L2INPUT_BVI;
      vnet_buffer (b[2])->sw_if_index[VLIB_TX] = L2INPUT_BVI;
      vnet_buffer (b[3])->sw_if_index[VLIB_TX] = L2INPUT_BVI;

      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = sw_if_index[0];
      vnet_buffer (b[1])->sw_if_index[VLIB_RX] = sw_if_index[1];
      vnet_buffer (b[2])->sw_if_index[VLIB_RX] = sw_if_index[2];
      vnet_buffer (b[3])->sw_if_index[VLIB_RX] = sw_if_index[3];

      b += 4;
      n_left -= 4;
      sw_if_index += 4;
    }
  while (n_left)
    {
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = L2INPUT_BVI;
      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = sw_if_index[0];

      vnet_update_l2_len (b[0]);

      b += 1;
      n_left -= 1;
      sw_if_index += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
