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
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sw_if_index, thread_index, n_left,
    *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 lens[VLIB_FRAME_SIZE], *len;
  u16 nexts[VLIB_FRAME_SIZE];
  vnet_interface_main_t *im;
  vnet_main_t *vnm;

  vnm = vnet_get_main ();
  im = &vnm->interface_main;
  thread_index = vm->thread_index;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  vlib_get_buffers (vm, from, bufs, n_left);

  b = bufs;
  sw_if_index = sw_if_indices;
  len = lens;

  /* It's all going to l2-input */
  clib_memset_u16 (nexts, 0, VLIB_FRAME_SIZE);

  while (n_left >= 4)
    {
      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_header (b[6], STORE);
	  vlib_prefetch_buffer_header (b[7], STORE);
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

      len[0] = vlib_buffer_length_in_chain (vm, b[0]);
      len[1] = vlib_buffer_length_in_chain (vm, b[1]);
      len[2] = vlib_buffer_length_in_chain (vm, b[2]);
      len[3] = vlib_buffer_length_in_chain (vm, b[3]);

      b += 4;
      n_left -= 4;
      sw_if_index += 4;
      len += 4;
    }
  while (n_left)
    {
      /* Make sure all pkts were transmitted on the same (loop) intfc */
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = L2INPUT_BVI;
      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = sw_if_index[0];
      len[0] = vlib_buffer_length_in_chain (vm, b[0]);

      vnet_update_l2_len (b[0]);

      b += 1;
      n_left -= 1;
      sw_if_index += 1;
      len += 1;
    }

  /* count against them in blocks */
  n_left = frame->n_vectors;

  while (n_left)
    {
      u16 off, count;

      off = frame->n_vectors - n_left;

      sw_if_index = sw_if_indices + off;
      len = lens + off;

      count = clib_count_equal_u32 (sw_if_index, n_left);
      n_left -= count;

      u32 n_bytes = 0, i;
      for (i = 0; i < count; i++)
	n_bytes += len[i];

      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index, sw_if_index[0],
				       count, n_bytes);
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
