/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>

#include <dev_virtio/virtio.h>

static vlib_error_desc_t virtio_tx_counters[] = {
  { .name = "unsupported",
    .desc = "dev_virtio tx not implemented",
    .severity = VL_COUNTER_SEVERITY_ERROR },
};

vnet_dev_node_t virtio_tx_node = {
  .error_counters = virtio_tx_counters,
  .n_error_counters = ARRAY_LEN (virtio_tx_counters),
};

VNET_DEV_NODE_FN (virtio_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /* Placeholder implementation drops frames until dataplane support is added.
   */
  u32 n_vectors = frame->n_vectors;
  if (n_vectors)
    {
      u32 *buffers = vlib_frame_vector_args (frame);
      vlib_buffer_free (vm, buffers, n_vectors);
      vlib_error_count (vm, node->node_index, 0, n_vectors);
    }
  return n_vectors;
}
