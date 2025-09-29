/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>

#include <dev_virtio/virtio.h>

static vlib_error_desc_t virtio_rx_counters[] = {
  { .name = "unsupported",
    .desc = "dev_virtio rx not implemented",
    .severity = VL_COUNTER_SEVERITY_ERROR },
};

vnet_dev_node_t virtio_rx_node = {
  .error_counters = virtio_rx_counters,
  .n_error_counters = ARRAY_LEN (virtio_rx_counters),
};

VNET_DEV_NODE_FN (virtio_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /* Placeholder implementation until virtio dataplane support is added. */
  return 0;
}
