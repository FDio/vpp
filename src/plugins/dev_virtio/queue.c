/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

#include <dev_virtio/virtio.h>

vnet_dev_rv_t
virtio_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  dev_virtio_rxq_t *vrq = vnet_dev_get_rx_queue_data (rxq);
  vrq->queue_id = rxq->queue_id;
  return VNET_DEV_ERR_NOT_SUPPORTED;
}

void
virtio_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  clib_memset (vnet_dev_get_rx_queue_data (rxq), 0, sizeof (dev_virtio_rxq_t));
}

vnet_dev_rv_t
virtio_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  dev_virtio_txq_t *vtq = vnet_dev_get_tx_queue_data (txq);
  vtq->queue_id = txq->queue_id;
  return VNET_DEV_ERR_NOT_SUPPORTED;
}

void
virtio_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  clib_memset (vnet_dev_get_tx_queue_data (txq), 0, sizeof (dev_virtio_txq_t));
}
