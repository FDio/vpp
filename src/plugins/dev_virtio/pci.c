/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <dev_virtio/virtio.h>

vnet_dev_rv_t
virtio_pci_map_caps (vlib_main_t *vm, vnet_dev_t *dev,
                     dev_virtio_device_t *vd)
{
  vnet_dev_rv_t rv;

  /* Map BAR0 as a best-effort placeholder so that future work can
   * inspect the modern virtio PCI capability layout. */
  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &vd->common_cfg)))
    return rv;

  vd->notify_base = vd->common_cfg;
  vd->device_cfg = vd->common_cfg;
  vd->isr = vd->common_cfg;
  vd->modern = 1;
  vd->mtu = ETHERNET_MAX_PACKET_BYTES;
  return VNET_DEV_OK;
}
