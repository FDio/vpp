/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <dev_virtio/virtio.h>

vnet_dev_rv_t
virtio_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  dev_virtio_port_t *vp = vnet_dev_get_port_data (port);
  dev_virtio_device_t *vd = vnet_dev_get_data (port->dev);

  vp->primary_queue_pairs = 1;
  vnet_dev_set_hw_addr_eth_mac (&port->attr.hw_addr, vd->mac);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
virtio_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  dev_virtio_device_t *vd = vnet_dev_get_data (port->dev);
  vd->link_up = 1;
  return VNET_DEV_OK;
}

void
virtio_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  dev_virtio_device_t *vd = vnet_dev_get_data (port->dev);
  vd->link_up = 0;
}

vnet_dev_rv_t
virtio_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		   vnet_dev_port_cfg_change_req_t *req)
{
  return VNET_DEV_ERR_NOT_SUPPORTED;
}

vnet_dev_rv_t
virtio_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
	    vnet_dev_port_cfg_change_req_t *req)
{
  return VNET_DEV_ERR_NOT_SUPPORTED;
}
