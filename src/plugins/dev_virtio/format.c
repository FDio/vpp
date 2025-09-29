/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

#include <dev_virtio/virtio.h>

u8 *
format_virtio_port_status (u8 *s, va_list *args)
{
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  dev_virtio_device_t *vd = vnet_dev_get_data (port->dev);
  dev_virtio_port_t *vp = vnet_dev_get_port_data (port);

  s =
    format (s, "virtio status: modern=%u link=%s mtu=%u qpairs=%u", vd->modern,
	    vd->link_up ? "up" : "down", vd->mtu, vp->primary_queue_pairs);

  if (!vd->modern)
    s = format (s, " (placeholder implementation)");

  return s;
}
