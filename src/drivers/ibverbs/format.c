/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <ibverbs.h>

u8 *
format_ibv_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ibv_rx_trace_t *t = va_arg (*args, ibv_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "ibverbs: %v (%d) qid %u next-node %U len %u", hi->name,
	      t->hw_if_index, t->qid, format_vlib_next_node_name, vm,
	      node->index, t->next_index, t->length);

  return s;
}

u8 *
format_ibv_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ibv_dev_t *rd = vnet_dev_get_data (port->dev);
  struct ibv_port_attr port_attr = {};
  const char *state = "unknown";
  const char *link_layer = "unknown";
  u32 speed = 0;
  int rv_ibv;

  static const char *state_str[] = {
    [IBV_PORT_DOWN] = "down",
    [IBV_PORT_INIT] = "init",
    [IBV_PORT_ARMED] = "armed",
    [IBV_PORT_ACTIVE] = "active",
  };
  static const char *link_layer_str[] = {
    [IBV_LINK_LAYER_UNSPECIFIED] = "unspecified",
    [IBV_LINK_LAYER_INFINIBAND] = "infiniband",
    [IBV_LINK_LAYER_ETHERNET] = "ethernet",
  };

  rv_ibv = ibv_query_port (rd->ctx, port->port_id, &port_attr);
  if (rv_ibv)
    return format (s, "ibv_query_port failed rv %d", rv_ibv);

  if (port_attr.state < ARRAY_LEN (state_str) && state_str[port_attr.state])
    state = state_str[port_attr.state];
  if (port_attr.link_layer < ARRAY_LEN (link_layer_str) &&
      link_layer_str[port_attr.link_layer])
    link_layer = link_layer_str[port_attr.link_layer];
  if (port_attr.active_speed)
    speed = ibv_port_speed (port_attr.active_speed);

  s = format (s, "state %s, link-layer %s", state, link_layer);
  if (port_attr.active_width)
    s = format (s, ", active-width %u", port_attr.active_width);
  if (port_attr.active_speed)
    {
      if (speed)
	s = format (s, ", active-speed %u Mbps", speed);
      else
	s = format (s, ", active-speed %u", port_attr.active_speed);
    }
  if (port_attr.active_mtu)
    s = format (s, ", mtu %u", ibv_port_mtu (port_attr.active_mtu));
  return s;
}
