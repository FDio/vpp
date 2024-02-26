/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/log.h>
#include <vnet/flow/flow.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "handler",
};

clib_error_t *
vnet_dev_port_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hw,
				  u32 frame_size)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hw->dev_instance);
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE,
    .max_rx_frame_size = frame_size,
  };

  log_debug (p->dev, "size %u", frame_size);

  rv = vnet_dev_port_cfg_change_req_validate (vm, p, &req);
  if (rv == VNET_DEV_ERR_NO_CHANGE)
    return 0;

  if (rv != VNET_DEV_OK)
    return vnet_dev_port_err (vm, p, rv,
			      "new max frame size is not valid for port");

  if ((rv = vnet_dev_process_port_cfg_change_req (vm, p, &req)) != VNET_DEV_OK)
    return vnet_dev_port_err (vm, p, rv,
			      "device failed to change max frame size");

  return 0;
}

u32
vnet_dev_port_eth_flag_change (vnet_main_t *vnm, vnet_hw_interface_t *hw,
			       u32 flags)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hw->dev_instance);
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_PROMISC_MODE,
  };

  switch (flags)
    {
    case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
      log_debug (p->dev, "promisc off");
      break;
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      log_debug (p->dev, "promisc on");
      req.promisc = 1;
      break;
    default:
      return ~0;
    }

  rv = vnet_dev_port_cfg_change_req_validate (vm, p, &req);
  if (rv == VNET_DEV_ERR_NO_CHANGE)
    return 0;

  if (rv != VNET_DEV_OK)
    return ~0;

  rv = vnet_dev_process_port_cfg_change_req (vm, p, &req);
  if (rv == VNET_DEV_OK || rv == VNET_DEV_ERR_NO_CHANGE)
    return 0;
  return ~0;
}

clib_error_t *
vnet_dev_port_mac_change (vnet_hw_interface_t *hi, const u8 *old,
			  const u8 *new)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR,
  };

  vnet_dev_set_hw_addr_eth_mac (&req.addr, new);

  log_debug (p->dev, "new mac  %U", format_vnet_dev_hw_addr, &req.addr);

  rv = vnet_dev_port_cfg_change_req_validate (vm, p, &req);
  if (rv == VNET_DEV_ERR_NO_CHANGE)
    return 0;

  if (rv != VNET_DEV_OK)
    return vnet_dev_port_err (vm, p, rv, "hw address is not valid for port");

  if ((rv = vnet_dev_process_port_cfg_change_req (vm, p, &req)) != VNET_DEV_OK)
    return vnet_dev_port_err (vm, p, rv, "device failed to change hw address");

  return 0;
}

clib_error_t *
vnet_dev_add_del_mac_address (vnet_hw_interface_t *hi, const u8 *address,
			      u8 is_add)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = is_add ? VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR :
			   VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR,
  };

  vnet_dev_set_hw_addr_eth_mac (&req.addr, address);

  log_debug (p->dev, "received (addr %U is_add %u", format_vnet_dev_hw_addr,
	     &req.addr, is_add);

  rv = vnet_dev_port_cfg_change_req_validate (vm, p, &req);
  if (rv != VNET_DEV_OK)
    return vnet_dev_port_err (vm, p, rv,
			      "provided secondary hw addresses cannot "
			      "be added/removed");

  if ((rv = vnet_dev_process_port_cfg_change_req (vm, p, &req)) != VNET_DEV_OK)
    return vnet_dev_port_err (
      vm, p, rv, "device failed to add/remove secondary hw address");

  return 0;
}

int
vnet_dev_flow_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op,
		      u32 dev_instance, u32 flow_index, uword *private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (dev_instance);
  vnet_dev_port_cfg_change_req_t req;
  vnet_dev_rv_t rv;

  switch (op)
    {
    case VNET_FLOW_DEV_OP_ADD_FLOW:
      req.type = VNET_DEV_PORT_CFG_ADD_RX_FLOW;
      break;
    case VNET_FLOW_DEV_OP_DEL_FLOW:
      req.type = VNET_DEV_PORT_CFG_DEL_RX_FLOW;
      break;
    case VNET_FLOW_DEV_OP_GET_COUNTER:
      req.type = VNET_DEV_PORT_CFG_GET_RX_FLOW_COUNTER;
      break;
    case VNET_FLOW_DEV_OP_RESET_COUNTER:
      req.type = VNET_DEV_PORT_CFG_RESET_RX_FLOW_COUNTER;
      break;
    default:
      log_warn (p->dev, "unsupported request for flow_ops received");
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  req.flow_index = flow_index;
  req.private_data = private_data;

  rv = vnet_dev_port_cfg_change_req_validate (vm, p, &req);
  if (rv != VNET_DEV_OK)
    {
      log_err (p->dev, "validation failed for flow_ops");
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  if ((rv = vnet_dev_process_port_cfg_change_req (vm, p, &req)) != VNET_DEV_OK)
    {
      log_err (p->dev, "request for flow_ops failed");
      return vnet_dev_flow_err (vm, rv);
    }

  return 0;
}

clib_error_t *
vnet_dev_interface_set_rss_queues (vnet_main_t *vnm, vnet_hw_interface_t *hi,
				   clib_bitmap_t *bitmap)
{
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  log_warn (p->dev, "unsupported request for flow_ops received");
  return vnet_error (VNET_ERR_UNSUPPORTED, "not implemented");
}

void
vnet_dev_clear_hw_interface_counters (u32 instance)
{
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (instance);
  vlib_main_t *vm = vlib_get_main ();

  vnet_dev_process_call_port_op_no_rv (vm, port, vnet_dev_port_clear_counters);
}

void
vnet_dev_set_interface_next_node (vnet_main_t *vnm, u32 hw_if_index,
				  u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_dev_port_t *port =
    vnet_dev_get_port_from_dev_instance (hw->dev_instance);
  int runtime_update = 0;

  if (node_index == ~0)
    {
      port->intf.redirect_to_node_next_index = 0;
      if (port->intf.feature_arc == 0)
	{
	  port->intf.rx_next_index =
	    vnet_dev_default_next_index_by_port_type[port->attr.type];
	  runtime_update = 1;
	}
      port->intf.redirect_to_node = 0;
    }
  else
    {
      u16 next_index = vlib_node_add_next (vlib_get_main (),
					   port_rx_eth_node.index, node_index);
      port->intf.redirect_to_node_next_index = next_index;
      if (port->intf.feature_arc == 0)
	{
	  port->intf.rx_next_index = next_index;
	  runtime_update = 1;
	}
      port->intf.redirect_to_node = 1;
    }
  port->intf.rx_next_index =
    node_index == ~0 ?
	    vnet_dev_default_next_index_by_port_type[port->attr.type] :
	    node_index;

  if (runtime_update)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	vnet_dev_rx_queue_rt_request (
	  vm, rxq, (vnet_dev_rx_queue_rt_req_t){ .update_next_index = 1 });
      log_debug (port->dev, "runtime update requested due to chgange in "
			    "reditect-to-next configuration");
    }
}
