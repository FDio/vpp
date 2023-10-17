/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/flow/flow.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "handler",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, dev_log.class, "%U%s" f,                  \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

clib_error_t *
vnet_dev_port_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hw,
				  u32 frame_size)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hw->dev_instance);
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_MAX_FRAME_SIZE,
    .max_frame_size = frame_size,
  };

  log_debug (p->dev, "set_max_frame_size: %u", frame_size);

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
      log_debug (p->dev, "eth_flag_change: promisc off");
      break;
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      log_debug (p->dev, "eth_flag_change: promisc on");
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

  log_debug (p->dev, "port_mac_change: %U", format_vnet_dev_hw_addr,
	     &req.addr);

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

  log_debug (p->dev, "add_del_mac_address received (addr %U is_add %u",
	     format_vnet_dev_hw_addr, &req.addr, is_add);

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
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (dev_instance);
  log_warn (p->dev, "unsupported request for flow_ops received");
  return VNET_FLOW_ERROR_NOT_SUPPORTED;
}

clib_error_t *
vnet_dev_interface_set_rss_queues (vnet_main_t *vnm, vnet_hw_interface_t *hi,
				   clib_bitmap_t *bitmap)
{
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  log_warn (p->dev, "unsupported request for flow_ops received");
  return vnet_error (VNET_ERR_UNSUPPORTED, "not implemented");
}
