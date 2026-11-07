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
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (hw->dev_instance);
  vnet_dev_port_t *p;
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE,
    .max_rx_frame_size = frame_size + VNET_DEV_ETH_FCS_LEN,
  };

  p = di->port;

  if (!di->is_primary_if)
    return vnet_dev_port_err (vm, p, VNET_DEV_ERR_NOT_PRIMARY_INTERFACE, "");

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

clib_error_t *
vnet_dev_port_set_link_speed (struct vnet_main_t *vnm, u32 hw_if_index, vnet_hw_if_speed_t speed)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (hw->dev_instance);
  vnet_dev_port_t *p;
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_SET_LINK_SPEED,
    .link_speed = vnet_hw_if_speed_to_kbps (speed),
  };

  p = di->port;

  if (!di->is_primary_if)
    return vnet_dev_port_err (vm, p, VNET_DEV_ERR_NOT_PRIMARY_INTERFACE, "");

  log_debug (p->dev, "speed %u kbps", req.link_speed);

  rv = vnet_dev_port_cfg_change_req_validate (vm, p, &req);
  if (rv == VNET_DEV_ERR_NO_CHANGE)
    return 0;

  if (rv != VNET_DEV_OK)
    return vnet_dev_port_err (vm, p, rv, "requested link speed is not valid for port");

  if ((rv = vnet_dev_process_port_cfg_change_req (vm, p, &req)) != VNET_DEV_OK)
    return vnet_dev_port_err (vm, p, rv, "device failed to change link speed");

  return 0;
}

u32
vnet_dev_port_eth_flag_change (vnet_main_t *vnm, vnet_hw_interface_t *hw,
			       u32 flags)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (hw->dev_instance);
  vnet_dev_port_t *p = di->port;
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_PROMISC_MODE,
  };

  if (!di->is_primary_if)
    return ~0;

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
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (hi->dev_instance);
  vnet_dev_port_t *p = di->port;
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR,
  };

  if (!di->is_primary_if)
    return vnet_dev_port_err (vm, p, VNET_DEV_ERR_NOT_PRIMARY_INTERFACE, "");

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
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (hi->dev_instance);
  vnet_dev_port_t *p = di->port;
  vnet_dev_rv_t rv;

  vnet_dev_port_cfg_change_req_t req = {
    .type = is_add ? VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR :
			   VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR,
  };

  if (!di->is_primary_if)
    return vnet_dev_port_err (vm, p, VNET_DEV_ERR_NOT_PRIMARY_INTERFACE, "");

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
vnet_dev_flow_ops_fn (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_instance, u32 flow_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (dev_instance);
  vnet_dev_port_t *p;
  vnet_dev_port_cfg_change_req_t req = {};
  vnet_dev_rv_t rv;

  if (!di)
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  if (!di->is_primary_if)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  p = di->port;

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
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (instance);
  vlib_main_t *vm = vlib_get_main ();

  if (di->is_primary_if)
    vnet_dev_process_call_port_op_no_rv (vm, di->port,
					 vnet_dev_port_clear_counters);
}

void
vnet_dev_set_interface_next_node (vnet_main_t *vnm, u32 hw_if_index,
				  u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (hw->dev_instance);
  vnet_dev_port_interface_t *intf;
  int runtime_update = 0;

  if (di->is_primary_if)
    intf = vnet_dev_port_get_primary_if (di->port);
  else
    intf = vnet_dev_port_get_sec_if_by_index (di->port, di->sec_if_index);

  if (node_index == ~0)
    {
      intf->redirect_to_node_next_index = 0;
      if (intf->feature_arc == 0)
	{
	  intf->rx_next_index =
	    vnet_dev_default_next_index_by_port_type[di->port->attr.type];
	  runtime_update = 1;
	}
      intf->redirect_to_node = 0;
    }
  else
    {
      u16 next_index = vlib_node_add_next (vlib_get_main (),
					   port_rx_eth_node.index, node_index);
      intf->redirect_to_node_next_index = next_index;
      if (intf->feature_arc == 0)
	{
	  intf->rx_next_index = next_index;
	  runtime_update = 1;
	}
      intf->redirect_to_node = 1;
    }
  intf->rx_next_index =
    node_index == ~0 ?
      vnet_dev_default_next_index_by_port_type[di->port->attr.type] :
      node_index;

  if (runtime_update)
    {
      foreach_vnet_dev_port_rx_queue (rxq, di->port)
	vnet_dev_rx_queue_rt_request (
	  vm, rxq, (vnet_dev_rx_queue_rt_req_t){ .update_next_index = 1 });
      log_debug (di->port->dev, "runtime update requested due to change in "
				"redirect-to-next configuration");
    }
}

/* SFF-8636 lower page byte 2 (Table 18) */
typedef union
{
  struct
  {
    u8 data_not_ready : 1;
    u8 intl : 1;
    u8 flat_mem : 1;
    u8 _reserved : 5;
  };
  u8 as_u8;
} sff8636_status_t;

static vnet_dev_rv_t
vnet_dev_port_module_eeprom_read (vlib_main_t *vm, vnet_dev_port_t *p, u8 i2c_address, u8 page,
				  u16 offset, u16 length, u8 *data)
{
  vnet_dev_port_module_eeprom_req_t req = {
    .i2c_address = i2c_address,
    .page = page,
    .offset = offset,
    .length = length,
    .data = data,
  };

  return vnet_dev_process_call_port_op_with_ptr (vm, p, p->port_ops.get_module_eeprom, &req);
}

vnet_dev_rv_t
vnet_dev_port_get_module_eeprom (vlib_main_t *vm, vnet_dev_port_t *p, vnet_interface_eeprom_t *e)
{
  vnet_dev_rv_t rv;
  u8 id;

  if (!p->port_ops.get_module_eeprom)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  rv = vnet_dev_port_module_eeprom_read (vm, p, 0x50, 0, 0, 1, &id);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (p->dev, "module identifier 0x%02x", id);

  switch (id)
    {
    case 0x03: /* SFF-8024 Table 4-1: SFP/SFP+/SFP28 */
      e->eeprom_type = VNET_INTERFACE_EEPROM_TYPE_SFF8472;
      e->eeprom_len = 256;
      rv = vnet_dev_port_module_eeprom_read (vm, p, 0x50, 0, 0, 256, e->eeprom_raw);
      /* A2h diagnostic page is optional - keep the A0h data even if this fails */
      if (rv == VNET_DEV_OK && vnet_dev_port_module_eeprom_read (
				 vm, p, 0x51, 0, 0, 256, e->eeprom_raw + 256) == VNET_DEV_OK)
	e->eeprom_len = 512;
      return rv;

    case 0x0c: /* QSFP */
    case 0x0d: /* QSFP+ */
    case 0x11: /* QSFP28 */
      {
	sff8636_status_t status;

	e->eeprom_type = VNET_INTERFACE_EEPROM_TYPE_SFF8636;
	e->eeprom_len = 256;
	rv = vnet_dev_port_module_eeprom_read (vm, p, 0x50, 0, 0, 256, e->eeprom_raw);
	/* upper pages 1-3 hold channel/module alarm thresholds and need page
	 * select support in the module - skip them for flat-memory modules
	 * (e.g. most passive DACs) which only have page 0 and may not behave
	 * as a page select - stop at whichever page the driver can't give us */
	status.as_u8 = e->eeprom_raw[2];
	if (rv == VNET_DEV_OK && !status.flat_mem)
	  for (u8 pg = 1; rv == VNET_DEV_OK && pg <= 3; pg++)
	    {
	      if (vnet_dev_port_module_eeprom_read (vm, p, 0x50, pg, 128, 128,
						    e->eeprom_raw + 128 * (pg + 1)) != VNET_DEV_OK)
		break;
	      e->eeprom_len = 128 * (pg + 2);
	    }
	return rv;
      }

    default:
      log_debug (p->dev, "unsupported module identifier 0x%02x", id);
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}

clib_error_t *
vnet_dev_port_eeprom_read (vnet_main_t *__clib_unused vnm, vnet_hw_interface_t *hi,
			   vnet_interface_eeprom_t **eeprom)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (hi->dev_instance);
  vnet_dev_port_t *p = di->port;
  vnet_interface_eeprom_t *e;
  vnet_dev_rv_t rv;

  e = clib_mem_alloc (sizeof (*e));
  *e = (vnet_interface_eeprom_t) {};

  rv = vnet_dev_port_get_module_eeprom (vm, p, e);
  if (rv != VNET_DEV_OK)
    {
      clib_mem_free (e);
      return vnet_dev_port_err (vm, p, rv, "failed to read module EEPROM");
    }

  *eeprom = e;
  return 0;
}
