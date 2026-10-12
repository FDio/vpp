/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "fdb",
};
static vnet_dev_rv_t
qppe_fdb_mac_op (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr, u32 op_type)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_fdb_entry_t entry = {
    .bf = {
      .mac_addr_0 = addr->eth_mac[0],
      .mac_addr_1 = addr->eth_mac[1],
      .mac_addr_2 = addr->eth_mac[2],
      .mac_addr_3 = addr->eth_mac[3],
      .mac_addr_4 = addr->eth_mac[4],
      .mac_addr_5 = addr->eth_mac[5],
      .entry_valid = 1,
      .lookup_valid = 1,
      .vsi = port->port_id,
      .dst_type = 2,
      .da_cmd = 3,
      .hit_age = 3,
    },
  };
  ppe_reg_fdb_tbl_op_t op = {
    .op_type = op_type,
    .hash_block_bitmap = 3,
  };
  u32 status;

  qppe_mmio_write32 (qd, HPPE_REG_FDB_TBL_OP_DATA0, entry.val[0]);
  qppe_mmio_write32 (qd, HPPE_REG_FDB_TBL_OP_DATA1, entry.val[1]);
  qppe_mmio_write32 (qd, HPPE_REG_FDB_TBL_OP_DATA2, entry.val[2]);
  qppe_mmio_write32 (qd, HPPE_REG_FDB_TBL_OP, op.as_u32);
  status = qppe_mmio_read32 (qd, HPPE_REG_FDB_TBL_OP_RSLT);
  if ((status & 0xf) != 0 || ((status >> 5) & 0xf) > 8)
    {
      log_err (dev, "port %u FDB %s failed for MAC %U: status 0x%08x", port->port_id,
	       op_type == HPPE_FDB_OP_TYPE_DEL ? "delete" : "add", format_vnet_dev_hw_addr, addr,
	       status);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "port %u MAC %U %s FDB with redirect-to-CPU", port->port_id,
	     format_vnet_dev_hw_addr, addr,
	     op_type == HPPE_FDB_OP_TYPE_DEL ? "removed from" : "added to");
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_fdb_mac_add (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  return qppe_fdb_mac_op (port, addr, HPPE_FDB_OP_TYPE_ADD);
}

vnet_dev_rv_t
qppe_fdb_mac_del (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  return qppe_fdb_mac_op (port, addr, HPPE_FDB_OP_TYPE_DEL);
}
