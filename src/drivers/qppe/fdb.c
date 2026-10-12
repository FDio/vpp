/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <qppe.h>

#define PPE_REG_FDB_TBL_OP		 0x060008
#define PPE_REG_FDB_TBL_RD_OP		 0x060010
#define PPE_REG_FDB_TBL_OP_RSLT		 0x060020
#define PPE_REG_FDB_TBL_RD_OP_RSLT	 0x060030
#define PPE_REG_FDB_TBL_RD_OP_RSLT_DATA0 0x060200
#define PPE_REG_FDB_TBL_RD_OP_RSLT_DATA1 0x060204
#define PPE_REG_FDB_TBL_RD_OP_RSLT_DATA2 0x060208
#define PPE_REG_FDB_TBL_OP_DATA0	 0x060230
#define PPE_REG_FDB_TBL_OP_DATA1	 0x060234
#define PPE_REG_FDB_TBL_OP_DATA2	 0x060238
#define PPE_REG_FDB_TBL_RD_OP_DATA0	 0x060260
#define PPE_REG_FDB_TBL_RD_OP_DATA1	 0x060264
#define PPE_REG_FDB_TBL_RD_OP_DATA2	 0x060268
#define PPE_FDB_TBL_ENTRIES		 2048

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "fdb",
};

typedef union
{
  u32 val[3];
  struct
  {
    u32 mac_addr_5 : 8;
    u32 mac_addr_4 : 8;
    u32 mac_addr_3 : 8;
    u32 mac_addr_2 : 8;
    u32 mac_addr_1 : 8;
    u32 mac_addr_0 : 8;
    u32 entry_valid : 1;
    u32 lookup_valid : 1;
    u32 vsi : 6;
    u32 dst_value_0 : 8;
    u32 dst_value_1 : 4;
    u32 dst_type : 2;
    u32 sa_cmd : 2;
    u32 da_cmd : 2;
    u32 hit_age : 2;
    u32 _reserved0 : 20;
  } bf;
} qppe_fdb_entry_t;

/* FDB_TBL_OP, per the vendor SSDK's struct fdb_tbl_op (hppe_fdb_reg.h). op_type
 * values are the adpt layer's OP_TYPE_* constants (adpt_hppe_fdb.c): only ADD
 * and DEL are used here; GET(2)/FLUSH(4)/AGE(5) are untouched by this driver. */
typedef union
{
  u32 as_u32;
  struct
  {
    u32 cmd_id : 4;
    u32 byp_rslt_en : 1;
    u32 op_type : 3;
    u32 hash_block_bitmap : 2;
    u32 op_mode : 1;
    u32 entry_index : 11;
    u32 reserved_22_31 : 10;
  };
} ppe_reg_fdb_tbl_op_t;

#define PPE_FDB_OP_TYPE_ADD 0
#define PPE_FDB_OP_TYPE_DEL 1

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
  /* Add/delete in hash mode with both FDB hash banks enabled, since the
   * lookup key (MAC + VSI, above) is the only part of the entry a delete
   * actually matches on - the rest is harmless for that op. */
  ppe_reg_fdb_tbl_op_t op = {
    .op_type = op_type,
    .hash_block_bitmap = 3,
  };
  u32 status;

  qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_OP_DATA0, entry.val[0]);
  qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_OP_DATA1, entry.val[1]);
  qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_OP_DATA2, entry.val[2]);
  qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_OP, op.as_u32);
  status = qppe_mmio_read32 (qd, PPE_REG_FDB_TBL_OP_RSLT);
  if ((status & 0xf) != 0 || ((status >> 5) & 0xf) > 8)
    {
      log_err (dev, "port %u FDB %s failed for MAC %U: status 0x%08x", port->port_id,
	       op_type == PPE_FDB_OP_TYPE_DEL ? "delete" : "add", format_vnet_dev_hw_addr, addr,
	       status);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "port %u MAC %U %s FDB with redirect-to-CPU", port->port_id,
	     format_vnet_dev_hw_addr, addr,
	     op_type == PPE_FDB_OP_TYPE_DEL ? "removed from" : "added to");
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_fdb_mac_add (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  return qppe_fdb_mac_op (port, addr, PPE_FDB_OP_TYPE_ADD);
}

vnet_dev_rv_t
qppe_fdb_mac_del (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  return qppe_fdb_mac_op (port, addr, PPE_FDB_OP_TYPE_DEL);
}

u8 *
format_qppe_fdb_table (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;
  u32 failed_index = 0;
  u32 failed_status = 0;
  u8 read_failed = 0;
  const char *const qppe_fdb_cmd_names[] = {
    "forward",
    "drop",
    "copy-to-cpu",
    "redirect-to-cpu",
  };

  const char *const qppe_fdb_dst_type_names[] = {
    "reserved",
    "reserved",
    "port-id",
    "port-bitmap",
  };

  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 11, "index", "MAC", "entry valid", "lookup valid", "VSI", "dst type",
		     "destination", "SA cmd", "DA cmd", "hit age", "static");
  for (u32 index = 0; index < PPE_FDB_TBL_ENTRIES; index++)
    {
      u32 cmd_id = index & 0xf;
      u32 op = cmd_id | (2u << 5) | (3u << 8) | (1u << 10) | (index << 11);
      u32 status;
      qppe_fdb_entry_t entry = {};
      u32 dst_value;

      /* Indexed read uses the SSDK FDB_TBL_RD_OP interface. */
      qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_RD_OP_DATA0, 0);
      qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_RD_OP_DATA1, 0);
      qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_RD_OP_DATA2, 0);
      qppe_mmio_write32 (qd, PPE_REG_FDB_TBL_RD_OP, op);
      status = qppe_mmio_read32 (qd, PPE_REG_FDB_TBL_RD_OP_RSLT);
      if ((status & 0xf) != cmd_id || ((status >> 5) & 0xf) > 8)
	{
	  failed_index = index;
	  failed_status = status;
	  read_failed = 1;
	  break;
	}

      entry.val[0] = qppe_mmio_read32 (qd, PPE_REG_FDB_TBL_RD_OP_RSLT_DATA0);
      entry.val[1] = qppe_mmio_read32 (qd, PPE_REG_FDB_TBL_RD_OP_RSLT_DATA1);
      entry.val[2] = qppe_mmio_read32 (qd, PPE_REG_FDB_TBL_RD_OP_RSLT_DATA2);
      if (!entry.bf.entry_valid)
	continue;

      dst_value = entry.bf.dst_value_0 | (entry.bf.dst_value_1 << 8);

      table_format_cell (&table, row, 0, "%u", index);
      table_format_cell (&table, row, 1, "%02x:%02x:%02x:%02x:%02x:%02x", entry.bf.mac_addr_0,
			 entry.bf.mac_addr_1, entry.bf.mac_addr_2, entry.bf.mac_addr_3,
			 entry.bf.mac_addr_4, entry.bf.mac_addr_5);
      table_format_cell (&table, row, 2, "%s", entry.bf.entry_valid ? "yes" : "no");
      table_format_cell (&table, row, 3, "%s", entry.bf.lookup_valid ? "yes" : "no");
      table_format_cell (&table, row, 4, "%u", entry.bf.vsi);
      table_format_cell (&table, row, 5, "%s (%u)", qppe_fdb_dst_type_names[entry.bf.dst_type],
			 entry.bf.dst_type);
      if (entry.bf.dst_type == 2)
	table_format_cell (&table, row, 6, "%u", dst_value);
      else
	table_format_cell (&table, row, 6, "0x%03x", dst_value);
      table_format_cell (&table, row, 7, "%s (%u)", qppe_fdb_cmd_names[entry.bf.sa_cmd],
			 entry.bf.sa_cmd);
      table_format_cell (&table, row, 8, "%s (%u)", qppe_fdb_cmd_names[entry.bf.da_cmd],
			 entry.bf.da_cmd);
      table_format_cell (&table, row, 9, "%u", entry.bf.hit_age);
      table_format_cell (&table, row, 10, "%s", entry.bf.hit_age == 3 ? "yes" : "no");
      row++;
    }

  if (row)
    {
      s = format (s, "PPE FDB_TBL:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &table);
    }
  else
    s = format (s, "PPE FDB_TBL: no valid entries");

  if (read_failed)
    {
      s = format_newline (s, indent);
      s = format (s, "PPE FDB indexed read failed at entry %u: status 0x%08x", failed_index,
		  failed_status);
    }

  table_free (&table);
  return s;
}
