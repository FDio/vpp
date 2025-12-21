/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vppinfra/file.h>
#include <dev_rdma/ibv/ibv.h>
#include <dev_rdma/mlx5/mlx5.h>
#include <dev_rdma/common.h>

#include <dirent.h>
#undef always_inline
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

vnet_dev_rv_t rdma_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void rdma_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);

VLIB_REGISTER_LOG_CLASS (rdma_log, static) = {
  .class_name = "dev_rdma",
  .subclass_name = "init",
};

static clib_arg_t rdma_dev_args[] = {
  {
    .name = "force_ibverbs",
    .desc = "Force ibverbs mode",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 0,
  },
  {
    .type = CLIB_ARG_END,
  },
};

static u8 *
rdma_sysfs_first_entry (const char *path)
{
  DIR *dir;
  struct dirent *ent;
  u8 *name = 0;

  dir = opendir (path);
  if (!dir)
    return 0;

  while ((ent = readdir (dir)) != 0)
    {
      if (ent->d_name[0] == '.')
	continue;
      name = format (0, "%s%c", ent->d_name, 0);
      break;
    }

  closedir (dir);
  return name;
}

static uword
rdma_sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t *addr)
{
  uword rv;
  unformat_input_t in;
  u8 *s;

  s = clib_file_get_resolved_basename ("%s", path);
  if (!s)
    return 0;

  unformat_init_string (&in, (char *) s, strlen ((char *) s));
  rv = unformat (&in, "%U", unformat_vlib_pci_addr, addr);
  unformat_free (&in);
  vec_free (s);
  return rv;
}

static vnet_dev_rv_t
rdma_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_addr_t addr = vnet_dev_get_pci_addr (dev);
  rdma_dev_t *rd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct ibv_device **dev_list = 0;
  struct ibv_device *ibv_dev = 0;
  struct ibv_context *ctx = 0;
  struct ibv_device_attr_ex dev_attr_ex = {};
  vlib_pci_addr_t ibv_addr = {};
  int n_devs = 0;
  int i;
  int force_ibverbs;
  u8 p;
  u8 *path = 0;

  dev_list = ibv_get_device_list (&n_devs);
  if (!dev_list || n_devs <= 0)
    {
      if (dev_list)
	ibv_free_device_list (dev_list);
      return VNET_DEV_ERR_NOT_READY;
    }

  for (i = 0; i < n_devs; i++)
    {
      path = format (path, "%s/device%c", dev_list[i]->dev_path, 0);
      if (!rdma_sysfs_path_to_pci_addr ((char *) path, &ibv_addr))
	continue;

      vec_reset_length (path);

      if (ibv_addr.as_u32 != addr.as_u32)
	continue;

      ibv_dev = dev_list[i];
      break;
    }

  if (!ibv_dev)
    {
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  force_ibverbs = clib_args_get_bool_val_by_name (dev->args, "force_ibverbs");

  if (force_ibverbs)
    rd->type = RDMA_DEV_T_IBVERBS;
  else if (mlx5dv_is_supported (ibv_dev))
    rd->type = RDMA_DEV_T_MLX5_DV;
  else
    rd->type = RDMA_DEV_T_IBVERBS;

  rd->ctx = ctx = ibv_open_device (ibv_dev);
  if (!ctx)
    {
      rv = VNET_DEV_ERR_BUS;
      goto done;
    }

  if (ibv_query_device_ex (ctx, 0, &dev_attr_ex))
    {
      rv = VNET_DEV_ERR_BUS;
      goto done;
    }

  rd->max_qp = dev_attr_ex.orig_attr.max_qp;
  rd->max_cq = dev_attr_ex.orig_attr.max_cq;
  rd->max_qp_wr = dev_attr_ex.orig_attr.max_qp_wr;
  rd->max_cqe = dev_attr_ex.orig_attr.max_cqe;

  vlib_log (
    VLIB_LOG_LEVEL_DEBUG, rdma_log.class,
    "%U: ibv attrs max_qp %u max_cq %u max_qp_wr %u max_cqe %u phys_ports %u",
    format_vnet_dev_addr, dev, dev_attr_ex.orig_attr.max_qp,
    dev_attr_ex.orig_attr.max_cq, dev_attr_ex.orig_attr.max_qp_wr,
    dev_attr_ex.orig_attr.max_cqe, dev_attr_ex.orig_attr.phys_port_cnt);

  if (dev_attr_ex.rss_caps.max_rwq_indirection_table_size &&
      (dev_attr_ex.rss_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET)))
    rd->rss = 1;

  vlib_log (
    VLIB_LOG_LEVEL_DEBUG, rdma_log.class,
    "%U: ibv rss supported_qpts 0x%x ind_tbl_sz %u fields 0x%llx func 0x%x",
    format_vnet_dev_addr, dev, dev_attr_ex.rss_caps.supported_qpts,
    dev_attr_ex.rss_caps.max_rwq_indirection_table_size,
    (u64) dev_attr_ex.rss_caps.rx_hash_fields_mask,
    dev_attr_ex.rss_caps.rx_hash_function);

  for (p = 1; p <= dev_attr_ex.orig_attr.phys_port_cnt; p++)
    {
      vnet_dev_port_id_t port_id;

      port_id = p;

      if (rd->type == RDMA_DEV_T_MLX5_DV)
	rv = rdma_mlx5_add_port (vm, dev, port_id);
      else
	rv = rdma_ibv_add_port (vm, dev, port_id);
      if (rv != VNET_DEV_OK)
	goto done;
    }

  if (pool_elts (dev->ports) == 0)
    rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

done:
  if (rv != VNET_DEV_OK && ctx)
    ibv_close_device (ctx);
  if (dev_list)
    ibv_free_device_list (dev_list);
  vec_free (path);
  return rv;
}

static void
rdma_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  rdma_dev_t *rd = vnet_dev_get_data (dev);

  if (rd->pd)
    ibv_dealloc_pd (rd->pd);
  ibv_close_device (rd->ctx);
}

static u8 *
rdma_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;
  u8 *s, *name;

  s = format (0, "/sys/bus/pci/devices/%U/infiniband%c", format_vlib_pci_addr,
	      &di->addr, 0);
  name = rdma_sysfs_first_entry ((char *) s);

  if (name)
    {
      vec_free (name);
      vec_reset_length (s);
      return format (s, "%U - %U", format_dev_pci_vendor_name_from_ids,
		     di->vendor_id, format_dev_pci_device_name_from_ids,
		     di->vendor_id, di->device_id);
    }

  vec_free (s);
  return 0;
}

VNET_DEV_REGISTER_DRIVER (rdma_generic) = {
  .name = "rdma",
  .bus = "pci",
  .passive = 1,
  .device_data_sz = sizeof (rdma_dev_t),
  .ops = {
    .init = rdma_init,
    .free = rdma_free,
    .probe = rdma_probe,
  },
  .args = rdma_dev_args,
};
