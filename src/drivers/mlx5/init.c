/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vppinfra/file.h>
#include <mlx5.h>
#include <common.h>

#include <dirent.h>
#undef always_inline
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "init",
};

#define RDMA_MLX5_RXQ_MAX_CHAIN_LOG_SZ 3

static clib_arg_t mlx5_port_args[] = {
  {
    .name = "no_striding_rq",
    .desc = "Disable mlx5 striding RQ",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 0,
  },
  {
    .type = CLIB_ARG_END,
  },
};

vnet_dev_node_t mlx5_rx_node = {
  .format_trace = format_mlx5_rx_trace,
};
vnet_dev_node_t mlx5_tx_node = {};

static int
mlx5_gid_to_mac (const union ibv_gid *gid, u8 *mac)
{
  vnet_dev_t *dev = 0;
  const u8 *raw;

  log_debug (dev, "mlx5_gid_to_mac");

  raw = gid->raw;
  if (raw[11] != 0xff || raw[12] != 0xfe)
    return 0;

  mac[0] = raw[8] ^ 0x02;
  mac[1] = raw[9];
  mac[2] = raw[10];
  mac[3] = raw[13];
  mac[4] = raw[14];
  mac[5] = raw[15];
  return 1;
}

static int
mlx5_port_mac (vnet_dev_t *dev, struct ibv_context *ctx, u8 ibv_port, int gid_tbl_len,
	       vnet_dev_hw_addr_t *hw_addr)
{
  struct ibv_gid_entry gid_entry = {};
  u8 mac[6];
  int gid_index;
  int rv_ibv;

  log_debug (dev, "mlx5_port_mac: port %u", ibv_port);

  for (gid_index = 0; gid_index < gid_tbl_len; gid_index++)
    {
      rv_ibv = ibv_query_gid_ex (ctx, ibv_port, gid_index, &gid_entry, 0);
      if (rv_ibv)
	{
	  log_err (dev, "ibv_query_gid_ex failed port %u index %d rv %d", ibv_port, gid_index,
		   rv_ibv);
	  continue;
	}
      log_debug (dev, "ibv_query_gid_ex ok port %u index %d", ibv_port, gid_index);
      if (gid_entry.gid_type != IBV_GID_TYPE_ROCE_V1 && gid_entry.gid_type != IBV_GID_TYPE_ROCE_V2)
	continue;
      if (!mlx5_gid_to_mac (&gid_entry.gid, mac))
	continue;
      vnet_dev_set_hw_addr_eth_mac (hw_addr, mac);
      return 1;
    }

  return 0;
}

vnet_dev_rv_t
mlx5_add_port (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t port_id)
{
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  struct ibv_port_attr port_attr = {};
  struct mlx5dv_context mlx5dv_attrs = {};
  const struct mlx5dv_striding_rq_caps *caps;
  mlx5_port_t port_data = {};
  uword data_seg_log2_sz;
  u16 mtu_max;
  u8 ibv_port = (u8) port_id;
  u32 max_queues;
  u32 max_queue_size;
  int rv_ibv;
  vnet_dev_port_add_args_t port = {
    .port = {
      .attr = {
	.type = VNET_DEV_PORT_TYPE_ETHERNET,
      },
      .ops = {
	.start = mlx5_port_start,
	.stop = mlx5_port_stop,
	.config_change_validate = mlx5_port_cfg_change_validate,
	.config_change = mlx5_port_cfg_change,
      },
      .data_size = sizeof (mlx5_port_t),
      .initial_data = &port_data,
      .args = mlx5_port_args,
    },
    .rx_queue = {
      .config = {
	.data_size = sizeof (mlx5_rxq_t),
	.default_size = 1024,
	.min_size = 256,
	.size_is_power_of_two = 1,
      },
      .ops = {
	.alloc = mlx5_rxq_alloc,
	.free = mlx5_rxq_free,
      },
    },
    .tx_queue = {
      .config = {
	.data_size = sizeof (mlx5_txq_t),
	.default_size = 1024,
	.min_size = 256,
	.size_is_power_of_two = 1,
      },
      .ops = {
	.alloc = mlx5_txq_alloc,
	.free = mlx5_txq_free,
      },
    },
  };

  log_debug (dev, "mlx5_add_port: port %u", port_id);

  max_queue_size = rd->max_qp_wr;
  if (rd->max_cqe && rd->max_cqe < max_queue_size)
    max_queue_size = rd->max_cqe;
  if (max_queue_size == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
  max_queue_size = clib_min (max_queue_size, (u32) 0xffff);

  port.rx_queue.config.max_size = max_queue_size;
  port.tx_queue.config.max_size = max_queue_size;

  if (port.rx_queue.config.default_size > max_queue_size)
    port.rx_queue.config.default_size = max_queue_size;
  if (port.tx_queue.config.default_size > max_queue_size)
    port.tx_queue.config.default_size = max_queue_size;

  max_queues = rd->max_qp;
  if (rd->max_cq && rd->max_cq < max_queues)
    max_queues = rd->max_cq;
  if (max_queues == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
  max_queues = clib_min (max_queues, (u32) 0xffff);

  port.port.attr.max_rx_queues = max_queues;
  port.port.attr.max_tx_queues = max_queues;

  mlx5dv_attrs.comp_mask |= MLX5DV_CONTEXT_MASK_CQE_COMPRESION;
  mlx5dv_attrs.comp_mask |= MLX5DV_CONTEXT_MASK_STRIDING_RQ;
  if (mlx5dv_query_device (rd->ctx, &mlx5dv_attrs) == 0)
    {
      caps = &mlx5dv_attrs.striding_rq_caps;
      data_seg_log2_sz = min_log2 (vlib_buffer_get_default_data_size (vm));
      if (data_seg_log2_sz <= caps->max_single_stride_log_num_of_bytes &&
	  data_seg_log2_sz >= caps->min_single_stride_log_num_of_bytes &&
	  RDMA_MLX5_RXQ_MAX_CHAIN_LOG_SZ >= caps->min_single_wqe_log_num_of_strides &&
	  RDMA_MLX5_RXQ_MAX_CHAIN_LOG_SZ <= caps->max_single_wqe_log_num_of_strides)
	port_data.striding_rq = 1;
      if (mlx5dv_attrs.cqe_comp_caps.supported_format & MLX5DV_CQE_RES_FORMAT_HASH)
	port_data.cqe_res_format_hash = 1;
    }

  rv_ibv = ibv_query_port (rd->ctx, ibv_port, &port_attr);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_port failed port %u rv %d", ibv_port, rv_ibv);
      return VNET_DEV_OK;
    }
  log_debug (dev, "ibv_query_port ok port %u", ibv_port);

  vlib_log (VLIB_LOG_LEVEL_DEBUG, mlx5_log.class,
	    "%U: ibv port %u state %u link_layer %u max_mtu %u active_mtu %u "
	    "max_msg_sz %u",
	    format_vnet_dev_addr, dev, ibv_port, port_attr.state, port_attr.link_layer,
	    port_attr.max_mtu, port_attr.active_mtu, port_attr.max_msg_sz);

  if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET)
    return VNET_DEV_OK;

  mtu_max = mlx5_port_mtu (port_attr.max_mtu);
  if (mtu_max == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  port.rx_node = &mlx5_rx_node;
  port.tx_node = &mlx5_tx_node;
  port.port.attr.caps.rss = rd->rss;
  if (!mlx5_port_mac (dev, rd->ctx, ibv_port, port_attr.gid_tbl_len, &port.port.attr.hw_addr))
    {
      ethernet_mac_address_generate (port.port.attr.hw_addr.eth_mac);
    }
  port.port.attr.max_supported_rx_frame_size = mtu_max;

  return vnet_dev_port_add (vm, dev, port_id, &port);
}

static u8 *
mlx5_sysfs_first_entry (const char *path)
{
  vnet_dev_t *dev = 0;
  DIR *dir;
  struct dirent *ent;
  u8 *name = 0;

  log_debug (dev, "mlx5_sysfs_first_entry: path %s", path);

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
mlx5_sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t *addr)
{
  vnet_dev_t *dev = 0;
  uword rv;
  unformat_input_t in;
  u8 *s;

  log_debug (dev, "mlx5_sysfs_path_to_pci_addr: path %s", path);

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
mlx5_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_addr_t addr = vnet_dev_get_pci_addr (dev);
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct ibv_device **dev_list = 0;
  struct ibv_device *ibv_dev = 0;
  struct ibv_context *ctx = 0;
  struct ibv_device_attr_ex dev_attr_ex = {};
  vlib_pci_addr_t ibv_addr = {};
  int n_devs = 0;
  int i;
  int rv_ibv;
  u8 p;
  u8 *path = 0;

  log_debug (dev, "mlx5_init");

  dev_list = ibv_get_device_list (&n_devs);
  if (!dev_list || n_devs <= 0)
    {
      if (!dev_list)
	log_err (dev, "ibv_get_device_list failed");
      else
	log_err (dev, "ibv_get_device_list returned %d devices", n_devs);
      if (dev_list)
	{
	  ibv_free_device_list (dev_list);
	  log_debug (dev, "ibv_free_device_list ok");
	}
      return VNET_DEV_ERR_NOT_READY;
    }
  log_debug (dev, "ibv_get_device_list ok n_devs %d", n_devs);

  for (i = 0; i < n_devs; i++)
    {
      path = format (path, "%s/device%c", dev_list[i]->dev_path, 0);
      if (!mlx5_sysfs_path_to_pci_addr ((char *) path, &ibv_addr))
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

  if (!mlx5dv_is_supported (ibv_dev))
    {
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  rd->ctx = ctx = ibv_open_device (ibv_dev);
  if (!ctx)
    {
      log_err (dev, "ibv_open_device failed");
      rv = VNET_DEV_ERR_BUS;
      goto done;
    }
  log_debug (dev, "ibv_open_device ok");

  rv_ibv = ibv_query_device_ex (ctx, 0, &dev_attr_ex);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_device_ex failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_BUS;
      goto done;
    }
  log_debug (dev, "ibv_query_device_ex ok");

  rd->pd = ibv_alloc_pd (ctx);
  if (rd->pd == 0)
    {
      log_err (dev, "ibv_alloc_pd failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }
  log_debug (dev, "ibv_alloc_pd ok");

  rd->max_qp = dev_attr_ex.orig_attr.max_qp;
  rd->max_cq = dev_attr_ex.orig_attr.max_cq;
  rd->max_qp_wr = dev_attr_ex.orig_attr.max_qp_wr;
  rd->max_cqe = dev_attr_ex.orig_attr.max_cqe;
  rd->max_sge = dev_attr_ex.orig_attr.max_sge;

  vlib_log (VLIB_LOG_LEVEL_DEBUG, mlx5_log.class,
	    "%U: ibv attrs max_qp %u max_cq %u max_qp_wr %u max_cqe %u phys_ports %u",
	    format_vnet_dev_addr, dev, dev_attr_ex.orig_attr.max_qp, dev_attr_ex.orig_attr.max_cq,
	    dev_attr_ex.orig_attr.max_qp_wr, dev_attr_ex.orig_attr.max_cqe,
	    dev_attr_ex.orig_attr.phys_port_cnt);

  if (dev_attr_ex.rss_caps.max_rwq_indirection_table_size &&
      (dev_attr_ex.rss_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET)))
    {
      rd->rss = 1;
      rd->rss_hash_fields_mask = dev_attr_ex.rss_caps.rx_hash_fields_mask;
      rd->rss_hash_function = dev_attr_ex.rss_caps.rx_hash_function;
    }

  vlib_log (VLIB_LOG_LEVEL_DEBUG, mlx5_log.class,
	    "%U: ibv rss supported_qpts 0x%x ind_tbl_sz %u fields 0x%llx func 0x%x",
	    format_vnet_dev_addr, dev, dev_attr_ex.rss_caps.supported_qpts,
	    dev_attr_ex.rss_caps.max_rwq_indirection_table_size,
	    (u64) dev_attr_ex.rss_caps.rx_hash_fields_mask, dev_attr_ex.rss_caps.rx_hash_function);

  for (p = 1; p <= dev_attr_ex.orig_attr.phys_port_cnt; p++)
    {
      vnet_dev_port_id_t port_id;

      port_id = p;

      rv = mlx5_add_port (vm, dev, port_id);
      if (rv != VNET_DEV_OK)
	goto done;
    }

  if (pool_elts (dev->ports) == 0)
    rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

done:
  if (rv != VNET_DEV_OK && rd->pd)
    {
      rv_ibv = ibv_dealloc_pd (rd->pd);
      if (rv_ibv)
	log_err (dev, "ibv_dealloc_pd failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dealloc_pd ok");
    }
  if (rv != VNET_DEV_OK && ctx)
    {
      rv_ibv = ibv_close_device (ctx);
      if (rv_ibv)
	log_err (dev, "ibv_close_device failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_close_device ok");
    }
  if (dev_list)
    {
      ibv_free_device_list (dev_list);
      log_debug (dev, "ibv_free_device_list ok");
    }
  vec_free (path);
  return rv;
}

static void
mlx5_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  int rv_ibv;

  log_debug (dev, "mlx5_free");

  if (rd->pd)
    {
      rv_ibv = ibv_dealloc_pd (rd->pd);
      if (rv_ibv)
	log_err (dev, "ibv_dealloc_pd failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dealloc_pd ok");
    }
  rv_ibv = ibv_close_device (rd->ctx);
  if (rv_ibv)
    log_err (dev, "ibv_close_device failed rv %d", rv_ibv);
  else
    log_debug (dev, "ibv_close_device ok");
}

static u8 *
mlx5_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_pci_device_info_t *di = args->device_info;
  vnet_dev_t *dev = 0;
  u8 *s, *name;

  log_debug (dev, "mlx5_probe");

  if (di->vendor_id != 0x15b3)
    return 0;

  s = format (0, "/sys/bus/pci/devices/%U/infiniband%c", format_vlib_pci_addr, &di->addr, 0);
  name = mlx5_sysfs_first_entry ((char *) s);

  if (name)
    {
      vec_free (name);
      vec_reset_length (s);
      return format (s, "%U - %U", format_dev_pci_vendor_name_from_ids, di->vendor_id,
		     format_dev_pci_device_name_from_ids, di->vendor_id, di->device_id);
    }

  vec_free (s);
  return 0;
}

VNET_DEV_REGISTER_DRIVER (mlx5_generic) = {
  .name = "mlx5",
  .bus = "pci",
  .passive = 1,
  .device = {
    .data_sz = sizeof (mlx5_dev_t),
    .ops = {
      .init = mlx5_init,
      .free = mlx5_free,
      .probe = mlx5_probe,
    },
  },
};
