/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vppinfra/file.h>
#include <mlx5.h>
#include <common.h>

#undef always_inline
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "init",
};

#define _(f, n, s, d) { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t mlx5_rx_node_counters[] = { foreach_mlx5_rx_node_counter };
vlib_error_desc_t mlx5_tx_node_counters[] = { foreach_mlx5_tx_node_counter };
#undef _

#define RDMA_MLX5_RXQ_MAX_CHAIN_LOG_SZ 3

static vnet_dev_rss_key_t mlx5_default_rss_key = {
  .key = {
    0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a,
    0x3e, 0x94, 0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7,
    0xd9, 0x56, 0x3d, 0x59, 0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
  },
  .length = 40,
};

typedef enum
{
  MLX5_DEV_ARG_STRIDING_RQ,
  MLX5_DEV_ARG_MINI_CQE,
  MLX5_DEV_ARG_TX_EMPW,
  MLX5_DEV_ARG_N_ARGS,
} mlx5_dev_arg_id_t;

static clib_arg_t mlx5_dev_args[] = {
  [MLX5_DEV_ARG_STRIDING_RQ] = {
    .id = MLX5_DEV_ARG_STRIDING_RQ,
    .name = "striding-rq",
    .desc = "Enable mlx5 striding RQ path selection",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  [MLX5_DEV_ARG_MINI_CQE] = {
    .id = MLX5_DEV_ARG_MINI_CQE,
    .name = "mini-cqe",
    .desc = "Enable mlx5 mini-CQE path selection",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  [MLX5_DEV_ARG_TX_EMPW] = {
    .id = MLX5_DEV_ARG_TX_EMPW,
    .name = "tx-empw",
    .desc = "Enable mlx5 eMPW TX path selection",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  [MLX5_DEV_ARG_N_ARGS] = {
    .type = CLIB_ARG_END,
  },
};

static void
mlx5_set_dev_arg_default_bool (clib_args_handle_t h, mlx5_dev_arg_id_t id, u8 value)
{
  if (h == 0 || id >= MLX5_DEV_ARG_N_ARGS || vec_len (h->args) <= id ||
      h->args[id].type != CLIB_ARG_TYPE_BOOL)
    return;

  h->args[id].default_val.boolean = value;
}

vnet_dev_node_t mlx5_rx_node_base = {
  .error_counters = mlx5_rx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_rx_node_counters),
  .format_trace = format_mlx5_rx_trace,
};
vnet_dev_node_t mlx5_rx_node_mini_cqe = {
  .error_counters = mlx5_rx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_rx_node_counters),
  .format_trace = format_mlx5_rx_trace,
};
vnet_dev_node_t mlx5_rx_node_striding = {
  .error_counters = mlx5_rx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_rx_node_counters),
  .format_trace = format_mlx5_rx_trace,
};
vnet_dev_node_t mlx5_tx_node_empw = {
  .error_counters = mlx5_tx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_tx_node_counters),
  .format_trace = format_mlx5_tx_trace,
};
vnet_dev_node_t mlx5_tx_node_send = {
  .error_counters = mlx5_tx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_tx_node_counters),
  .format_trace = format_mlx5_tx_trace,
};

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
      if (!rdma_gid_to_mac (&gid_entry.gid, mac))
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
  mlx5_port_t port_data = {
    .flow_state = {
      .promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID,
      .mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID,
    },
  };
  uword data_seg_log2_sz;
  u16 mtu_max;
  u8 ibv_port = port_id;
  u32 max_queues;
  u32 max_queue_size;
  int rv_ibv;
  vnet_dev_port_add_args_t port = {
	    .port = {
	      .attr = {
		.type = VNET_DEV_PORT_TYPE_ETHERNET,
	      },
	      .default_rss_key = mlx5_default_rss_key,
	      .ops = {
		.init = mlx5_port_init,
	.start = mlx5_port_start,
	.stop = mlx5_port_stop,
	.format_status = format_mlx5_port_info,
	.config_change_validate = mlx5_port_cfg_change_validate,
	.config_change = mlx5_port_cfg_change,
      },
      .data_size = sizeof (mlx5_port_t),
      .initial_data = &port_data,
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
		.format_info = format_mlx5_rxq_info,
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
	.format_info = format_mlx5_txq_info,
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
	port_data.cap_striding_rq = 1;
      if (mlx5dv_attrs.cqe_comp_caps.supported_format & MLX5DV_CQE_RES_FORMAT_HASH)
	port_data.cap_cqe_res_format_hash = 1;
      if (mlx5dv_attrs.flags & MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW)
	port_data.cap_tx_empw = 1;
    }

  mlx5_set_dev_arg_default_bool (dev->args, MLX5_DEV_ARG_STRIDING_RQ, port_data.cap_striding_rq);
  mlx5_set_dev_arg_default_bool (dev->args, MLX5_DEV_ARG_MINI_CQE,
				 port_data.cap_cqe_res_format_hash);
  mlx5_set_dev_arg_default_bool (dev->args, MLX5_DEV_ARG_TX_EMPW, port_data.cap_tx_empw);

  if (dev->args)
    {
      if (clib_args_get_bool_val_by_name (dev->args, "striding-rq"))
	port_data.striding_rq = port_data.cap_striding_rq;
      if (clib_args_get_bool_val_by_name (dev->args, "mini-cqe"))
	port_data.cqe_res_format_hash = port_data.cap_cqe_res_format_hash;
      if (clib_args_get_bool_val_by_name (dev->args, "tx-empw"))
	port_data.tx_empw = port_data.cap_tx_empw;
    }
  else
    {
      port_data.striding_rq = port_data.cap_striding_rq;
      port_data.cqe_res_format_hash = port_data.cap_cqe_res_format_hash;
      port_data.tx_empw = port_data.cap_tx_empw;
    }

  rv_ibv = ibv_query_port (rd->ctx, ibv_port, &port_attr);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_port failed port %u rv %d", ibv_port, rv_ibv);
      return VNET_DEV_OK;
    }
  log_debug (dev, "ibv_query_port ok port %u", ibv_port);

  log_debug (dev, "%U", format_rdma_port_attr, (u32) ibv_port, &port_attr);

  if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET)
    return VNET_DEV_OK;

  mtu_max = mlx5_port_mtu (port_attr.max_mtu);
  if (mtu_max == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  if (port_data.striding_rq)
    port.rx_node = &mlx5_rx_node_striding;
  else if (port_data.cqe_res_format_hash)
    port.rx_node = &mlx5_rx_node_mini_cqe;
  else
    port.rx_node = &mlx5_rx_node_base;
  if (port_data.tx_empw)
    port.tx_node = &mlx5_tx_node_empw;
  else
    port.tx_node = &mlx5_tx_node_send;
  port.port.attr.caps.interrupt_mode = 1;
  port.port.attr.caps.rss = rd->rss;
  port.port.attr.tx_offloads.ip4_cksum = rd->tx_ip4_cksum_offload;
  if (!mlx5_port_mac (dev, rd->ctx, ibv_port, port_attr.gid_tbl_len, &port.port.attr.hw_addr))
    {
      ethernet_mac_address_generate (port.port.attr.hw_addr.eth_mac);
    }
  port.port.attr.max_supported_rx_frame_size = mtu_max;

  return vnet_dev_port_add (vm, dev, port_id, &port);
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
  struct mlx5dv_context mlx5dv_attrs = {};
  vlib_buffer_main_t *bm = vm->buffer_main;
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
      if (!rdma_sysfs_path_to_pci_addr ((char *) path, &ibv_addr))
	continue;

      vec_reset_length (path);

      if (ibv_addr.as_u32 != addr.as_u32)
	continue;

      ibv_dev = dev_list[i];
      break;
    }

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  if (!ibv_dev || !mlx5dv_is_supported (ibv_dev))
    goto done;

  rv = VNET_DEV_ERR_BUS;
  rd->ctx = ctx = ibv_open_device (ibv_dev);
  if (!ctx)
    {
      log_err (dev, "ibv_open_device failed");
      goto done;
    }
  log_debug (dev, "ibv_open_device ok");

  rv_ibv = ibv_query_device_ex (ctx, 0, &dev_attr_ex);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_device_ex failed rv %d", rv_ibv);
      goto done;
    }
  log_debug (dev, "ibv_query_device_ex ok");

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
  rv_ibv = mlx5dv_query_device (ctx, &mlx5dv_attrs);
  if (rv_ibv)
    {
      log_err (dev, "mlx5dv_query_device failed rv %d", rv_ibv);
      goto done;
    }

  if ((mlx5dv_attrs.flags & MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED) == 0)
    {
      vlib_log (VLIB_LOG_LEVEL_WARNING, mlx5_log.class,
		"%U: mlx5dv context flags 0x%llx missing MPW_ALLOWED, probe failed",
		format_vnet_dev_addr, dev, (u64) mlx5dv_attrs.flags);
      goto done;
    }

  rv = VNET_DEV_ERR_INIT_FAILED;
  rd->pd = ibv_alloc_pd (ctx);
  if (rd->pd == 0)
    {
      log_err (dev, "ibv_alloc_pd failed");
      goto done;
    }
  log_debug (dev, "ibv_alloc_pd ok");

  rd->mr =
    ibv_reg_mr (rd->pd, (void *) bm->buffer_mem_start, bm->buffer_mem_size, IBV_ACCESS_LOCAL_WRITE);
  if (rd->mr == 0)
    {
      log_err (dev, "ibv_reg_mr failed");
      goto done;
    }
  rd->lkey = rd->mr->lkey;
  log_debug (dev, "ibv_reg_mr ok lkey 0x%x", rd->lkey);

  rd->max_qp = dev_attr_ex.orig_attr.max_qp;
  rd->max_cq = dev_attr_ex.orig_attr.max_cq;
  rd->max_qp_wr = dev_attr_ex.orig_attr.max_qp_wr;
  rd->max_cqe = dev_attr_ex.orig_attr.max_cqe;

  log_debug (dev, "%U", format_rdma_dev_attr_ex, &dev_attr_ex);

  if (((dev_attr_ex.rss_caps.supported_qpts | dev_attr_ex.tso_caps.supported_qpts) &
       (1 << IBV_QPT_RAW_PACKET)) == 0)
    {
      log_err (dev, "raw packet qp type unsupported");
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  if (dev_attr_ex.rss_caps.max_rwq_indirection_table_size &&
      (dev_attr_ex.rss_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET)))
    {
      rd->rss = 1;
      rd->rss_hash_fields_mask = dev_attr_ex.rss_caps.rx_hash_fields_mask;
      rd->rss_hash_function = dev_attr_ex.rss_caps.rx_hash_function;
      rd->rss_max_ind_tbl_size = dev_attr_ex.rss_caps.max_rwq_indirection_table_size;
    }
  if ((dev_attr_ex.raw_packet_caps & IBV_RAW_PACKET_CAP_IP_CSUM) == 0)
    {
      log_err (dev, "raw packet ip4 checksum offload unsupported");
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }
  rd->tx_ip4_cksum_offload = 1;

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
  if (rv != VNET_DEV_OK && rd->mr)
    {
      rv_ibv = ibv_dereg_mr (rd->mr);
      if (rv_ibv)
	log_err (dev, "ibv_dereg_mr failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dereg_mr ok");
    }
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

  if (rd->mr)
    {
      rv_ibv = ibv_dereg_mr (rd->mr);
      if (rv_ibv)
	log_err (dev, "ibv_dereg_mr failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dereg_mr ok");
    }
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
  struct ibv_device **dev_list;
  vnet_dev_t *dev = 0;
  vlib_pci_addr_t ibv_addr = {};
  int n_devs = 0;
  u8 supported = 0;
  u8 *path = 0;

  log_debug (dev, "mlx5_probe");

  if (di->vendor_id != 0x15b3)
    return 0;

  dev_list = ibv_get_device_list (&n_devs);
  if (dev_list && n_devs > 0)
    {
      for (u32 i = 0; i < n_devs; i++)
	{
	  path = format (path, "%s/device%c", dev_list[i]->dev_path, 0);
	  if (!rdma_sysfs_path_to_pci_addr ((char *) path, &ibv_addr))
	    continue;
	  vec_reset_length (path);
	  if (ibv_addr.as_u32 != di->addr.as_u32)
	    continue;
	  if (mlx5dv_is_supported (dev_list[i]))
	    supported = 1;
	  break;
	}
    }

  if (dev_list)
    ibv_free_device_list (dev_list);

  vec_free (path);

  if (supported)
    return format (0, "%U - %U", format_dev_pci_vendor_name_from_ids, di->vendor_id,
		   format_dev_pci_device_name_from_ids, di->vendor_id, di->device_id);

  return 0;
}

VNET_DEV_REGISTER_DRIVER (mlx5_generic) = {
  .name = "mlx5",
  .bus = "pci",
  .passive = 1,
  .device = {
    .data_sz = sizeof (mlx5_dev_t),
    .args = mlx5_dev_args,
    .ops = {
      .init = mlx5_init,
      .free = mlx5_free,
      .probe = mlx5_probe,
      .format_info = format_mlx5_dev_info,
    },
  },
};
