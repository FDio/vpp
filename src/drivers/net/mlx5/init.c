/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <mlx5.h>
#include <common.h>
#include <mlx5_ifc.h>
#include <vnet/devices/netlink.h>

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

static clib_arg_t mlx5_port_args[] = {
  {
    .name = "no_striding_rq",
    .desc = "Do not use mlx5 striding RQ for frames larger than one buffer",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 0,
  },
  {
    .name = "no_cqe_compression",
    .desc = "Disable mlx5 rx CQE compression",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 0,
  },
  {
    .name = "no_empw",
    .desc = "Do not use mlx5 enhanced multi-packet send WQEs",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 0,
  },
  {
    .type = CLIB_ARG_END,
  },
};

vnet_dev_node_t mlx5_rx_node_legacy = {
  .error_counters = mlx5_rx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_rx_node_counters),
  .format_trace = format_mlx5_rx_legacy_trace,
};
vnet_dev_node_t mlx5_rx_node_striding = {
  .error_counters = mlx5_rx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_rx_node_counters),
  .format_trace = format_mlx5_rx_striding_trace,
};
vnet_dev_node_t mlx5_tx_node = {
  .error_counters = mlx5_tx_node_counters,
  .n_error_counters = ARRAY_LEN (mlx5_tx_node_counters),
  .format_trace = format_mlx5_tx_trace,
};

static u32
mlx5_max_sq_wqe_sz (mlx5_dev_t *rd)
{
  u32 in[DEVX_ST_SZ_DW (query_hca_cap_in)] = {};
  u32 out[DEVX_ST_SZ_DW (query_hca_cap_out)] = {};

  DEVX_SET (query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
  DEVX_SET (query_hca_cap_in, in, op_mod, MLX5_HCA_CAP_OP_MOD_GENERAL_DEVICE_CUR);

  if (mlx5dv_devx_general_cmd (rd->ctx, in, sizeof (in), out, sizeof (out)) ||
      DEVX_GET (query_hca_cap_out, out, status))
    return 0;

  return DEVX_GET (query_hca_cap_out, out, capability.max_wqe_sz_sq);
}

static int
mlx5_tx_min_inline (vlib_main_t *vm, mlx5_dev_t *rd, u16 *min_inline)
{
  struct ibv_qp_init_attr_ex qpia = {
    .cap.max_send_wr = 1,
    .cap.max_send_sge = 1,
    .qp_type = IBV_QPT_RAW_PACKET,
    .comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
    .send_ops_flags = IBV_QP_EX_WITH_SEND,
    .pd = rd->pd,
  };
  struct mlx5dv_qp dv_qp = {};
  struct mlx5dv_obj obj = { .qp = { .out = &dv_qp } };
  struct ibv_qp_ex *qpx;
  struct ibv_qp *qp;
  struct ibv_cq *cq;
  int rv = -1;

  cq = ibv_create_cq (rd->ctx, 1, 0, 0, 0);
  if (cq == 0)
    return -1;

  qpia.send_cq = qpia.recv_cq = cq;
  qp = ibv_create_qp_ex (rd->ctx, &qpia);
  if (qp == 0)
    goto done;

  obj.qp.in = qp;
  qpx = ibv_qp_to_qp_ex (qp);
  if (qpx && mlx5dv_init_obj (&obj, MLX5DV_OBJ_QP) == 0 && dv_qp.sq.buf &&
      dv_qp.sq.stride >= sizeof (mlx5_wqe_t))
    {
      ibv_wr_start (qpx);
      ibv_wr_send (qpx);
      ibv_wr_set_sge (qpx, rd->lkey, vm->buffer_main->buffer_mem_start,
		      MLX5_ETH_L2_INLINE_HEADER_SIZE);
      *min_inline = clib_net_to_host_u16 (((mlx5_wqe_t *) dv_qp.sq.buf)->eseg.inline_hdr_sz);
      ibv_wr_abort (qpx);
      rv = 0;
    }

  ibv_destroy_qp (qp);
done:
  ibv_destroy_cq (cq);
  return rv;
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
  clib_error_t *err = 0;
  u32 netdev_max_mtu;
  u8 ibv_port = port_id;
  u32 max_queues, max_queue_size;
  int rv_ibv;
  vnet_dev_port_add_args_t port = {
    .port = {
      .attr = {
	.type = VNET_DEV_PORT_TYPE_ETHERNET,
      },
      .ops = {
	.init = mlx5_port_init,
	.start = mlx5_port_start,
	.stop = mlx5_port_stop,
	.format_status = format_mlx5_port_status,
	.config_change_validate = mlx5_port_cfg_change_validate,
	.config_change = mlx5_port_cfg_change,
	.get_module_eeprom = mlx5_port_get_module_eeprom,
      },
      .data_size = sizeof (mlx5_port_t),
      .initial_data = &port_data,
      .default_rss_config = {
	.key = {
	  0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2,
	  0x83, 0x19, 0xdb, 0x1a, 0x3e, 0x94, 0x6b, 0x9e, 0x38, 0xd9,
	  0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7, 0xd9, 0x56,
	  0x3d, 0x59, 0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
	},
	.key_len = RDMA_RSS_KEY_SIZE,
	.set_key = 1,
      },
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
  rdma_rss_init (&port_data.rss);

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
	port_data.striding_rq = port_data.striding_rq_supported = 1;
      if ((mlx5dv_attrs.cqe_comp_caps.supported_format & MLX5DV_CQE_RES_FORMAT_HASH) &&
	  mlx5dv_attrs.cqe_comp_caps.max_num &&
	  mlx5dv_attrs.cqe_comp_caps.max_num <= VLIB_FRAME_SIZE)
	port_data.cqe_res_format_hash = 1;
      if (mlx5dv_attrs.flags & MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW)
	{
	  u16 min_inline = MLX5_ETH_L2_INLINE_HEADER_SIZE;

	  u32 max_wqe_sz = mlx5_max_sq_wqe_sz (rd);

	  if (mlx5_tx_min_inline (vm, rd, &min_inline) || min_inline)
	    log_debug (dev, "port %u: no eMPW, tx requires %u inline bytes", ibv_port, min_inline);
	  else if (max_wqe_sz < MLX5_TX_EMPW_MAX_WQE_SZ)
	    log_notice (dev, "port %u: eMPW disabled, max sq wqe size %u < %u", ibv_port,
			max_wqe_sz, MLX5_TX_EMPW_MAX_WQE_SZ);
	  else
	    port_data.empw_supported = 1;
	}
    }

  rv_ibv = ibv_query_port (rd->ctx, ibv_port, &port_attr);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_port failed port %u rv %d", ibv_port, rv_ibv);
      return VNET_DEV_OK;
    }

  vlib_log (VLIB_LOG_LEVEL_DEBUG, mlx5_log.class,
	    "%U: ibv port %u state %u link_layer %u max_mtu %u active_mtu %u "
	    "max_msg_sz %u",
	    format_vnet_dev_addr, dev, ibv_port, port_attr.state, port_attr.link_layer,
	    port_attr.max_mtu, port_attr.active_mtu, port_attr.max_msg_sz);

  if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET)
    return VNET_DEV_OK;

  port_data.netdev_ifindex = rdma_port_netdev_ifindex (rd->ctx, ibv_port);
  if (port_data.netdev_ifindex == 0)
    {
      log_debug (dev, "port %u: no kernel netdev, skipping", ibv_port);
      return VNET_DEV_OK;
    }

  err = vnet_netlink_get_link_max_mtu (port_data.netdev_ifindex, &netdev_max_mtu);
  if (err)
    {
      log_err (dev, "port %u: cannot find kernel netdev max mtu: %U", ibv_port, format_clib_error,
	       err);
      clib_error_free (err);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  port.rx_node = &mlx5_rx_node_legacy;
  port.tx_node = &mlx5_tx_node;
  port.port.attr.caps.interrupt_mode = 1;
  port.port.attr.caps.rss = rd->rss;
  port.port.attr.caps.mac_filter = 1;
  port.port.attr.rx_offloads.ip4_cksum = 1;
  port.port.attr.tx_offloads.ip4_cksum = rd->tx_cksum_offload;
  port.port.attr.tx_offloads.tcp_cksum = rd->tx_cksum_offload;
  port.port.attr.tx_offloads.udp_cksum = rd->tx_cksum_offload;
  port.port.attr.tx_offloads.tcp_gso = rd->tx_cksum_offload && rd->tx_tso;
  if (!rdma_port_mac (rd->ctx, ibv_port, port_attr.gid_tbl_len, &port.port.attr.hw_addr))
    {
      ethernet_mac_address_generate (port.port.attr.hw_addr.eth_mac);
    }
  port.port.attr.max_supported_rx_frame_size = netdev_max_mtu + RDMA_NETDEV_MTU_OVERHEAD;
  port.port.attr.caps.change_max_rx_frame_size = 1;

  return vnet_dev_port_add (vm, dev, port_id, &port);
}

static vnet_dev_rv_t
mlx5_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_addr_t addr = vnet_dev_get_pci_addr (dev);
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  vlib_buffer_main_t *bm = vm->buffer_main;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct ibv_context *ctx = 0;
  struct ibv_device_attr_ex dev_attr_ex = {};
  int rv_ibv;

  log_debug (dev, "mlx5_init");

  rv = rdma_open_device (&addr, &ctx);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "cannot open verbs device: %U", format_vnet_dev_rv, rv);
      return rv;
    }
  rd->ctx = ctx;

  if (!mlx5dv_is_supported (ctx->device))
    {
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  rv_ibv = ibv_query_device_ex (ctx, 0, &dev_attr_ex);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_device_ex failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_BUS;
      goto done;
    }

  rd->pd = ibv_alloc_pd (ctx);
  if (rd->pd == 0)
    {
      log_err (dev, "ibv_alloc_pd failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  rd->mr =
    ibv_reg_mr (rd->pd, (void *) bm->buffer_mem_start, bm->buffer_mem_size, IBV_ACCESS_LOCAL_WRITE);
  if (rd->mr == 0)
    {
      log_err (dev, "ibv_reg_mr failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }
  rd->lkey = rd->mr->lkey;

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
      rd->rss_max_ind_tbl_size = dev_attr_ex.rss_caps.max_rwq_indirection_table_size;
    }
  if (dev_attr_ex.raw_packet_caps & IBV_RAW_PACKET_CAP_IP_CSUM)
    rd->tx_cksum_offload = 1;
  if ((dev_attr_ex.tso_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET)) &&
      dev_attr_ex.tso_caps.max_tso >= CLIB_U16_MAX)
    rd->tx_tso = 1;

  vlib_log (VLIB_LOG_LEVEL_DEBUG, mlx5_log.class,
	    "%U: ibv rss supported_qpts 0x%x ind_tbl_sz %u fields 0x%llx func 0x%x",
	    format_vnet_dev_addr, dev, dev_attr_ex.rss_caps.supported_qpts,
	    dev_attr_ex.rss_caps.max_rwq_indirection_table_size,
	    (u64) dev_attr_ex.rss_caps.rx_hash_fields_mask, dev_attr_ex.rss_caps.rx_hash_function);

  for (u8 p = 1; p <= dev_attr_ex.orig_attr.phys_port_cnt; p++)
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
  if (rv != VNET_DEV_OK)
    {
      rdma_dev_close (rd->ctx, rd->pd, rd->mr);
      rd->ctx = 0;
      rd->pd = 0;
      rd->mr = 0;
    }
  return rv;
}

static void
mlx5_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  int rv_ibv = rdma_dev_close (rd->ctx, rd->pd, rd->mr);

  if (rv_ibv)
    log_err (dev, "verbs device close failed rv %d", rv_ibv);
  rd->ctx = 0;
  rd->pd = 0;
  rd->mr = 0;
}

static u8 *
mlx5_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_pci_device_info_t *di = args->device_info;

  if (di->vendor_id != 0x15b3)
    return 0;

  if (!rdma_pci_addr_has_device (&di->addr))
    return 0;

  return format (0, "%U - %U", format_dev_pci_vendor_name_from_ids, di->vendor_id,
		 format_dev_pci_device_name_from_ids, di->vendor_id, di->device_id);
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
      .format_info = format_mlx5_dev_info,
    },
  },
};
