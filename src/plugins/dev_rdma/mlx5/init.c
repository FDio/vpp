/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/ethernet/ethernet.h>
#include <vlib/log.h>
#include <dev_rdma/mlx5/mlx5.h>
#include <dev_rdma/common.h>
#undef always_inline
#include <infiniband/mlx5dv.h>

#define RDMA_MLX5_RXQ_MAX_CHAIN_LOG_SZ 3

vnet_dev_rv_t rdma_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void rdma_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);

VLIB_REGISTER_LOG_CLASS (rdma_log, static) = {
  .class_name = "dev_rdma",
  .subclass_name = "mlx5-init",
};

vnet_dev_node_t rdma_mlx5_rx_node = {};
vnet_dev_node_t rdma_mlx5_tx_node = {};

static int
rdma_mlx5_gid_to_mac (const union ibv_gid *gid, u8 *mac)
{
  const u8 *raw;

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
rdma_mlx5_port_mac (struct ibv_context *ctx, u8 ibv_port, int gid_tbl_len,
		    vnet_dev_hw_addr_t *hw_addr)
{
  struct ibv_gid_entry gid_entry = {};
  u8 mac[6];
  int gid_index;

  for (gid_index = 0; gid_index < gid_tbl_len; gid_index++)
    {
      if (ibv_query_gid_ex (ctx, ibv_port, gid_index, &gid_entry, 0))
	continue;
      if (gid_entry.gid_type != IBV_GID_TYPE_ROCE_V1 &&
	  gid_entry.gid_type != IBV_GID_TYPE_ROCE_V2)
	continue;
      if (!rdma_mlx5_gid_to_mac (&gid_entry.gid, mac))
	continue;
      vnet_dev_set_hw_addr_eth_mac (hw_addr, mac);
      return 1;
    }

  return 0;
}

vnet_dev_rv_t
rdma_mlx5_add_port (vlib_main_t *vm, vnet_dev_t *dev,
		    vnet_dev_port_id_t port_id)
{
  rdma_dev_t *rd = vnet_dev_get_data (dev);
  struct ibv_port_attr port_attr = {};
  struct mlx5dv_context mlx5dv_attrs = {};
  const struct mlx5dv_striding_rq_caps *caps;
  rdma_mlx5_port_t port_data = {};
  uword data_seg_log2_sz;
  u16 mtu_max;
  u8 ibv_port = (u8) port_id;
  u32 max_queues;
  u32 max_queue_size;
  vnet_dev_port_add_args_t port = {
    .port = {
      .attr = {
	.type = VNET_DEV_PORT_TYPE_ETHERNET,
      },
      .ops = {
	.start = rdma_port_start,
	.stop = rdma_port_stop,
      },
      .data_size = sizeof (rdma_mlx5_port_t),
      .initial_data = &port_data,
    },
    .rx_queue = {
      .config = {
	.default_size = 1024,
	.min_size = 256,
	.size_is_power_of_two = 1,
      },
    },
    .tx_queue = {
      .config = {
	.default_size = 1024,
	.min_size = 256,
	.size_is_power_of_two = 1,
      },
    },
  };

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

  mlx5dv_attrs.comp_mask |= MLX5DV_CONTEXT_MASK_STRIDING_RQ;
  if (mlx5dv_query_device (rd->ctx, &mlx5dv_attrs) == 0)
    {
      caps = &mlx5dv_attrs.striding_rq_caps;
      data_seg_log2_sz = min_log2 (vlib_buffer_get_default_data_size (vm));
      if (data_seg_log2_sz <= caps->max_single_stride_log_num_of_bytes &&
	  data_seg_log2_sz >= caps->min_single_stride_log_num_of_bytes &&
	  RDMA_MLX5_RXQ_MAX_CHAIN_LOG_SZ >=
	    caps->min_single_wqe_log_num_of_strides &&
	  RDMA_MLX5_RXQ_MAX_CHAIN_LOG_SZ <=
	    caps->max_single_wqe_log_num_of_strides)
	port_data.striding_rq = 1;
    }

  if (ibv_query_port (rd->ctx, ibv_port, &port_attr))
    return VNET_DEV_OK;

  vlib_log (VLIB_LOG_LEVEL_DEBUG, rdma_log.class,
	    "%U: ibv port %u state %u link_layer %u max_mtu %u active_mtu %u "
	    "max_msg_sz %u",
	    format_vnet_dev_addr, dev, ibv_port, port_attr.state,
	    port_attr.link_layer, port_attr.max_mtu, port_attr.active_mtu,
	    port_attr.max_msg_sz);

  if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET)
    return VNET_DEV_OK;

  mtu_max = rdma_port_mtu (port_attr.max_mtu);
  if (mtu_max == 0)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  port.rx_node = &rdma_mlx5_rx_node;
  port.tx_node = &rdma_mlx5_tx_node;
  port.port.attr.caps.rss = rd->rss;
  if (!rdma_mlx5_port_mac (rd->ctx, ibv_port, port_attr.gid_tbl_len,
			   &port.port.attr.hw_addr))
    {
      ethernet_mac_address_generate (port.port.attr.hw_addr.eth_mac);
    }
  port.port.attr.max_supported_rx_frame_size = mtu_max;

  return vnet_dev_port_add (vm, dev, port_id, &port);
}
