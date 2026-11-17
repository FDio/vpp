/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <ibverbs.h>
#include <vnet/devices/netlink.h>

#undef always_inline
#include <infiniband/verbs.h>

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "init",
};

#define _(f, n, s, d) { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t ibv_rx_node_counters[] = { foreach_ibv_rx_node_counter };
vlib_error_desc_t ibv_tx_node_counters[] = { foreach_ibv_tx_node_counter };
#undef _

vnet_dev_node_t ibv_rx_node = {
  .error_counters = ibv_rx_node_counters,
  .n_error_counters = ARRAY_LEN (ibv_rx_node_counters),
  .format_trace = format_ibv_rx_trace,
};
vnet_dev_node_t ibv_tx_node = {
  .error_counters = ibv_tx_node_counters,
  .n_error_counters = ARRAY_LEN (ibv_tx_node_counters),
  .format_trace = format_ibv_tx_trace,
};

static vnet_dev_rv_t
ibv_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_addr_t addr = vnet_dev_get_pci_addr (dev);
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct ibv_context *ctx = 0;
  struct ibv_device_attr_ex dev_attr_ex = {};
  vlib_buffer_main_t *bm = vm->buffer_main;
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);
  int rv_ibv;

  log_debug (dev, "ibv_init");

  rv = rdma_open_device (&addr, &ctx);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "cannot open verbs device: %U", format_vnet_dev_rv, rv);
      return rv;
    }
  rd->ctx = ctx;

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

  vlib_log (VLIB_LOG_LEVEL_DEBUG, ibv_log.class,
	    "%U: ibv attrs max_qp %u max_cq %u max_qp_wr %u max_cqe %u phys_ports %u",
	    format_vnet_dev_addr, dev, dev_attr_ex.orig_attr.max_qp, dev_attr_ex.orig_attr.max_cq,
	    dev_attr_ex.orig_attr.max_qp_wr, dev_attr_ex.orig_attr.max_cqe,
	    dev_attr_ex.orig_attr.phys_port_cnt);

  if (dev_attr_ex.rss_caps.max_rwq_indirection_table_size &&
      (dev_attr_ex.rss_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET)))
    {
      rd->rss = 1;
      rd->rss_max_ind_tbl_size = dev_attr_ex.rss_caps.max_rwq_indirection_table_size;
      rd->rss_hash_fields_mask = dev_attr_ex.rss_caps.rx_hash_fields_mask;
      rd->rss_hash_function = dev_attr_ex.rss_caps.rx_hash_function;
    }
  if (dev_attr_ex.raw_packet_caps & IBV_RAW_PACKET_CAP_IP_CSUM)
    rd->tx_cksum_offload = 1;
  if (dev_attr_ex.orig_attr.device_cap_flags & IBV_DEVICE_RAW_IP_CSUM)
    rd->rx_cksum_offload = 1;
  rd->tx_max_sge = clib_min (dev_attr_ex.orig_attr.max_sge, IBV_TXQ_MAX_SGE);
  if ((dev_attr_ex.tso_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET)) &&
      dev_attr_ex.tso_caps.max_tso >= CLIB_U16_MAX)
    rd->tx_tso = 1;

  vlib_log (VLIB_LOG_LEVEL_DEBUG, ibv_log.class,
	    "%U: ibv rss supported_qpts 0x%x ind_tbl_sz %u fields 0x%llx func 0x%x",
	    format_vnet_dev_addr, dev, dev_attr_ex.rss_caps.supported_qpts,
	    dev_attr_ex.rss_caps.max_rwq_indirection_table_size,
	    (u64) dev_attr_ex.rss_caps.rx_hash_fields_mask, dev_attr_ex.rss_caps.rx_hash_function);

  for (u8 p = 1; p <= dev_attr_ex.orig_attr.phys_port_cnt; p++)
    {
      vnet_dev_port_id_t port_id = p;
      struct ibv_port_attr port_attr = {};
      u8 ibv_port = port_id;
      u32 max_queues = clib_min (rd->max_qp, rd->max_cq);
      u32 max_queue_size = clib_min (rd->max_cqe, rd->max_qp_wr);
      u32 max_sge = clib_min (IBV_RXQ_MAX_CHAIN_SZ, dev_attr_ex.orig_attr.max_sge);
      vnet_dev_port_add_args_t port;
      ibv_port_t port_data = {};
      u32 max_frame_size = max_sge * buffer_size;
      u32 netdev_max_mtu;
      clib_error_t *err = 0;

      if (!max_queues)
	{
	  log_err (dev, "ibv_add_port: no queues");
	  continue;
	}
      if (max_queue_size < VLIB_FRAME_SIZE)
	{
	  log_err (dev, "ibv_add_port: max_queue_size %u", max_queue_size);
	  continue;
	}

      rdma_rss_init (&port_data.rss);

      port_data.netdev_ifindex = rdma_port_netdev_ifindex (&addr, ibv_port);
      if (port_data.netdev_ifindex &&
	  (err = vnet_netlink_get_link_max_mtu (port_data.netdev_ifindex, &netdev_max_mtu)) == 0)
	max_frame_size = clib_min (max_frame_size, netdev_max_mtu + RDMA_NETDEV_MTU_OVERHEAD);
      else
	{
	  clib_error_free (err);
	  port_data.netdev_ifindex = 0;
	}

      max_queue_size = clib_min (max_queue_size, 32768);
      max_queues = clib_min (max_queues, 128);

      port = (vnet_dev_port_add_args_t){
		.port = {
		  .attr = {
	    .type = VNET_DEV_PORT_TYPE_ETHERNET,
	    .max_rx_queues = max_queues,
	    .max_tx_queues = max_queues,
		    .max_supported_rx_frame_size = max_frame_size,
		    .caps = {
		      .rss = rd->rss,
		      .interrupt_mode = 1,
		      .mac_filter = 1,
		      .change_max_rx_frame_size = port_data.netdev_ifindex != 0,
		    },
	    .rx_offloads = {
	      .ip4_cksum = rd->rx_cksum_offload,
	    },
	    .tx_offloads = {
	      .ip4_cksum = rd->tx_cksum_offload,
	      .tcp_cksum = rd->tx_cksum_offload,
	      .udp_cksum = rd->tx_cksum_offload,
	      .tcp_gso = rd->tx_cksum_offload && rd->tx_tso &&
			 (rd->tx_max_sge - 1) * buffer_size >= CLIB_U16_MAX,
	    },
	  },
		  .ops = {
	    .start = ibv_port_start,
	    .stop = ibv_port_stop,
	    .format_status = format_ibv_port_status,
	    .config_change_validate = ibv_port_cfg_change_validate,
	    .config_change = ibv_port_cfg_change,
	    .get_module_eeprom = ibv_port_get_module_eeprom,
		  },
		  .data_size = sizeof (ibv_port_t),
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
		},
	.rx_node = &ibv_rx_node,
	.tx_node = &ibv_tx_node,
	.rx_queue = {
	  .config = {
	    .data_size = sizeof (ibv_rxq_t),
	    .default_size = 2 * VLIB_FRAME_SIZE,
	    .max_size = max_queue_size,
	    .min_size = VLIB_FRAME_SIZE,
	    .size_is_power_of_two = 1,
	  },
		.ops = {
		  .alloc = ibv_rxq_alloc,
		  .free = ibv_rxq_free,
		  .format_info = format_ibv_rxq_info,
		},
	      },
	.tx_queue = {
	  .config = {
	    .data_size = sizeof (ibv_txq_t),
	    .default_size = 2 * VLIB_FRAME_SIZE,
	    .max_size = max_queue_size,
	    .min_size = VLIB_FRAME_SIZE,
	    .size_is_power_of_two = 1,
	  },
	  .ops = {
	    .alloc = ibv_txq_alloc,
	    .free = ibv_txq_free,
	  },
	},
      };

      log_debug (dev, "ibv_add_port: port %u", port_id);

      rv_ibv = ibv_query_port (rd->ctx, ibv_port, &port_attr);
      if (rv_ibv)
	{
	  log_err (dev, "ibv_query_port failed port %u rv %d", ibv_port, rv_ibv);
	  continue;
	}

      vlib_log (VLIB_LOG_LEVEL_DEBUG, ibv_log.class,
		"%U: ibv port %u state %u link_layer %u max_mtu %u active_mtu %u "
		"max_msg_sz %u",
		format_vnet_dev_addr, dev, ibv_port, port_attr.state, port_attr.link_layer,
		port_attr.max_mtu, port_attr.active_mtu, port_attr.max_msg_sz);

      if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET)
	{
	  log_warn (dev, "ibv port %u non-ethernet link_layer %u, skipping", ibv_port,
		    port_attr.link_layer);
	  continue;
	}

      if (!rdma_port_mac (rd->ctx, ibv_port, port_attr.gid_tbl_len, &port.port.attr.hw_addr))
	ethernet_mac_address_generate (port.port.attr.hw_addr.eth_mac);

      rv = vnet_dev_port_add (vm, dev, port_id, &port);
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
ibv_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  int rv_ibv = rdma_dev_close (rd->ctx, rd->pd, rd->mr);

  if (rv_ibv)
    log_err (dev, "verbs device close failed rv %d", rv_ibv);
  rd->ctx = 0;
  rd->pd = 0;
  rd->mr = 0;
}

static u8 *
ibv_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_pci_device_info_t *di = args->device_info;

  if (!rdma_pci_addr_has_device (&di->addr))
    return 0;

  return format (0, "%U - %U", format_dev_pci_vendor_name_from_ids, di->vendor_id,
		 format_dev_pci_device_name_from_ids, di->vendor_id, di->device_id);
}

VNET_DEV_REGISTER_DRIVER (ibv_generic) = {
  .name = "ibverbs",
  .bus = "pci",
  .passive = 1,
  .device = {
    .data_sz = sizeof (ibv_dev_t),
    .ops = {
      .init = ibv_init,
      .free = ibv_free,
      .probe = ibv_probe,
      .format_info = format_ibv_dev_info,
    },
  },
};
